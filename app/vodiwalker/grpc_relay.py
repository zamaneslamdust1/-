"""
VLESS over gRPC (gun mode) — سرور gRPC داخلی هسته پنل
======================================================
پیاده‌سازی HTTP/2 server با کتابخانه‌ی h2 (h2c — بدون TLS)

- مسیر: POST /{serviceName}/Tun که serviceName = UUID کانفیگ است
- فریمینگ gRPC: هر پیام = 1 بایت فلاگ + 4 بایت طول (big-endian) + payload
- بار مفید دقیقاً همان پروتکل VLESS است (مثل tcp_relay) و در پایان پاسخ،
  تریلر grpc-status:0 فرستاده می‌شود تا کلاینت‌های gRPC واقعی (Xray/grpc-go)
  تمیز پایان یابند.
- پورت داخلی: 6545 (متغیر محیطی GRPC_LISTEN_PORT)
  * Railway: قابلیت «TCP Proxy» را به همین پورت داخلی وصل کن؛ در لینک،
    security روی none می‌ماند (h2c مستقیم).
  * VPS با nginx/Caddy: grpc passthrough با TLS + تنظیم «gRPC Security=tls»
    و «gRPC Host/Port عمومی» در Railway Network Center پنل.
"""

import asyncio
import os
import re
import secrets
import socket
import uuid as uuid_lib
from datetime import datetime

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions

logger = None  # در start_grpc_relay() از main ست می‌شود

GRPC_LISTEN_PORT = int(os.environ.get("GRPC_LISTEN_PORT", "6545"))
RELAY_BUF = 256 * 1024
GRPC_CHUNK = 16 * 1024          # هر فریم پاسخ زیر 16KB (کمتر از پنجره پیش‌فرض)
TARGET_TIMEOUT = 10.0
FLOW_WAIT_TIMEOUT = 30.0

GRPC_PATH_RE = re.compile(r"^/([^/]+)/Tun/?$")

_server = None


class _NeedMoreData(Exception):
    """هدر VLESS هنوز کامل نرسیده است."""


def _parse_vless_header(buf: bytes):
    """پارسر VLESS (همان قالب tcp_relay) با تفکیک «ناقص» از «خراب»."""
    if len(buf) < 24:
        raise _NeedMoreData()
    pos = 1  # نسخه (0)
    raw_uuid = buf[pos:pos + 16]
    pos += 16
    try:
        uid = str(uuid_lib.UUID(bytes=raw_uuid))
    except Exception:
        raise ValueError("bad uuid")
    if len(buf) < pos + 1:
        raise _NeedMoreData()
    addon_len = buf[pos]
    pos += 1 + addon_len
    if len(buf) < pos + 1:
        raise _NeedMoreData()
    command = buf[pos]
    pos += 1
    if len(buf) < pos + 2:
        raise _NeedMoreData()
    port = int.from_bytes(buf[pos:pos + 2], "big")
    pos += 2
    if len(buf) < pos + 1:
        raise _NeedMoreData()
    addr_type = buf[pos]
    pos += 1
    if addr_type == 1:
        if len(buf) < pos + 4:
            raise _NeedMoreData()
        address = ".".join(str(b) for b in buf[pos:pos + 4])
        pos += 4
    elif addr_type == 2:
        if len(buf) < pos + 1:
            raise _NeedMoreData()
        dlen = buf[pos]
        pos += 1
        if len(buf) < pos + dlen:
            raise _NeedMoreData()
        address = buf[pos:pos + dlen].decode("utf-8", errors="ignore")
        pos += dlen
    elif addr_type == 3:
        if len(buf) < pos + 16:
            raise _NeedMoreData()
        ab = buf[pos:pos + 16]
        pos += 16
        address = ":".join(f"{ab[i]:02x}{ab[i + 1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown addr type: {addr_type}")
    return uid, command, address, port, buf[pos:]


class _GrpcStream:
    __slots__ = ("sid", "service", "grpc_buf", "vless_buf", "target_reader", "target_writer",
                 "uid", "client_closed", "pump_task", "conn_id", "opened", "client_ip")

    def __init__(self, sid: int, service: str):
        self.sid = sid
        self.service = service
        self.grpc_buf = b""
        self.vless_buf = b""
        self.target_reader = None
        self.target_writer = None
        self.uid = None
        self.client_closed = False
        self.pump_task = None
        self.conn_id = None
        self.opened = False
        self.client_ip = "نامشخص"


def _client_ip(writer) -> str:
    try:
        peer = writer.get_extra_info("peername")
        return peer[0] if peer else "نامشخص"
    except Exception:
        return "نامشخص"


def _flush(conn, writer):
    out = conn.data_to_send()
    if out:
        writer.write(out)


async def _send_grpc_error(conn, writer, sid: int, message: str, status: str = "2"):
    try:
        conn.send_headers(sid, [("grpc-status", status), ("grpc-message", message)], end_stream=True)
        _flush(conn, writer)
        await writer.drain()
    except Exception:
        pass


async def _send_data_with_flow(conn, writer, sid: int, frame: bytes):
    """ارسال DATA با احترام به پنجره‌ی flow-control کلاینت."""
    deadline = asyncio.get_event_loop().time() + FLOW_WAIT_TIMEOUT
    while True:
        try:
            window = conn.local_flow_control_window(sid)
        except (h2.exceptions.StreamClosedError, KeyError):
            raise ConnectionError("stream closed")
        if window >= len(frame):
            break
        if asyncio.get_event_loop().time() > deadline:
            raise ConnectionError("flow control timeout")
        await asyncio.sleep(0.02)
    conn.send_data(sid, frame, end_stream=False)


async def _pump_target_to_grpc(st: _GrpcStream, conn, writer, ctx):
    """هدف → کلاینت: بایت‌های خام هدف داخل قاب gRPC و در پایان تریلر grpc-status:0."""
    check_and_use = ctx["check_and_use"]
    throttle = ctx["throttle"]
    try:
        while True:
            data = await st.target_reader.read(RELAY_BUF)
            if not data:
                break
            if not await check_and_use(st.uid, len(data)):
                break
            await throttle(st.uid, len(data))
            for off in range(0, len(data), GRPC_CHUNK):
                piece = data[off:off + GRPC_CHUNK]
                frame = b"\x00" + len(piece).to_bytes(4, "big") + piece
                await _send_data_with_flow(conn, writer, st.sid, frame)
                _flush(conn, writer)
                if writer.transport.get_write_buffer_size() > RELAY_BUF:
                    await writer.drain()
        # پایان تمیز: تریلر gRPC
        conn.send_headers(st.sid, [("grpc-status", "0"), ("grpc-message", "ok")], end_stream=True)
        _flush(conn, writer)
        await writer.drain()
    except Exception:
        try:
            conn.reset_stream(st.sid, h2.errors.ErrorCodes.INTERNAL_ERROR)
            _flush(conn, writer)
            await writer.drain()
        except Exception:
            pass


async def _close_stream(st: _GrpcStream, connections: dict):
    if st.pump_task:
        st.pump_task.cancel()
        try:
            await st.pump_task
        except asyncio.CancelledError:
            pass
        except Exception:
            pass
        st.pump_task = None
    if st.target_writer:
        try:
            st.target_writer.close()
            await st.target_writer.wait_closed()
        except Exception:
            pass
        st.target_writer = None
    if st.conn_id:
        connections.pop(st.conn_id, None)


async def _try_open_tunnel(st: _GrpcStream, conn, writer, streams: dict, ctx):
    """تلاش برای پارس هدر VLESS و باز کردن تونل به هدف."""
    from main import LINKS, LINKS_LOCK, is_link_allowed, is_ip_allowed, log_activity
    connections = ctx["connections"]

    if st.opened:
        return

    try:
        uid, command, address, port, rest = _parse_vless_header(st.vless_buf)
    except _NeedMoreData:
        return  # هنوز کامل نرسیده — فریم بعدی
    except ValueError as exc:
        logger and logger.warning(f"🚫 gRPC [{st.sid}] bad VLESS header: {exc}")
        streams.pop(st.sid, None)
        await _send_grpc_error(conn, writer, st.sid, "bad request")
        return

    # serviceName باید با UUID داخل هدر VLESS یکی باشد
    if uid != st.service:
        logger and logger.warning(f"🚫 gRPC [{st.sid}] service/{st.service[:8]}… != uuid/{uid[:8]}…")
        streams.pop(st.sid, None)
        await _send_grpc_error(conn, writer, st.sid, "unauthorized")
        return

    async with LINKS_LOCK:
        link = LINKS.get(uid)

    if not is_link_allowed(link):
        logger and logger.warning(f"🚫 gRPC uuid={uid[:8]}… not allowed")
        streams.pop(st.sid, None)
        await _send_grpc_error(conn, writer, st.sid, "unauthorized")
        return

    if not is_ip_allowed(link, uid, st.client_ip):
        log_activity("connection", f"اتصال gRPC {st.client_ip} به کانفیگ «{link.get('label', '?')}» رد شد (محدودیت IP)", "warn")
        streams.pop(st.sid, None)
        await _send_grpc_error(conn, writer, st.sid, "unauthorized")
        return

    if command != 1:  # فقط TCP (UDP پشتیبانی نمی‌شود)
        streams.pop(st.sid, None)
        await _send_grpc_error(conn, writer, st.sid, "udp not supported")
        return

    st.uid = uid
    st.conn_id = secrets.token_urlsafe(6)
    connections[st.conn_id] = {
        "uuid": uid, "ip": st.client_ip, "transport": "vless-grpc",
        "connected_at": datetime.now().isoformat(), "bytes": 0,
    }
    logger and logger.info(
        f"✅ gRPC [{st.conn_id}] uuid={uid[:8]}… → {address}:{port} ip={st.client_ip} total={len(connections)}"
    )
    log_activity("connection", f"اتصال gRPC جدید از {st.client_ip} → {address}:{port} (کانفیگ {link.get('label', '?')})", "info")

    header_len = len(st.vless_buf) - len(rest)
    if not await ctx["check_and_use"](uid, max(header_len, 1)):
        streams.pop(st.sid, None)
        await _send_grpc_error(conn, writer, st.sid, "quota exceeded")
        return
    ctx["stats"]["total_requests"] += 1
    connections[st.conn_id]["bytes"] += header_len

    try:
        target_reader, target_writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=TARGET_TIMEOUT
        )
    except Exception as exc:
        logger and logger.warning(f"🚫 gRPC target connect failed {address}:{port}: {exc}")
        connections.pop(st.conn_id, None)
        st.conn_id = None
        streams.pop(st.sid, None)
        await _send_grpc_error(conn, writer, st.sid, "target unreachable")
        return

    sock = target_writer.transport.get_extra_info("socket")
    if sock:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    st.target_reader = target_reader
    st.target_writer = target_writer
    st.opened = True
    st.vless_buf = b""

    if rest:
        if not await ctx["check_and_use"](uid, len(rest)):
            await _close_stream(st, connections)
            return
        await ctx["throttle"](uid, len(rest))
        target_writer.write(rest)
        await target_writer.drain()

    st.pump_task = asyncio.create_task(_pump_target_to_grpc(st, conn, writer, ctx))


async def _route_payload(st: _GrpcStream, payload: bytes, conn, writer, streams: dict, ctx):
    """payload یک پیام gRPC را به تونل می‌رساند (باز کردن یا ادامه‌ی ارسال)."""
    if not payload:
        return
    if st.opened:
        if not await ctx["check_and_use"](st.uid, len(payload)):
            await _close_stream(st, ctx["connections"])
            return
        await ctx["throttle"](st.uid, len(payload))
        st.target_writer.write(payload)
        if st.target_writer.transport.get_write_buffer_size() > RELAY_BUF:
            await st.target_writer.drain()
        if st.conn_id in ctx["connections"]:
            ctx["connections"][st.conn_id]["bytes"] += len(payload)
    else:
        st.vless_buf += payload
        await _try_open_tunnel(st, conn, writer, streams, ctx)


async def _consume_grpc_frames(st: _GrpcStream, conn, writer, streams: dict, ctx):
    """فریم‌های gRPC بافر شده را استخراج و مسیریابی می‌کند."""
    while True:
        buf = st.grpc_buf
        if len(buf) < 5:
            return
        length = int.from_bytes(buf[1:5], "big")
        if len(buf) < 5 + length:
            return
        payload = buf[5:5 + length]
        st.grpc_buf = buf[5 + length:]
        if payload:
            await _route_payload(st, payload, conn, writer, streams, ctx)
        if st.sid not in streams:
            return  # استریم رد/بسته شده


async def _handle_event(conn, writer, streams: dict, event, ctx):
    if isinstance(event, h2.events.RequestReceived):
        sid = event.stream_id
        headers = {k.lower(): v for k, v in event.headers}
        method = headers.get(":method", "")
        path = headers.get(":path", "")
        ctype = headers.get("content-type", "")
        match = GRPC_PATH_RE.match(path or "")
        if method != "POST" or not match or not ctype.startswith("application/grpc"):
            conn.send_headers(sid, [(":status", "404"), ("content-type", "text/plain")], end_stream=True)
            return
        service = match.group(1).lower()
        st = _GrpcStream(sid, service)
        st.client_ip = _client_ip(writer)
        streams[sid] = st
        # پاسخ gRPC: هدرها همان ابتدا فرستاده می‌شوند (مثل Xray)
        conn.send_headers(sid, [
            (":status", "200"),
            ("content-type", "application/grpc"),
            ("grpc-encoding", "identity"),
        ])

    elif isinstance(event, h2.events.DataReceived):
        st = streams.get(event.stream_id)
        conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
        if st is None or st.sid not in streams:
            return
        st.grpc_buf += event.data
        await _consume_grpc_frames(st, conn, writer, streams, ctx)

    elif isinstance(event, h2.events.StreamEnded):
        st = streams.get(event.stream_id)
        if st:
            st.client_closed = True
            await _consume_grpc_frames(st, conn, writer, streams, ctx)
            if st.target_writer:
                try:
                    st.target_writer.write_eof()
                except Exception:
                    pass
            elif st.sid in streams and len(st.vless_buf) < 24:
                # کلاینت END_STREAM داد بدون هدر VLESS کامل → خطای gRPC و بستن
                streams.pop(st.sid, None)
                await _send_grpc_error(conn, writer, st.sid, "bad request")

    elif isinstance(event, h2.events.StreamReset):
        st = streams.pop(event.stream_id, None)
        if st:
            await _close_stream(st, ctx["connections"])

    elif isinstance(event, h2.events.ConnectionTerminated):
        raise RuntimeError("h2 connection terminated")


async def _handle_conn(reader, writer):
    from main import (
        LINKS, LINKS_LOCK, stats, hourly_traffic, connections, error_logs,
        is_link_allowed, is_ip_allowed, save_state, log_activity, now_ir,
    )
    from speed_limit import throttle

    async def check_and_use(uid: str, n: int) -> bool:
        async with LINKS_LOCK:
            link = LINKS.get(uid)
            if link is None:
                return False
            if not is_link_allowed(link):
                return False
            link["used_bytes"] += n
            stats["total_bytes"] += n
            hourly_traffic[now_ir().strftime("%H:00")] += n
        return True

    ctx = {
        "check_and_use": check_and_use,
        "throttle": throttle,
        "connections": connections,
        "error_logs": error_logs,
        "stats": stats,
        "save_state": save_state,
    }

    streams: dict[int, _GrpcStream] = {}
    conn = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
    )
    conn.initiate_connection()

    try:
        _flush(conn, writer)
        await writer.drain()
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break
            for event in conn.receive_data(data):
                await _handle_event(conn, writer, streams, event, ctx)
                if isinstance(event, h2.events.ConnectionTerminated):
                    raise RuntimeError("h2 connection terminated")
            _flush(conn, writer)
            if writer.transport.get_write_buffer_size() > RELAY_BUF:
                await writer.drain()
    except (h2.exceptions.H2Error, ValueError, RuntimeError, ConnectionError):
        pass
    except Exception:
        pass
    finally:
        for st in list(streams.values()):
            try:
                await _close_stream(st, connections)
            except Exception:
                pass
        streams.clear()
        asyncio.create_task(save_state())
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# ============================================================
# START / STOP
# ============================================================

async def start_grpc_relay(app_logger=None):
    """در startup اصلی main.py صدا زده می‌شود. اگر پورت قابل bind نباشد فقط لاگ می‌کند."""
    global _server, logger
    logger = app_logger
    try:
        _server = await asyncio.start_server(_handle_conn, "0.0.0.0", GRPC_LISTEN_PORT)
        logger and logger.info(f"VLESS-gRPC (gun/h2c) relay listening on 0.0.0.0:{GRPC_LISTEN_PORT}")
    except Exception as exc:
        logger and logger.warning(f"gRPC relay could not start on port {GRPC_LISTEN_PORT}: {exc}")


async def stop_grpc_relay():
    global _server
    if _server:
        _server.close()
        try:
            await _server.wait_closed()
        except Exception:
            pass
        _server = None
