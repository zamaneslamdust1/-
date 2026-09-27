"""
Shadowsocks AEAD relay (TCP) — سرور Shadowsocks داخلی هسته پنل
================================================================
پنل برای پروتکل «shadowsocks» فقط لینک سمت کلاینت نمی‌سازد؛ این ماژول سرور
واقعی SS است (مثل tcp_relay.py یک لیسنر جداگانه).

- روش‌های پشتیبانی‌شده: chacha20-ietf-poly1305 (پیش‌فرض) و aes-256-gcm
- چندکاربره: رمز هر کاربر = UUID لینک (یا ss_password دستیِ همان لینک)
- احتساب ترافیک / محدودیت IP / انقضا / محدودیت سرعت دقیقاً مثل tcp_relay
- پورت داخلی: 6544 (متغیر محیطی SS_LISTEN_PORT)
  * Railway: قابلیت «TCP Proxy» را به همین پورت داخلی وصل کن و مقدار
    «SS Port عمومی» را در تنظیمات پنل (Railway Network Center) وارد کن.
- نکته: UDP Relay فعلاً پشتیبانی نمی‌شود (فقط TCP) — مرور وب کاملاً کار می‌کند.
"""

import asyncio
import hashlib
import os
import secrets
import socket
from datetime import datetime

logger = None  # در start_ss_relay() از main ست می‌شود

SS_LISTEN_PORT = int(os.environ.get("SS_LISTEN_PORT", "6544"))
RELAY_BUF = 256 * 1024
MAX_CHUNK = 0x3FFF          # سقف payload هر چانک در پروتکل SS-AEAD
KEY_LEN = 32                # هر دو متد 256 بیتی هستند
SALT_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16
HANDSHAKE_TIMEOUT = 15.0

DEFAULT_METHOD = "chacha20-ietf-poly1305"
SUPPORTED_METHODS = (DEFAULT_METHOD, "aes-256-gcm")

_server = None


# ============================================================
# CRYPTO — طبق مشخصات رسمی Shadowsocks AEAD
# ============================================================

def evp_bytes_to_key(password: str, key_len: int = KEY_LEN) -> bytes:
    """KDF استاندارد Shadowsocks (معادل OpenSSL EVP_BytesToKey با MD5)."""
    data = password.encode("utf-8")
    out = b""
    prev = b""
    while len(out) < key_len:
        prev = hashlib.md5(prev + data).digest()
        out += prev
    return out[:key_len]


def derive_subkey(master: bytes, salt: bytes) -> bytes:
    """HKDF-SHA1 با info = b\"ss-subkey\" طبق spec."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA1(), length=KEY_LEN, salt=salt, info=b"ss-subkey").derive(master)


class _StreamCipher:
    """AEAD جریانی SS با nonce شمارنده‌ای 12 بایتی little-endian (از 0)."""

    def __init__(self, method: str, password: str, salt: bytes):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
        self.subkey = derive_subkey(evp_bytes_to_key(password), salt)
        self._impl = AESGCM(self.subkey) if method == "aes-256-gcm" else ChaCha20Poly1305(self.subkey)
        self._enc_counter = 0
        self._dec_counter = 0

    @staticmethod
    def _nonce(counter: int) -> bytes:
        return counter.to_bytes(NONCE_LEN, "little")

    def encrypt(self, plain: bytes) -> bytes:
        out = self._impl.encrypt(self._nonce(self._enc_counter), plain, None)
        self._enc_counter += 1
        return out

    def decrypt(self, data: bytes) -> bytes:
        out = self._impl.decrypt(self._nonce(self._dec_counter), data, None)
        self._dec_counter += 1
        return out


# ============================================================
# PROTOCOL HELPERS
# ============================================================

def _parse_socks_address(payload: bytes):
    """آدرس هدف در قالب SOCKS5: ATYP + addr + port (2B big-endian)."""
    if len(payload) < 2:
        raise ValueError("payload too small")
    atyp = payload[0]
    pos = 1
    if atyp == 1:  # IPv4
        if len(payload) < pos + 4 + 2:
            raise ValueError("short ipv4")
        address = ".".join(str(b) for b in payload[pos:pos + 4])
        pos += 4
    elif atyp == 3:  # Domain
        if len(payload) < pos + 1:
            raise ValueError("short domain len")
        dlen = payload[pos]
        pos += 1
        if len(payload) < pos + dlen + 2:
            raise ValueError("short domain")
        address = payload[pos:pos + dlen].decode("utf-8", errors="ignore")
        pos += dlen
    elif atyp == 4:  # IPv6
        if len(payload) < pos + 16 + 2:
            raise ValueError("short ipv6")
        ab = payload[pos:pos + 16]
        pos += 16
        address = ":".join(f"{ab[i]:02x}{ab[i + 1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown addr type: {atyp}")
    port = int.from_bytes(payload[pos:pos + 2], "big")
    pos += 2
    return address, port, payload[pos:]


async def _read_exact(reader: asyncio.StreamReader, n: int, timeout: float | None = None) -> bytes:
    buf = b""
    while len(buf) < n:
        if timeout is not None:
            chunk = await asyncio.wait_for(reader.read(n - len(buf)), timeout=timeout)
        else:
            chunk = await reader.read(n - len(buf))
        if not chunk:
            raise EOFError("connection closed")
        buf += chunk
    return buf


async def _collect_ss_users() -> dict:
    """{password: (uid, method)} از بین لینک‌های زنده — رمز پیش‌فرض هر لینک UUID خودش است."""
    from main import LINKS, LINKS_LOCK, is_link_allowed
    users: dict[str, tuple[str, str]] = {}
    async with LINKS_LOCK:
        items = list(LINKS.items())
    for uid, link in items:
        try:
            if not is_link_allowed(link):
                continue
        except Exception:
            continue
        password = str(link.get("ss_password") or "").strip() or uid
        method = str(link.get("ss_method") or DEFAULT_METHOD).strip().lower()
        if method not in SUPPORTED_METHODS:
            method = DEFAULT_METHOD
        users.setdefault(password, (uid, method))
    return users


def _client_ip(writer) -> str:
    try:
        peer = writer.get_extra_info("peername")
        return peer[0] if peer else "نامشخص"
    except Exception:
        return "نامشخص"


# ============================================================
# PIPES
# ============================================================

async def _pipe_ss_to_target(reader, target_writer, client_cipher: _StreamCipher, rest: bytes,
                             conn_id: str, uid: str, check_and_use, throttle):
    """کلاینت (رمزگشایی‌شده) → هدف. اولین payload بعد از آدرس هم همین‌جا ارسال می‌شود."""
    try:
        if rest:
            if not await check_and_use(uid, len(rest)):
                return
            await throttle(uid, len(rest))
            target_writer.write(rest)
            await target_writer.drain()
        while True:
            enc_len = await _read_exact(reader, 2 + TAG_LEN)
            plain_len = client_cipher.decrypt(enc_len)
            n = int.from_bytes(plain_len, "big")
            if n == 0:
                continue
            if n > MAX_CHUNK:
                break
            enc_payload = await _read_exact(reader, n + TAG_LEN)
            data = client_cipher.decrypt(enc_payload)
            if not data:
                continue
            if not await check_and_use(uid, len(data)):
                break
            await throttle(uid, len(data))
            target_writer.write(data)
            if target_writer.transport.get_write_buffer_size() > RELAY_BUF:
                await target_writer.drain()
    except Exception:
        pass
    finally:
        try:
            target_writer.write_eof()
        except Exception:
            pass


async def _pipe_target_to_ss(target_reader, client_writer, server_cipher: _StreamCipher, server_salt: bytes,
                             conn_id: str, uid: str, check_and_use, throttle):
    """هدف → کلاینت (رمزگذاری‌شده با salt سرور)."""
    salt_sent = False
    try:
        while True:
            data = await target_reader.read(RELAY_BUF)
            if not data:
                break
            if not await check_and_use(uid, len(data)):
                break
            await throttle(uid, len(data))
            if not salt_sent:
                client_writer.write(server_salt)
                salt_sent = True
            for off in range(0, len(data), MAX_CHUNK):
                piece = data[off:off + MAX_CHUNK]
                # فرمت SS-AEAD: [طول ۲ بایتی رمز شده + تگ] + [payload رمز شده + تگ]
                client_writer.write(
                    server_cipher.encrypt(len(piece).to_bytes(2, "big"))
                    + server_cipher.encrypt(piece)
                )
            if client_writer.transport.get_write_buffer_size() > RELAY_BUF:
                await client_writer.drain()
    except Exception:
        pass


# ============================================================
# HANDLER
# ============================================================

async def _handle_client(reader, writer):
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

    conn_id = secrets.token_urlsafe(6)
    ip = _client_ip(writer)
    target_writer = None
    uid = None

    try:
        # 1) salt کلاینت + اولین چانک طول → تشخیص کاربر با امتحان رمزها
        salt = await _read_exact(reader, SALT_LEN, HANDSHAKE_TIMEOUT)
        enc_len_chunk = await _read_exact(reader, 2 + TAG_LEN, HANDSHAKE_TIMEOUT)

        users = await _collect_ss_users()
        if not users:
            return

        client_cipher = None
        matched_password = None
        matched_method = None
        payload_len = 0
        last_err = None
        for password, (cand_uid, cand_method) in users.items():
            try:
                cand = _StreamCipher(cand_method, password, salt)
                plain = cand.decrypt(enc_len_chunk)
                if len(plain) != 2:
                    raise ValueError("bad length chunk")
                n = int.from_bytes(plain, "big")
                if not (0 < n <= MAX_CHUNK):
                    raise ValueError("bad chunk size")
                client_cipher = cand
                matched_password = password
                matched_method = cand_method
                payload_len = n
                break
            except Exception as exc:
                last_err = exc
                continue

        if client_cipher is None:
            logger and logger.warning(
                f"🚫 SS [{conn_id}] auth failed from {ip} (no matching password) users={len(users)} last_err={last_err}"
            )
            stats["total_errors"] += 1
            return

        # 2) اولین payload کامل (شامل آدرس هدف)
        enc_payload = await _read_exact(reader, payload_len + TAG_LEN, HANDSHAKE_TIMEOUT)
        first_payload = client_cipher.decrypt(enc_payload)
        address, port, rest = _parse_socks_address(first_payload)

        # 3) مجوزها — uid کاربر از رمز پیدا شده می‌آید
        uid = users[matched_password][0]

        async with LINKS_LOCK:
            link = LINKS.get(uid)

        if not is_link_allowed(link):
            logger and logger.warning(f"🚫 SS [{conn_id}] uuid={uid[:8]}… not allowed")
            return

        if not is_ip_allowed(link, uid, ip):
            log_activity("connection", f"اتصال Shadowsocks {ip} به کانفیگ «{link.get('label', '?')}» رد شد (محدودیت IP)", "warn")
            return

        connections[conn_id] = {
            "uuid": uid, "ip": ip, "transport": "shadowsocks",
            "connected_at": datetime.now().isoformat(), "bytes": 0,
        }
        logger and logger.info(f"✅ SS [{conn_id}] uuid={uid[:8]}… → {address}:{port} ip={ip} total={len(connections)}")
        log_activity("connection", f"اتصال Shadowsocks جدید از {ip} → {address}:{port} (کانفیگ {link.get('label', '?')})", "info")

        if not await check_and_use(uid, len(first_payload)):
            return
        stats["total_requests"] += 1
        connections[conn_id]["bytes"] += len(first_payload)

        # 4) اتصال به هدف
        target_reader, target_writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=10.0
        )
        sock = target_writer.transport.get_extra_info("socket")
        if sock:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        # 5) پاسخ: salt سرور + چانک‌های رمز شده
        server_salt = os.urandom(SALT_LEN)
        server_cipher = _StreamCipher(matched_method, matched_password, server_salt)

        done, pending = await asyncio.wait(
            {
                asyncio.create_task(_pipe_ss_to_target(reader, target_writer, client_cipher, rest, conn_id, uid, check_and_use, throttle)),
                asyncio.create_task(_pipe_target_to_ss(target_reader, writer, server_cipher, server_salt, conn_id, uid, check_and_use, throttle)),
            },
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass

        asyncio.create_task(save_state())

    except asyncio.TimeoutError:
        stats["total_errors"] += 1
        error_logs.append({"error": "ss handshake timeout", "time": datetime.now().isoformat()})
    except (EOFError, ValueError) as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": f"ss protocol: {exc}", "time": datetime.now().isoformat()})
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        logger and logger.error(f"SS relay error [{conn_id}]: {exc}")
    finally:
        if target_writer:
            try:
                target_writer.close()
                await target_writer.wait_closed()
            except Exception:
                pass
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        connections.pop(conn_id, None)
        logger and logger.info(f"🔌 SS closed [{conn_id}]")


# ============================================================
# START / STOP
# ============================================================

async def start_ss_relay(app_logger=None):
    """در startup اصلی main.py صدا زده می‌شود. اگر پورت قابل bind نباشد فقط لاگ می‌کند."""
    global _server, logger
    logger = app_logger
    try:
        _server = await asyncio.start_server(_handle_client, "0.0.0.0", SS_LISTEN_PORT)
        logger and logger.info(f"Shadowsocks AEAD relay listening on 0.0.0.0:{SS_LISTEN_PORT} ({', '.join(SUPPORTED_METHODS)})")
    except Exception as exc:
        logger and logger.warning(f"Shadowsocks relay could not start on port {SS_LISTEN_PORT}: {exc}")


async def stop_ss_relay():
    global _server
    if _server:
        _server.close()
        try:
            await _server.wait_closed()
        except Exception:
            pass
        _server = None
