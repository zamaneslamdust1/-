"""VodiWalker — Reflex entrypoint  (project layout: app/app.py, app_name="app").

کد اصلی پنل (اپ FastAPI، رله‌های VLESS-TCP / Shadowsocks / gRPC / XHTTP،
داشبورد HTML، ربات تلگرام) **بدون هیچ تغییری** در app/vodiwalker/ است.
این فایل فقط:

  1. مسیر app/vodiwalker را قابل import می‌کند و یک پوشهٔ دادهٔ قابل نوشتن
     انتخاب می‌کند (روی Reflex Cloud مسیر کاری/ریشه همیشه writable نیست)،
  2. اپ FastAPI پنل را با ``api_transformer`` به Reflex می‌دهد تا همهٔ مسیرهای
     پنل (/login، /dashboard، /api/*، /sub/*، /sub-all، ...) توسط همان
     بک‌اندی سرو شود که مسیرهای خود Reflex (/ping، /_event، /_upload) را
     سرو می‌کند — https://reflex.dev/docs/api-routes/overview/ ,
  3. startup/shutdown پنل را از طریق یک Reflex lifespan task دقیقاً یک‌بار
     اجرا می‌کند (https://reflex.dev/docs/utility-methods/lifespan-tasks/)،
  4. روی "/" یک لندینگ‌پیج بومی Reflex با آمار زنده و دکمهٔ ورود به پنل می‌سازد.
"""
import asyncio
import inspect
import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import reflex as rx

logger = logging.getLogger("VodiWalker-Reflex")

ROOT = Path(__file__).resolve().parent.parent
VW_DIR = Path(__file__).resolve().parent / "vodiwalker"


# ── 1. environment ───────────────────────────────────────────────────────────
def _pick_data_dir() -> str:
    """پنل state خودش را در DATA_DIR ذخیره می‌کند. مسیر /data روی Reflex Cloud
    معمولاً قابل نوشتن نیست؛ اولین مسیری که واقعاً writable باشد برمی‌گردد.
    دیسک محلی روی Cloud بعد از restart/redeploy پاک می‌شود → بکاپ/restore
    از داخل خود پنل راهِ نگه‌داشتن داده‌هاست."""
    for cand in (
        os.environ.get("DATA_DIR"),
        "/data",
        str(ROOT / ".vodiwalker_data"),
        "/tmp/vodiwalker_data",
    ):
        if not cand:
            continue
        try:
            p = Path(cand)
            p.mkdir(parents=True, exist_ok=True)
            probe = p / ".write_test"
            probe.write_text("ok")
            probe.unlink()
            return str(p)
        except Exception:
            continue
    return "/tmp"


os.environ["DATA_DIR"] = _pick_data_dir()

# ── بوت‌سترپ اولین اجرا ─────────────────────────────────────────────────────
# اگر در مسیر داده‌ی انتخاب‌شده هنوز state نداریم، seed تمیز داخل ریپو
# (app/vodiwalker/data/vodiwalker_state.json) را کپی می‌کنیم تا پنل با
# تنظیمات شناخته‌شده بالا بیاید (ورود: admin/123456 — بعداً عوضش کنید).
_VW_SEED = VW_DIR / "data" / "vodiwalker_state.json"
try:
    _dst_state = Path(os.environ["DATA_DIR"]) / "vodiwalker_state.json"
    if _VW_SEED.is_file() and not _dst_state.exists():
        _dst_state.write_bytes(_VW_SEED.read_bytes())
        logger.info("Seeded initial VodiWalker state -> %s", _dst_state)
except Exception:
    logger.exception("Could not seed initial state")

# ── 1.5 نصب خودکار وابستگی‌های حیاتی (تور ایمنی) ─────────────────────────────
# Reflex Cloud معمولاً requirements.txt را نصب می‌کند؛ اما اگر به هر دلیلی
# نصب نشده باشد، بک‌اند با «ModuleNotFoundError: No module named 'uvicorn'»
# می‌میرد (همان خطای دیپلوی قبلی). مثل main.py پنل RVG، قبل از لود پنل چک
# می‌کنیم و هر چه نبود همان‌جا نصب می‌کنیم تا دیپلوی همیشه بالا بیاید.
def _ensure_runtime_deps() -> None:
    import importlib.util
    import subprocess

    needed = {
        "uvicorn": "uvicorn[standard]>=0.30",
        "fastapi": "fastapi>=0.115",
        "aiofiles": "aiofiles>=23.2.1",
        "httpx": "httpx[http2]>=0.27,<1.0",
        "psutil": "psutil>=5.9.8,<8",
        "h2": "h2>=4.1.0",
        "cryptography": "cryptography>=41.0.0",
    }
    missing = [pkg for mod, pkg in needed.items() if importlib.util.find_spec(mod) is None]
    if not missing:
        return
    logger.warning("Missing runtime dependencies, installing now: %s", missing)
    try:
        subprocess.check_call(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--quiet",
                "--disable-pip-version-check",
                *missing,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        logger.info("Runtime dependencies installed successfully")
    except Exception:
        logger.exception("Runtime dependency installation failed — panel import may fail")


_ensure_runtime_deps()

# ماژول‌های پنل همدیگر را با اسم سطح بالا import می‌کنند
# (`import tcp_relay`، `from pages import LOGIN_HTML`، `from main import ...`)
# پس پوشهٔ سورس باید اول sys.path باشد.
if str(VW_DIR) not in sys.path:
    sys.path.insert(0, str(VW_DIR))

# ── 2. لود پنل (خطای import به‌جای کرش، روی لندینگ‌پیج نشان داده می‌شود) ──────
vw_main = None
_VW_ERROR = ""
try:
    import main as vw_main  # app/vodiwalker/main.py
except Exception as exc:  # pragma: no cover
    logger.exception("VodiWalker failed to import")
    _VW_ERROR = f"{type(exc).__name__}: {exc}"

# ── 3. شروع/توقف دقیقاً یک‌بار، فارغ از اینکه کدام هوک اول صدا زده شود ────────
_state = {"started": False, "stopped": False}
_lock = asyncio.Lock()

if vw_main is not None:
    _router = vw_main.app.router

    # پنل هندلرها را با @app.on_event(...) ثبت کرده؛ همه را برمی‌داریم و
    # نسخهٔ idempotent خودمان جایگزین می‌کنیم تا کنار lifespan Reflex دوبار
    # اجرا نشوند.
    _orig_startup_handlers = list(getattr(_router, "on_startup", None) or [])
    _orig_shutdown_handlers = list(getattr(_router, "on_shutdown", None) or [])
    if isinstance(getattr(_router, "on_startup", None), list):
        _router.on_startup[:] = []
    if isinstance(getattr(_router, "on_shutdown", None), list):
        _router.on_shutdown[:] = []

    async def _run_handlers(handlers):
        for _h in handlers:
            try:
                _res = _h()
                if inspect.isawaitable(_res):
                    await _res
            except Exception:
                logger.exception("VodiWalker lifecycle handler failed")

    async def _startup_once():
        async with _lock:
            if _state["started"]:
                return
            _state["started"] = True  # اول ست می‌شود: هیچ‌وقت per-request ری‌استارت تکراری نکن
            logger.info("VodiWalker startup (via Reflex lifespan)")
            await _run_handlers(_orig_startup_handlers)

    async def _shutdown_once():
        if _state["stopped"] or not _state["started"]:
            return
        _state["stopped"] = True
        try:
            await _run_handlers(_orig_shutdown_handlers)
        except Exception:
            logger.exception("VodiWalker shutdown failed")

    # تور ایمنی: اگر به هر دلیلی lifespan اجرا نشده بود، اولین درخواست HTTP
    # پنل را استارت می‌کند.
    @vw_main.app.middleware("http")
    async def _lazy_start(request, call_next):
        if not _state["started"]:
            await _startup_once()
        return await call_next(request)

    @asynccontextmanager
    async def _vw_lifespan():
        await _startup_once()
        try:
            yield
        finally:
            await _shutdown_once()


# ── 4. لندینگ‌پیج بومی Reflex ────────────────────────────────────────────────
def _backend_base() -> str:
    """'' = همون origin (حالت عادی). اگر api_url رفلکس به یک هاست واقعی
    اشاره کند، لینک پنل هم به همان هاست می‌رود."""
    try:
        from reflex.config import get_config

        url = (get_config().api_url or "").rstrip("/")
    except Exception:
        url = ""
    return "" if (not url or "localhost" in url or "127.0.0.1" in url) else url


PANEL_URL = f"{_backend_base()}/login"


class PanelState(rx.State):
    ready: bool = False
    error: str = _VW_ERROR
    version: str = "--"
    uptime: str = "--:--:--"
    connections: int = 0
    links_total: int = 0
    subs_total: int = 0
    traffic: str = "0 B"
    requests: int = 0

    @rx.event
    def refresh(self):
        m = vw_main
        if m is None:
            return
        try:
            self.version = f"v{m.APP_VERSION}"
            self.uptime = m.uptime()
            self.connections = len(m.connections)
            self.links_total = len(m.LINKS)
            self.subs_total = len(m.SUBS)
            self.traffic = m.fmt_bytes(int(m.stats.get("total_bytes", 0)))
            self.requests = int(m.stats.get("total_requests", 0))
            self.error = ""
            self.ready = True
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"


def stat_card(label: str, value) -> rx.Component:
    return rx.card(
        rx.vstack(
            rx.text(label, size="2", color_scheme="gray"),
            rx.heading(value, size="6"),
            align="center",
            spacing="1",
        ),
        width="100%",
    )


def index() -> rx.Component:
    return rx.el.div(
        rx.container(
            rx.vstack(
                rx.image(src="/placeholder.svg", width="72px", height="72px", alt="VodiWalker"),
                rx.heading("VodiWalker", size="9"),
                rx.text(
                    "پنل مدیریت و فروش کانفیگ — VLESS · Shadowsocks · gRPC · XHTTP",
                    color_scheme="gray",
                    size="4",
                    text_align="center",
                ),
                rx.cond(
                    PanelState.error != "",
                    rx.callout(PanelState.error, icon="triangle_alert", color_scheme="red", width="100%"),
                ),
                rx.grid(
                    stat_card("نسخه", PanelState.version),
                    stat_card("زمان فعالیت", PanelState.uptime),
                    stat_card("اتصال‌های زنده", PanelState.connections),
                    stat_card("کانفیگ‌ها", PanelState.links_total),
                    stat_card("گروه‌های ساب", PanelState.subs_total),
                    stat_card("ترافیک کل", PanelState.traffic),
                    columns="2",
                    spacing="3",
                    width="100%",
                ),
                rx.hstack(
                    # load کامل صفحه: /login یک مسیر بک‌اند (FastAPI) است نه صفحهٔ Next.js
                    rx.button(
                        "ورود به پنل مدیریت",
                        size="3",
                        on_click=rx.call_script(f"window.location.href='{PANEL_URL}'"),
                    ),
                    rx.button("بروزرسانی آمار", size="3", variant="soft", on_click=PanelState.refresh),
                    spacing="3",
                    wrap="wrap",
                    justify="center",
                ),
                spacing="5",
                align="center",
                padding_y="4em",
            ),
            size="3",
        ),
        dir="rtl",
    )


app = rx.App(
    api_transformer=vw_main.app if vw_main is not None else None,
)
app.add_page(index, route="/", title="VodiWalker", on_load=PanelState.refresh)

if vw_main is not None:
    app.register_lifespan_task(_vw_lifespan)
