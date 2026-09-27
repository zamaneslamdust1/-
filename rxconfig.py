import os

import reflex as rx

# ── علت قفل‌کردن بک‌اند روی ۱ پروسه ──────────────────────────────────────────
# Reflex در حالت prod روی Reflex Cloud بک‌اند را با (تعداد CPU × 2 + 1) پروسه
# (worker) بالا می‌آورد. VodiWalker تک‌پروسه‌ای است (سشن‌ها، لینک‌ها، ساب‌ها و
# آمار همه در حافظهٔ یک پروسه‌اند؛ main.py هم workers=1 دارد). با چند worker،
# لاگین روی worker A ثبت می‌شد، درخواست بعدی به worker B می‌رسید که سشن را
# نمی‌شناخت → 401 → پرتاب به /login و به نظر می‌رسید «پنل ریست می‌شود».
os.environ.setdefault("GRANIAN_WORKERS", "1")   # بک‌اند granian (پیش‌فرض Reflex)
os.environ.setdefault("WEB_CONCURRENCY", "1")   # اگر gunicorn استفاده شود

# app_name باید با پوشه‌ای که app.py داخلش است مطابقت داشته باشد (app/app.py)
config = rx.Config(
    app_name="app",
    telemetry_enabled=False,
    plugins=[
        rx.plugins.RadixThemesPlugin(
            theme=rx.theme(appearance="dark", accent_color="violet", radius="large")
        ),
        rx.plugins.SitemapPlugin(),
    ],
)
