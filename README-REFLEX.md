# VodiWalker on Reflex (Build / Cloud)

ساختار پروژه (مطابق درخت فایل Reflex Build):

```
app/__init__.py
app/app.py          <- نقطهٔ ورود Reflex (api_transformer + lifespan + لندینگ‌پیج)
app/vodiwalker/     <- سورس اصلی پنل، دست‌نخورده (main.py، pages.py، رله‌ها، ...)
assets/             <- favicon.ico، placeholder.svg
apt-packages.txt    <- پکیج‌های سیستمی لازم برای بیلد
requirements.txt
rxconfig.py         <- app_name="app" + قفل بک‌اند روی ۱ worker
```

`reflex.lock/` (bun.lock, package.json) اولین بار که Reflex بیلد بگیرد ساخته می‌شود — داخل ریپو نیست.

## چرا GRANIAN_WORKERS=1؟

Reflex در prod بک‌اند را با چند پروسه بالا می‌آورد؛ VodiWalker تک‌پروسه‌ای است
(سشن‌ها و state در حافظه‌اند). با چند worker، لاگین ثبت می‌شد ولی درخواست بعدی
به worker دیگری می‌رسید → 401 → پرتاب به /login («پنل ریست می‌شود»).
این تنظیم داخل `rxconfig.py` انجام شده — دست نزنید.

## عیب‌یابی: ModuleNotFoundError: No module named 'uvicorn'

اگر این خطا را (قرمز، بالای لندینگ‌پیج) دیدید یعنی در محیط دیپلوی `main.py`
پنل اصلاً import نشده — چون پنل در سطح ماژول `import uvicorn` دارد و
requirements نصب نشده بود. این بسته دو لایهٔ محافظت دارد:

1. `requirements.txt` خودش `uvicorn[standard]>=0.30` دارد.
2. `app/app.py` قبل از لود پنل وابستگی‌های حیاتی را چک می‌کند و اگر نبودند
   همان لحظه با pip نصب‌شان می‌کند (self-heal، مثل پنل RVG).

اگر باز هم دیدید، یعنی یا `requirements.txt` در ریشهٔ ریپو نیست، یا دیپلوی از
ریپو/برنچ دیگری گرفته شده — ساختار بخش بالا را با ریپوی خودتان مقایسه کنید.

## Secrets (Reflex Build → Secrets)

- هیچ Secret اجباری وجود ندارد.
- اختیاری: `ADMIN_USERNAME` و `ADMIN_PASSWORD` (فقط اگر state خالی باشد استفاده می‌شوند).
- توکن ربات تلگرام از داخل خود پنل (تنظیمات) وارد می‌شود.

## چک‌های اول بعد از دیپلوی

1. `https://<app>/` → لندینگ‌پیج با آمار زنده (فرانت‌اند Reflex)
2. `https://<app>/ping` → `"pong"` (بک‌اند Reflex)
3. `https://<app>/health` → `{"status":"ok",...}` (مسیر خود پنل — یعنی مسیرهای سفارشی به بک‌اند می‌رسند)
4. `https://<app>/login` → ورود با `admin` / `123456` — **فوراً رمز را عوض کنید**
5. یک ساب را در v2rayNG/Hiddify ایمپورت کنید (`/sub/<uuid>` باید کار کند)

اگر ۳ جواب نداد ولی ۲ جواب داد، یعنی پلتفرم فقط مسیرهای خود Reflex را به
بک‌اند می‌فرستد — آن‌وقت از دیپلوی با گزینهٔ full-deploy یا هاست دیگری استفاده کنید.

## مهاجرت از پنل قبلی (Railway)

1. در پنل قبلی: بکاپ → دانلود فایل JSON
2. در پنل جدید: بکاپ → بازیابی → همان فایل را آپلود کنید
3. لینک‌ها و UUIDها حفظ می‌شوند؛ هاست‌های مردهٔ دامنهٔ قبلی خودکار پاک می‌شوند
4. «آدرس عمومی» در تنظیمات را **خالی بگذارید** تا لینک ساب از دامنهٔ Reflex ساخته شود

## نکتهٔ ذخیره‌سازی داده

State پنل در پوشهٔ داده روی دیسک همان deployment است. دیسک محلی روی Reflex
Cloud بعد از restart/redeploy پاک می‌شود → هر چند وقت یک‌بار از داخل پنل
**بکاپ بگیرید** و بعد از هر redeploy همان را restore کنید.
