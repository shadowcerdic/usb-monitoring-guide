# خلاصهٔ فارسی راهنمای پایش USB

این ریپو یک **راهنمای گام‌به‌گام** برای ساختن داشبورد پایش USB و DLP در
**Splunk** است. داده سینتتیک، detector آفلاین یا محیط دمو همراه آن نیست؛
تلمتری را از محیط واقعی خودت می‌آوری. نسخهٔ Elastic فقط در ضمیمه آمده است.

نسخهٔ کامل و اصلی به انگلیسی است:
[README انگلیسی](../../README.md)

## چه چیزی می‌سازی

- ایندکس `usb_monitoring` و sourcetype `usb_monitoring_json`
- یک lookup به نام `usb_file_attribution.csv` که رویدادهای ساخت فایل را با
  join روی **میزبان + حرف درایو + زمان** به سریال USB وصل می‌کند
- چهار تشخیص:
  - کپی دسته‌ای فایل‌های حساس به مدیای جداشدنی (T1052)
  - کپی سورس‌کد خارج از ساعت کاری (T1052)
  - ساخت انبوه فایل `.locked` روی دیسک ثابت (T1486)
  - اتصال HID ناشناس و اجرای شل تا ۶۰ ثانیه بعد (T1200 + T1059.001)
- داشبورد Splunk برای اتصال‌ها، فایل‌های منتسب، HID و فایل‌های قفل‌شده
- فرایند allowlist، تیونینگ و اعتبارسنجی

## مسیر ۱۰ مرحله‌ای

1. [دامنه و معماری](../01-scope-and-architecture.md)
2. [منابع تلمتری](../02-telemetry-sources.md)
3. [اینجست در Splunk](../03-splunk-ingestion.md)
4. [نگاشت فیلدها](../04-field-mapping.md)
5. [انتساب نشست USB](../05-usb-session-attribution.md)
6. [تشخیص‌ها](../06-detections.md)
7. [داشبورد](../07-dashboards.md)
8. [allowlist](../08-allowlist.md)
9. [تیونینگ و عملیات](../09-tuning-and-operations.md)
10. [اعتبارسنجی](../10-validation.md)

## سه نکتهٔ کلیدی که طراحی را عوض می‌کند

1. **رویداد Security 6416 حرف درایو ندارد.** فقط Device ID و ClassName
   می‌دهد. حرف درایو باید از inventory دیسک/ولوم، یک collector یا EDR بیاید.
2. **6416 رویداد قطع اتصال نیست.** قطع اتصال از EDR یا کانال
   Kernel-PnP/Device Management می‌آید و شمارهٔ رویداد بین buildهای ویندوز
   فرق می‌کند. اگر قطع اتصال نداشته باشی، نشست تا اتصال بعدی یا پایان
   lookback باز می‌ماند و انتساب فایل بعد از جدا کردن دستگاه می‌تواند خطا شود.
3. **6416 دستگاه HID را هم لاگ می‌کند** (اگر Audit PnP Activity روشن باشد)،
   ولی سریال HID اغلب خالی یا غیریکتاست. allowlist را روی سریال،
   device instance path یا asset ID از EDR بگذار و کیفیت آن را روی fleet
   خودت تست کن.

Sysmon اتصال دستگاه را لاگ نمی‌کند؛ فقط EID 11 (ساخت فایل) و EID 1
(شروع پروسه) را می‌دهد.

## پیش‌نیاز فعال‌سازی 6416

در auditpol نام subcategory برابر **Plug and Play Events** و در
Detailed Tracking است:

```bat
auditpol /set /subcategory:"Plug and Play Events" /success:enable
auditpol /get /subcategory:"Plug and Play Events"
```

مسیر Group Policy:
Computer Configuration → Windows Settings → Security Settings →
Advanced Audit Policy Configuration → System Audit Policies → Detailed
Tracking → Audit PNP Activity

اگر نام‌ها در سیستم تو محلی شده‌اند، با `auditpol /list /subcategory:*`
پیدا کن.

## فایل‌های مهم

- `splunk/props.conf` — استخراج زمان و JSON
- `splunk/macros.conf` — ماکروی `usb_normalize`
- `splunk/transforms.conf` — تعریف lookup انتساب
- `detections/splunk/*.spl` — چهار تشخیص
- `splunk/USB_Monitoring_Dashboard.xml` — داشبورد
- `scripts/enrich_usb_attribution.py` — job زمان‌بندی‌شده برای ساخت lookup
- `scripts/collect_usb_telemetry.ps1` — جمع‌آوری/اعتبارسنجی تلمتری ویندوز
- `appendix/elastic/` — نسخهٔ Elastic (ضمیمه، مسیر اصلی نیست)

## اجرای سریع

1. ایندکس `usb_monitoring` را بساز و فایل‌های `splunk/` را در app نصب کن.
2. 6416 و Sysmon را روی هاست‌های مجاز فعال کن و داده را به Splunk بفرست.
3. با کوئری‌های فصل ۲ مطمئن شو `usb.volume_letter` و `usb.serial_number`
   واقعاً می‌رسند.
4. `scripts/enrich_usb_attribution.py` را با توکن Splunk اجرا کن و
   `usb_file_attribution.csv` را بساز.
5. job را هر ۵ تا ۱۵ دقیقه اجرا کن و کهنه شدن lookup را آلارم بده.
6. SPLها را در حالت alert-only ذخیره کن.
7. داشبورد را import کن.
8. allowlist را با سریال‌های واقعی بساز.
9. دو هفته alert-only، بعد تیونینگ.
10. تست‌های فصل ۱۰ را روی هاست/دستگاه تست مجاز اجرا کن.

## چه چیزی تست نشده

هیچ کلاستر Splunk زنده‌ای در این ریپو برای اجرای SPL/XML استفاده نشده است.
کوئری‌ها و XML برای Splunk 9.x ساختاردهی شده‌اند، اما باید در محیط خودت
در حالت alert-only تست شوند. ضمیمهٔ Elastic هم جداگانه اعتبارسنجی شود.

## حریم خصوصی

نام و مسیر فایل می‌تواند داده شخصی یا مقرراتی داشته باشد. ایندکس
`usb_monitoring` را فقط به نقش‌های لازم بده، retention را آگاهانه تنظیم کن
و تلمتری خام را منتشر نکن. این راهنما جایگزین سیاست device-control یا DLP
محتوا نیست.
