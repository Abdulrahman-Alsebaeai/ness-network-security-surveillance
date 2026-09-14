# الإصلاحات النهائية في هذه النسخة

1. إصلاح عدم انتقال نتائج Cyber Range إلى بقية النظام.
2. تنفيذ Alert + Evidence + INTS + AI بشكل متزامن للسيناريو الأمني قبل رجوع API.
3. كل Scenario Run أصبح قابلاً للتتبع مستقلاً.
4. ربط Scenario History بالـIncident الناتج.
5. إضافة WebSocket event عام باسم `data.changed`.
6. إضافة `/api/ui-revision` ومزامنة احتياطية كل 1.5 ثانية لجميع الصفحات.
7. تحديث Dashboard والجداول وAI/INTS/Logs تلقائياً.
8. تحديث Charts عند تغير البيانات.
9. إضافة لوحة Live NESS Integration داخل Network Topology.
10. إصلاح Race Condition عند بدء المختبر تلقائياً مع الضغط اليدوي على Start.
11. استخدام SQLite UPSERT لأجهزة المختبر لمنع UNIQUE constraint errors.
12. منع دمج تشغيلين يدويين متتاليين لنفس السيناريو الأمني مع الحفاظ على منع التكرار داخل التشغيل نفسه.
13. تنظيف نافذة فحص الشبكة بين السيناريوهات حتى لا يتسرب Port Scan سابق إلى Host Sweep لاحق.
14. الحفاظ على دعم العربية RTL والإنجليزية LTR.
