# NESS — تحقق البناء النهائي للشبكة

تم إجراء اختبارات البناء التالية على النسخة قبل ضغطها:

- Python compile لجميع ملفات `app.py` و`ness_core` و`scripts`: ناجح.
- JavaScript syntax check لجميع ملفات `frontend/assets/js`: ناجح.
- إنشاء قاعدة SQLite جديدة بالكامل من `SCHEMA`: ناجح، و`PRAGMA integrity_check = ok`.
- ترقية قاعدة المشروع الحالية بدون حذف المستخدمين/الأهداف الموجودة: ناجح.
- التحقق من جداول `network_devices` و`network_flows` والـindexes والإعدادات: ناجح.
- اختبار أن `NETWORK_CIDR=192.168.56.0/24` يجعل AUTO يختار كرت المختبر المطابق بدل Wi‑Fi: ناجح باختبار وحدة اصطناعي.
- اختبار قواعد Network Port Scan وTCP SYN Flood وICMP Host Sweep: ناجح.
- اختبار تكاملي مستقل: Network Detection → Incident → SHA-256 Evidence → INTS → Automatic AI Classification/Risk/Prediction: ناجح.
- فحص مسارات API الشبكية المطلوبة داخل Flask: ناجح.
- فحص روابط/Assets صفحات HTML المحلية وعدم وجود مراجع محلية مفقودة: ناجح.
- اختبار أن `safe_network_sensor_demo.py` يرفض عنوان IPv4 عام: ناجح.
- قاعدة المشروع النهائية لا تحتوي Network Devices/Flows/Network Sensor incidents تجريبية أضيفت أثناء الاختبار.

## ما يحتاج اختبارًا على جهاز العرض نفسه

الالتقاط الفعلي من كرت Windows يعتمد على البيئة الخارجية وليس على ملفات Python فقط، لذلك يجب قبل العرض:

1. تثبيت Npcap.
2. تشغيل NESS بصلاحية Administrator.
3. وجود VirtualBox/VMware Lab adapter داخل CIDR المحدد.
4. فتح `Network Devices` والتأكد من Discovery.
5. فتح `Live Network Traffic` والتأكد أن `Sensor State = Running`.
6. إذا كان المطلوب رؤية VM-to-VM traffic، استخدام Promiscuous Mode / Port Mirroring أو وضع NESS على مسار الترافيك.

إذا لم تتحقق هذه المتطلبات، لا يعرض NESS بيانات مزيفة؛ بل تظهر حالة `Degraded` مع سبب المشكلة.
