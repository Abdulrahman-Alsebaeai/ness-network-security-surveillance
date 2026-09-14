# NESS Integrated Cyber Lab

هذه النسخة لا تحتاج WSL أو VMware أو VirtualBox أو Docker أو Npcap.

محرك المختبر موجود داخل `ness_core/cyber_lab_service.py` ويقوم تلقائياً بـ:

- إنشاء طوبولوجيا منطقية كاملة بثلاثة Segments: Users / DMZ / Data.
- تشغيل Web Server تدريبي حقيقي على Socket محلي HTTP.
- تشغيل Database Service تدريبي حقيقي على Socket محلي TCP.
- تشغيل Echo Service محلي UDP لاختبارات الحمل الآمنة.
- تمثيل Client-PC وSecurity-Test وNESS Gateway/Sensor وسويتشات الشبكة.
- تسجيل Traffic كـNetwork Flows داخل SQLite.
- تمرير التهديدات إلى Incidents / Evidence / INTS / Alerts / AI / Arduino.

العناوين `10.10.x.x` هي عناوين منطقية خاصة بمختبر NESS، أما الاتصالات الفعلية بين الخدمات فتعمل على localhost بمنافذ داخلية يختارها النظام تلقائياً لتفادي التعارض.
