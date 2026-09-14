# NESS — التكامل الحقيقي بين Cyber Range وبقية النظام

## لماذا كانت النسخة السابقة تبدو وكأن السيناريو يعمل داخل Cyber Range فقط؟

كان مسار التنفيذ مقسوماً إلى جزأين:

1. محرك Cyber Range كان ينفذ الحركة ويسجل جزءاً من الـ Network Flows ويستطيع إنشاء Incident/Evidence.
2. إنشاء Alert والتحليل التلقائي AI كان يعتمد على Callback/Worker خلفي منفصل.

إذا لم يعمل الـWorker في اللحظة نفسها، أو انقطع WebSocket في المتصفح، أو أعيد تشغيل نفس السيناريو خلال نافذة منع التكرار، كانت صفحة Cyber Range تتحرك بينما الصفحات الأخرى لا تتغير مباشرة.

## ما الذي تغير في هذه النسخة؟

أصبح السيناريو الأمني لا يعتبر مكتملاً حتى يكتب المسار الأمني بالكامل في قاعدة SQLite نفسها:

Traffic / Scenario
→ Detection
→ Incident
→ Digital Evidence + SHA-256
→ Alert
→ INTS Tracking
→ Automatic AI Analysis
→ Risk Score / Prediction
→ System Logs
→ Network Flows
→ WebSocket data.changed
→ تحديث جميع الواجهات

التنفيذ أصبح **متزامناً بالنسبة لسيناريوهات Cyber Range الأمنية**؛ لذلك عند انتهاء زر Run تكون بيانات Incident/Alert/Evidence/AI/INTS محفوظة بالفعل وليست مجرد مهمة مؤجلة في الخلفية.

## مزامنة الواجهات

يوجد مساران للتحديث معاً:

- WebSocket للدفع الفوري.
- `/api/ui-revision` كمسار احتياطي خفيف يتم فحصه كل 1.5 ثانية. إذا تغيرت قاعدة البيانات يتم تحديث الصفحة المفتوحة تلقائياً حتى لو تعطل WebSocket.

Dashboard والرسوم البيانية والجداول وصفحات Alerts وAI وLogs وINTS وNetwork Traffic أصبحت تستجيب لتغير البيانات دون الحاجة لإعادة تحميل يدوي.

## كل ضغطة Run هي تشغيل مستقل

يحصل كل تشغيل Scenario على Run ID مستقل. في بيئة التدريب لا يتم دمج تشغيلين يدويين متتاليين لنفس السيناريو في Incident واحد. هذا يجعل العرض أمام اللجنة واضحاً وقابلاً للتتبع:

Scenario Run → Incident Code → Evidence → Alert → AI → INTS.

وفي جدول Scenario History يظهر رابط الـIncident الناتج من السيناريو الأمني.

## ماذا يتغير عند السيناريو الطبيعي؟

السيناريو الطبيعي لا يجب أن ينشئ Incident أو Alert لأن ذلك سيكون سلوكاً غير واقعي. لكنه يغيّر فعلياً:

- Network Flows
- Packets / Bytes
- Network Device counters
- Logs
- Scenario History
- Dashboard network metrics

أمثلة: Ping، Normal HTTP، Send Message.

## ماذا يتغير عند السيناريو الأمني؟

SQL Injection وXSS وTraversal وPort Scan وAuthentication Burst وICMP Burst وHost Sweep تنشئ في كل تشغيل، حسب الكشف:

- Incident
- Evidence مع SHA-256
- Alert
- Automatic AI Analysis
- INTS events
- Security/AI logs
- Network Flows
- تحديث Dashboard
- WebSocket events
- Arduino عند تفعيله ووفق Alarm Policy

## لوحة Live NESS Integration

أضيفت داخل Network Topology لوحة تعرض مباشرة أعداد:

Incidents / Alerts / Evidence / AI / INTS / Logs / Network Flows / Scenario Runs

وهذه الأرقام ليست Counters مستقلة؛ بل تقرأ من نفس جداول SQLite التي تستخدمها الصفحات الأخرى، لذلك يمكنك التأكد بصرياً من انتقال البيانات إلى النظام كله.

## ملاحظة تقنية مهمة

هذه النسخة هي النسخة البسيطة التي طلبت عدم حاجتها إلى WSL/VMware/Docker. خدمات HTTP/TCP/UDP تعمل فعلياً عبر local sockets، بينما عناوين 10.10.x.x والطوبولوجيا هي نموذج شبكة منطقي داخل NESS. البيانات الأمنية، قاعدة البيانات، الأدلة، SHA-256، التحليل، التنبيهات وتغيّر الواجهات كلها عمليات فعلية داخل التطبيق.
