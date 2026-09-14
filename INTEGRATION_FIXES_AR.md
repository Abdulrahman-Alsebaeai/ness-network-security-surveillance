# NESS — إصلاح الربط الحقيقي بين Cyber Range وبقية النظام

## ما الذي تم إصلاحه؟

تم توحيد مسار الحدث بحيث يصبح تنفيذ السيناريو الأمني في Cyber Range مرتبطاً فعلياً بقاعدة البيانات وبقية وحدات NESS:

`Scenario Run → Network/HTTP Event → Detection → Incident → Evidence → Alert → AI Analysis → INTS → Logs/Flows → Realtime UI Update`

### أهم الإصلاحات

1. تشغيل محرك المراقبة والـCyber Range أصبح مضموناً عند تشغيل التطبيق، وليس فقط عند تشغيل `app.py` بطريقة محددة.
2. كل تشغيل صريح لسيناريو هجومي يحصل على Run ID مستقل، لذلك تكرار SQL Injection أو Brute Force مباشرة ينشئ حادثة جديدة بدلاً من اختفائها بسبب منع التكرار الزمني.
3. عزل ذاكرة Port Scan وICMP/Host Sweep بين السيناريوهات حتى لا يرث سيناريو نتائج السيناريو السابق.
4. تمرير `X-NESS-Lab-Run-ID` و`X-NESS-Lab-Scenario` داخل طلبات المختبر وربطها بالدليل والحادثة.
5. نتيجة تشغيل السيناريو تعرض الآن الحادثة المرتبطة وعدد Alerts وEvidence وAI وINTS وNetwork Flows المسجلة فعلياً.
6. سجل Scenario History يعرض الحادثة المرتبطة ونوع الهجوم.
7. تحديث الواجهات الحية أصبح Debounced بدلاً من إعادة طلب كل بيانات النظام عند كل Packet، لمنع عشرات الطلبات المتداخلة أثناء Burst/Scan.
8. تم إضافة تصنيفات AI لـ Host Sweep وICMP Flood / Sweep.
9. زر Stop Lab لم يعد يسمح للـAuto Start بإعادة تشغيل المختبر تلقائياً بعد الإيقاف اليدوي في نفس جلسة التشغيل.
10. WebSocket يرسل Snapshot بعد اكتمال السيناريو، فتتحدث الصفحات المفتوحة من البيانات المخزنة فعلياً.

## ماذا يجب أن يتغير بعد السيناريو؟

### سيناريوهات أمنية
مثل SQL Injection وXSS وDirectory Traversal وPort Scan وAuthentication Burst وICMP Burst وHost Sweep:

- Dashboard: ترتفع أعداد الحوادث/الهجمات/التنبيهات/التدفقات حسب الحدث.
- Incidents: حادثة جديدة مرتبطة بتشغيل السيناريو.
- Real-time Alerts: تنبيه جديد.
- Evidence: دليل جديد محفوظ في SQLite.
- AI Analysis: تحليل آلي للحادثة عند تفعيل Auto AI.
- Logs: سجلات تنفيذ/كشف/إنشاء الحادثة.
- INTS Tracking: أحداث التتبع المرتبطة.
- Network Traffic: تدفقات وحزم مرتبطة بالسيناريو.
- Cyber Range Scenario History: Run مستقل ورابط للحادثة.

### سيناريوهات طبيعية
مثل Normal HTTP وSend Message:

هذه لا ينبغي أن تنشئ Incident أمني لأنها حركة سليمة. لكنها تسجل Scenario Run وتحدث Network Flows/Traffic/Devices/System Logs حسب النشاط.

## التشغيل

على Windows شغّل:

`run_windows.bat`

ثم افتح:

`http://127.0.0.1:5000/network-topology.html`

نفّذ مثلاً SQL Injection. في نتيجة السيناريو يجب أن يظهر Run ID وIncident ورقم العناصر التي تم إنشاؤها، ثم ستظهر البيانات في بقية صفحات النظام تلقائياً.

## ملاحظة عن معنى "حقيقي"

المختبر Integrated Cyber Lab آمن ومضمّن داخل NESS. الاتصالات إلى خدمات Web/DB/Echo تستخدم sockets فعلية على localhost، بينما عناوين 10.10.x.x هي عناوين منطقية لطوبولوجيا المختبر. النظام لا يقوم بمسح أو مهاجمة شبكة خارجية ولا يحتاج VM/WSL/Docker/Npcap ليعمل.
