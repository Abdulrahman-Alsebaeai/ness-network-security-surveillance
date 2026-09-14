# تشغيل NESS Integrated Cyber Lab

## لا توجد مرحلة إعداد شبكة خارجية
لا تحتاج Ubuntu أو WSL أو VM أو Docker.

## الخطوات
1. فك المشروع.
2. شغّل `run_windows.bat`.
3. انتظر `SELF-CHECK PASSED`.
4. افتح `http://127.0.0.1:5000`.
5. سجل الدخول.
6. افتح `Cyber Range → Network Topology`.
7. إذا كان Auto Start مفعلاً ستظهر الشبكة Running تلقائياً.
8. إن كانت متوقفة اضغط `Start Lab`.
9. جرب `Normal HTTP` ثم `Send Message`.
10. بعد ذلك شغّل Security Scenario وشاهد Incident/Evidence/AI/Alert تتحدث تلقائياً.

## إذا كان منفذ داخلي مستخدماً
لا تحتاج تعديله. Web وDB وUDP services تستخدم منافذ Localhost ديناميكية يختارها النظام تلقائياً.
