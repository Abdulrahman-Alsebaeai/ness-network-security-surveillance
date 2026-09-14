# NESS — النسخة المبسطة Integrated Cyber Lab

## ما الذي تغير؟
هذه النسخة صُممت لتعمل مباشرة على Windows من خلال Python فقط. لا تحتاج:

- WSL أو Ubuntu.
- VMware أو VirtualBox.
- Docker.
- Npcap أو Scapy.
- إعداد Network Adapter أو IP يدوي.
- صلاحية Administrator لمختبر الشبكة.

بعد تثبيت مكتبات Python المطلوبة، يكفي تشغيل `run_windows.bat`.

## كيف تعمل الشبكة؟
NESS ينشئ داخله شبكة تدريبية منطقية كاملة:

```text
Client-PC 10.10.10.11
        |
   Users Switch
        |---- Security-Test 10.10.10.40
        |
NESS Gateway / IDS
10.10.10.1 / 10.10.20.1 / 10.10.30.1
       / \
      /   \
 DMZ Switch   Data Switch
     |            |
Web Server     Database Server
10.10.20.20    10.10.30.30
  :8080          :5432
```

واجهة **Cyber Range → Network Topology** تعرض الشبكة كاملة بأسلوب شبيه Packet Tracer، وتعرض Online/Offline، حركة الحزم، الخدمات، السيناريوهات، والتهديدات.

## ما الحقيقي وما المنطقي؟
- Web Server يعمل فعلياً باستخدام HTTP Socket محلي.
- Database Server يعمل فعلياً باستخدام TCP Socket محلي.
- Send Message ينفذ اتصال Client → Web ثم Web → DB فعلياً عبر Localhost sockets.
- Security scenarios ترسل HTTP/TCP/UDP محلي حقيقي ومقيد بالمختبر.
- عناوين `10.10.x.x` والسويتشات والراوتر هي طبقة شبكة منطقية يديرها NESS نفسه؛ ليست Network Namespaces مستقلة على مستوى Kernel.

هذا الاختيار هو المقصود في هذه النسخة لأنه يلغي جميع متطلبات الأنظمة الافتراضية ويحافظ على عرض عملي وتفاعلي وسهل للمناقشة.

## التشغيل
1. فك الضغط في مسار عادي مثل `C:\NESS\NESS_Simple_Integrated_Lab_Final`.
2. تأكد أن Python مثبت.
3. شغّل `run_windows.bat`.
4. في أول مرة فقط سيقوم بتثبيت مكتبات Python الناقصة.
5. افتح `http://127.0.0.1:5000`.
6. أنشئ أول Administrator إذا كانت قاعدة البيانات جديدة.
7. افتح **Cyber Range → Network Topology**.
8. المختبر يبدأ تلقائياً افتراضياً، ويمكن Start / Stop / Reset من نفس الصفحة.

## السيناريوهات المدمجة
- Client → Web Connectivity Test.
- Normal HTTP.
- Send Message Client → Web → DB.
- SQL Injection Lab Test.
- Reflected XSS Lab Test.
- Directory Traversal Lab Test.
- TCP Port Scan Lab Test.
- Authentication Burst.
- ICMP/Echo Burst.
- DMZ Host Sweep.

كل السيناريوهات محصورة داخل المختبر المحلي ولا تقبل عنوان إنترنت خارجي.

## المسار الأمني
```text
Integrated Lab Traffic
        ↓
NESS Gateway / Sensor Logic
        ↓
Detection + Classification
        ↓
Incident
        ↓
Digital Evidence + SHA-256
        ↓
INTS Tracking
        ↓
Alert
        ↓
Automatic AI Analysis
        ↓
Risk Score + Prediction
        ↓
WebSocket Live Updates
        ↓
Dashboard / Topology / Traffic / Incidents / Evidence
        ↓
Arduino حسب Alarm Policy
```


## العربية والإنجليزية
النسخة تدعم English LTR وArabic RTL بالكامل. يمكن التبديل من زر EN/AR في أعلى كل صفحة أو من Settings → Interface Language. تم إصلاح مشكلة تعليق المتصفح في العربية بإعادة بناء محرك i18n مع حماية من MutationObserver loops. راجع `BILINGUAL_SUPPORT_AR.md`.

---

## تحديث التكامل الكامل بين Cyber Range والواجهات

في هذه النسخة تم إصلاح المسار بحيث لا يبقى السيناريو داخل صفحة Network Topology فقط. السيناريو الأمني يكمل الآن Incident + Evidence + Alert + INTS + Automatic AI + Logs + Network Flows قبل انتهاء طلب Run، ثم يصدر حدث `data.changed` لجميع الواجهات.

كما تمت إضافة مزامنة احتياطية عبر `/api/ui-revision` كل 1.5 ثانية لضمان تحديث الصفحات حتى إذا انقطع WebSocket. يوجد شرح مفصل في `FULL_REALTIME_INTEGRATION_AR.md`.
