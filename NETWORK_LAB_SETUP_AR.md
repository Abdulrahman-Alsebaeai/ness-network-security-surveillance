# NESS — دليل التطبيق العملي للشبكة الافتراضية

هذه النسخة مصممة لتعمل داخل **مختبر شبكة خاص ومعزول**. الإعداد الافتراضي مقيد إلى:

```text
192.168.56.0/24
```

ولا يقوم NESS تلقائيًا باختيار شبكة Wi‑Fi أو LAN أخرى عندما لا يجد واجهة تنتمي إلى هذا النطاق؛ بدلًا من ذلك تظهر حالة **Degraded** إلى أن يتم إعداد شبكة المختبر أو تغيير `Network CIDR` يدويًا من Settings.

## ماذا يحدث تلقائيًا بعد تجهيز المختبر؟

```text
تشغيل NESS
   ↓
اختيار كرت الشبكة الذي ينتمي إلى Lab CIDR
   ↓
اكتشاف الأجهزة تلقائيًا ARP / Ping
   ↓
تحديث Network Devices و Online / Offline
   ↓
التقاط Metadata لحركة IPv4 المرئية لكرت الشبكة
   ↓
تجميعها إلى Network Flows
   ↓
Normal Traffic أو اكتشاف نمط مشبوه
   ↓
Incident + Digital Evidence + SHA-256 + INTS
   ↓
Alert + Automatic AI Analysis / Risk / Prediction
   ↓
WebSocket Live UI
   ↓
Arduino / Telegram حسب الإعدادات
```

لا يتم حفظ Payload الحزم من الـPacket Sensor؛ يتم حفظ **Metadata** فقط مثل Source/Destination IP، المنافذ، البروتوكول، عدد الحزم، عدد البايتات، TCP Flags، الوقت والتصنيف.

---

## الطريقة الأسهل للعرض أمام اللجنة — NESS على Windows + VirtualBox

### 1. أنشئ شبكة Host‑Only في VirtualBox

اجعل الشبكة مثلًا:

```text
Network: 192.168.56.0/24
Host / NESS: 192.168.56.1
```

إذا كانت VirtualBox Host‑Only الموجودة لديك تستخدم نطاقًا مختلفًا، يمكنك بدلًا من تغييره أن تضع نطاقها الحقيقي داخل:

```text
Settings → Automatic Network Sensor → Network CIDR
```

### 2. أنشئ الأجهزة الافتراضية

خطة بسيطة مناسبة للمناقشة:

```text
Windows Host / NESS       192.168.56.1
Ubuntu Web Server VM      192.168.56.20
Client VM                 192.168.56.30
Authorized Test VM        192.168.56.40
Subnet Mask               255.255.255.0
```

لا تحتاج هذه الشبكة إلى الإنترنت لتنفيذ العرض المحلي.

### 3. على Windows

- ثبّت Npcap حتى يستطيع Scapy التقاط الحزم من كرت الشبكة.
- شغّل `run_windows.bat` باستخدام **Run as administrator** عند استخدام Passive Packet Sensor.
- افتح NESS ثم Settings.
- اترك `Network Interface = AUTO`.
- ضع `Network CIDR = 192.168.56.0/24`.
- فعّل `Automatic device discovery` و`Passive packet sensor`.
- احفظ الإعدادات ثم اضغط `Restart Sensor`.

عند نجاح الالتقاط يجب أن ترى:

```text
Sensor State: Running
Network CIDR: 192.168.56.0/24
Interface: اسم VirtualBox Host-Only Adapter
```

ثم افتح **Network Devices**. خلال أول دورة اكتشاف أو عند الضغط على **Discover Now** ستظهر الأجهزة التي استطاع NESS اكتشافها تلقائيًا، بدون إضافتها إلى Monitored Targets.

> `Monitored Targets` بقيت كميزة منفصلة لفحص خدمات HTTP/URLs دوريًا. اكتشاف أجهزة الشبكة لا يحتاج إلى إضافتها هناك.

---

## تجربة حركة طبيعية

من Client VM افتح متصفحًا وتوجه إلى:

```text
http://192.168.56.1:5000
```

ستظهر حركة TCP/HTTP في **Live Network Traffic** إذا كان الـPacket Sensor يرى كرت المختبر. التدفق العادي يسجل بتصنيف:

```text
Normal
Risk: 0/100
```

---

## تجربة آمنة لمحرك HTTP والكشف التلقائي

من Authorized Test VM انسخ ملف:

```text
scripts/safe_demo_requests.py
```

ثم بعد تثبيت `requests` شغّل:

```bash
python safe_demo_requests.py --base-url http://192.168.56.1:5000
```

السكريبت نفسه يرفض الأهداف العامة ويقبل localhost أو IPv4 خاص/محلي فقط. وهو يستخدم مسارات `/watched/*` المصممة داخل NESS للعرض الآمن.

بعدها يفترض أن يظهر التسلسل آليًا:

```text
Detection
→ Incident
→ SHA-256 Evidence
→ INTS
→ Alert
→ Automatic AI Classification
→ Risk Score
→ Predicted Severity
→ Recommendation
→ WebSocket update
→ Arduino إذا كانت السياسة تسمح
```

---

## تجربة آمنة للـPassive Network Sensor نفسه

لإثبات أن الاكتشاف لا يعتمد فقط على `/watched/*`، يوجد ملف محدود ومقيد للمختبر:

```text
scripts/safe_network_sensor_demo.py
```

شغله **من Authorized Test VM** فقط داخل شبكة المختبر:

```bash
python safe_network_sensor_demo.py --target 192.168.56.1
```

هو يجرب عددًا صغيرًا جدًا من منافذ TCP المتتالية على عنوان خاص فقط، ولا يرسل Payload أو يستغل خدمة. مع الإعدادات الافتراضية يستطيع NESS اكتشاف نمط **Network Port Scan** إذا كان كرت الشبكة المحدد يرى هذه الحزم، ثم ينشئ Incident وبقية السلسلة تلقائيًا.

---

# إذا أردت رؤية VM → VM وليس فقط VM → NESS

وجود الأجهزة في نفس Subnet لا يعني وحده أن أي جهاز ثالث يرى كل الترافيك؛ الشبكات الافتراضية الحديثة تعمل كسويتش.

للعرض الأقوى:

1. شغّل NESS داخل Sensor VM مخصص.
2. اربط Sensor VM وبقية الأجهزة بنفس Host‑Only/Internal Network.
3. من VirtualBox افتح إعداد كرت الشبكة الخاص بـSensor VM واجعل **Promiscuous Mode = Allow All**.
4. أعط Sensor VM مثلًا `192.168.56.10` واجعل NESS يستخدم نفس `192.168.56.0/24`.
5. إذا كانت بيئة الـHypervisor لا تمرر كل VM-to-VM traffic رغم ذلك، ضع Sensor/Gateway على مسار الترافيك أو استخدم Port Mirroring في السويتش الافتراضي المستخدم في المختبر.

NESS لا يدعي رؤية حزمة لم تصل إلى واجهة الالتقاط. صفحة **Network Status** تعرض حالة Sensor بوضوح؛ فإذا كان Npcap/الصلاحيات/الواجهة غير صحيحة ستظهر `Degraded` مع سبب المشكلة بدلًا من إظهار بيانات وهمية.

---

# الفرق بين Network Devices وMonitored Targets

**Network Devices**:
- اكتشاف تلقائي من الشبكة.
- IP / MAC / Hostname / First Seen / Last Seen / Online-Offline.
- يتحدث تلقائيًا مع Discovery وPassive Sensor.

**Monitored Targets**:
- خدمة اختيارية لإضافة URL أو خادم تريد فحص توفره دوريًا بـHTTP GET.
- لا تستخدم لاكتشاف الأجهزة تلقائيًا.

---

# قواعد الكشف الشبكي المضافة

النسخة الحالية تحتوي قواعد دفاعية لحظية على Metadata الشبكة، منها:

```text
Network Port Scan
Network Host Sweep
TCP SYN Flood
ICMP Host Sweep
ICMP Flood
```

القيم الافتراضية قابلة للتغيير من Settings/Database إذا احتجت لاحقًا إلى ضبط المختبر. عند تحقق قاعدة، لا يحتاج المستخدم إلى الضغط على Analyze؛ يتم إنشاء الحادث وتمريره إلى محرك التحليل التلقائي مباشرة.

---

# ماذا تفعل إذا ظهر Sensor State = Degraded؟

تحقق بالترتيب:

1. هل `192.168.56.0/24` هو فعلًا نطاق شبكة VirtualBox لديك؟
2. هل يوجد كرت IPv4 على جهاز NESS داخل هذا النطاق؟
3. على Windows: هل Npcap مثبت؟
4. هل شغلت NESS كمسؤول Administrator؟
5. هل `Network Interface` مضبوط على AUTO أو اسم الكرت الصحيح؟
6. اضغط `Restart Sensor` بعد تعديل الإعدادات.
7. شغّل `scripts/project_self_check.py`؛ سيعرض Interfaces ويشرح إن كان Lab CIDR غير مطابق.

## ملاحظة مهمة

لا تحتاج إلى إضافة الأجهزة يدويًا عندما يعمل Automatic Network Discovery. الإدخال اليدوي في Monitored Targets يظل متاحًا فقط لمراقبة خدمات محددة، وليس شرطًا للمراقبة الشبكية الجديدة.
