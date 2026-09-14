# معمارية NESS Integrated Cyber Lab

## 1. الواجهة
`frontend/network-topology.html` + `frontend/assets/js/lab-topology.js`

تعرض كامل الشبكة بصرياً: الأجهزة، السويتشات، Gateway، الخوادم، الروابط، وحركة Traffic والتهديدات لحظياً.

## 2. محرك المختبر
`ness_core/cyber_lab_service.py`

هو المسؤول عن:
- Lifecycle: Start / Stop / Reset.
- Topology وDevice Registry.
- Web Server محلي حقيقي.
- DB TCP Service محلي حقيقي.
- UDP Echo Service.
- السيناريوهات التدريبية.
- Flow aggregation.
- Network anomaly detection.
- إرسال الأحداث عبر WebSocket.

## 3. الكشف والاستجابة
HTTP Detector + Network Event Detector → Incident → Evidence/SHA-256 → INTS → Alert → Automatic AI → Arduino.

## 4. العزل
لا يتم إنشاء Route أو NAT أو اتصال تلقائي بأي جهاز خارجي. جميع خدمات المختبر تستمع على `127.0.0.1` فقط، والعناوين `10.10.x.x` هي عناوين المختبر المنطقية التي تظهر في NESS.
