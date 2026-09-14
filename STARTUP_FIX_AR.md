# إصلاح توقف NESS في Self-Check

## السبب
كان مجلد المشروع على جهاز المستخدم يحتوي صفحتين قديمتين من إصدار سابق:
- `frontend/monitored-targets.html`
- `frontend/target-details.html`

الإصدار الحالي ألغى مسار Monitored Targets لصالح Network Devices / Cyber Range، لكن فحص اللغتين يفحص كل ملفات HTML الموجودة في المجلد. الصفحتان القديمتان لا تحتويان `language-bootstrap.js` لذلك كان الفحص يوقف التشغيل قبل وصول Flask إلى مرحلة البدء.

## الإصلاح في هذه النسخة
- أضيفت صفحتا Compatibility آمنتان بنفس الاسمين حتى يتم استبدال أي ملفات قديمة عند فك النسخة فوق مجلد سابق.
- كلتا الصفحتين تحملان `language-bootstrap.js` و`i18n.js` ثم تحولان المستخدم إلى `network-devices.html`.
- تم تحديث `project_self_check.py` لاستخدام `importlib.metadata.version()` بدل `__version__` القديم في Flask، لذلك يختفي DeprecationWarning الخاص بـ Flask.
- لا يوجد أي تغيير في قاعدة البيانات أو الحوادث أو Cyber Range أو الربط اللحظي.

## طريقة الاستخدام الصحيحة
يفضل فك هذه النسخة في مجلد جديد نظيف، ثم تشغيل `run_windows.bat`.
إذا أردت استبدال المجلد القديم، انسخ النسخة كاملة فوقه مع السماح بالاستبدال لكل الملفات.
