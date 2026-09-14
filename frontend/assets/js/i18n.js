/* NESS bilingual interface support: English + Arabic. */
(function(){
  const STORAGE_KEY = 'ness_language';
  const DEFAULT_LANG = 'en';
  const AR = {
  "NESS": "NESS",
  "Network Security & Surveillance": "أمن ومراقبة الشبكات",
  "Network Security & Surveillance System": "نظام أمن ومراقبة الشبكات",
  "NESS — Network Security & Surveillance System": "NESS — نظام أمن ومراقبة الشبكات",
  "Dashboard": "لوحة التحكم",
  "SOC Dashboard": "لوحة عمليات الأمن",
  "SOC Command Center": "مركز قيادة عمليات الأمن",
  "Command": "القيادة",
  "Investigation": "التحقيق",
  "Operations": "العمليات",
  "Administration": "الإدارة",
  "Incidents": "الحوادث",
  "Incident": "الحادث",
  "Real-time Alerts": "التنبيهات الفورية",
  "Evidence": "الأدلة",
  "Digital Evidence": "الأدلة الرقمية",
  "AI Analysis": "تحليل الذكاء الاصطناعي",
  "Logs": "السجلات",
  "Reports": "التقارير",
  "Users": "المستخدمون",
  "Roles & Permissions": "الأدوار والصلاحيات",
  "Settings": "الإعدادات",
  "Authenticated User": "مستخدم موثّق",
  "Administrator": "مدير النظام",
  "Security Operator": "مشغّل الأمن",
  "Security Analyst": "محلل الأمن",
  "User Role": "دور المستخدم",
  "Monitoring online": "المراقبة متصلة",
  "Logout": "تسجيل الخروج",
  "Refresh": "تحديث",
  "Alerts": "التنبيهات",
  "Flows": "التدفقات",
  "Live integration after this run": "التكامل الحي بعد هذا التشغيل",
  "Live NESS Integration": "تكامل NESS الحي",
  "Scenario Runs": "مرات تشغيل السيناريوهات",
  "Network Flows": "تدفقات الشبكة",
  "These values are read from the same SQLite records used by Dashboard, Incidents, Alerts, Evidence, AI Analysis, Logs and INTS.": "تُقرأ هذه القيم من نفس سجلات SQLite التي تستخدمها لوحة التحكم والحوادث والتنبيهات والأدلة وتحليل الذكاء الاصطناعي والسجلات وINTS.",
  "Normal scenarios update traffic, devices and logs. Security scenarios additionally create incidents, evidence, alerts, INTS events and automatic AI analysis.": "تقوم السيناريوهات الطبيعية بتحديث الحركة والأجهزة والسجلات، بينما تنشئ السيناريوهات الأمنية أيضًا الحوادث والأدلة والتنبيهات وأحداث INTS والتحليل التلقائي بالذكاء الاصطناعي.",
  "Scenario completed and synchronized across NESS": "اكتمل السيناريو وتمت مزامنته في جميع أجزاء NESS",
  "View all": "عرض الكل",
  "Export": "تصدير",
  "View": "عرض",
  "Details": "التفاصيل",
  "Open": "فتح",
  "Preview": "معاينة",
  "Download": "تنزيل",
  "Download PDF": "تنزيل PDF",
  "Print": "طباعة",
  "Save": "حفظ",
  "Save All Settings": "حفظ كل الإعدادات",
  "Save Matrix": "حفظ المصفوفة",
  "Save user": "حفظ المستخدم",
  "Update": "تحديث",
  "Cancel": "إلغاء",
  "Clear": "مسح",
  "Action": "الإجراء",
  "Actions": "الإجراءات",
  "Status": "الحالة",
  "Severity": "الخطورة",
  "Time": "الوقت",
  "Timestamp": "الطابع الزمني",
  "Type": "النوع",
  "Target": "الهدف",
  "Targets": "الأهداف",
  "Source IP": "عنوان IP المصدر",
  "IP": "IP",
  "ID": "المعرّف",
  "Hash": "البصمة",
  "Collected": "تم الجمع",
  "Custodian": "أمين الحفظ",
  "Owner": "المسؤول",
  "Actor": "المنفذ",
  "Category": "الفئة",
  "Message": "الرسالة",
  "Level": "المستوى",
  "Author": "المعدّ",
  "Period": "الفترة",
  "Title": "العنوان",
  "Name": "الاسم",
  "Email": "البريد الإلكتروني",
  "Username": "اسم المستخدم",
  "Password": "كلمة المرور",
  "Role": "الدور",
  "Permission": "الصلاحية",
  "System": "النظام",
  "Security": "الأمن",
  "Audit": "التدقيق",
  "Critical": "حرج",
  "High": "عالٍ",
  "Medium": "متوسط",
  "Low": "منخفض",
  "Info": "معلومات",
  "New": "جديد",
  "Active": "نشط",
  "Inactive": "غير نشط",
  "Resolved": "تم الحل",
  "False Positive": "إنذار كاذب",
  "Under Investigation": "قيد التحقيق",
  "Reviewed": "تمت المراجعة",
  "Ready": "جاهز",
  "Draft": "مسودة",
  "Preserved": "محفوظ",
  "Archived": "مؤرشف",
  "Online": "متصل",
  "Warning": "تحذير",
  "Offline": "غير متصل",
  "Not Checked": "لم يتم الفحص",
  "Disabled": "معطل",
  "Not Configured": "غير مهيأ",
  "Triggered": "تم التشغيل",
  "Delivered": "تم التسليم",
  "Paused": "متوقف مؤقتًا",
  "Unknown": "غير معروف",
  "Unassigned": "غير مخصص",
  "Never": "أبدًا",
  "Website": "موقع ويب",
  "Total Incidents": "إجمالي الحوادث",
  "Today's Attacks": "هجمات اليوم",
  "Critical Alerts": "التنبيهات الحرجة",
  "+12 during the last 24h": "+12 خلال آخر 24 ساعة",
  "Requires analyst review": "يتطلب مراجعة المحلل",
  "All monitoring agents active": "كل وكلاء المراقبة نشطون",
  "Attack Type Overview": "نظرة عامة على أنواع الهجمات",
  "Live telemetry stored in SQLite": "بيانات القياس الحية محفوظة في SQLite",
  "Severity Distribution": "توزيع الخطورة",
  "Open and reviewed incidents": "الحوادث المفتوحة والمراجعة",
  "Recent Incidents": "أحدث الحوادث",
  "Latest detected suspicious activities": "أحدث الأنشطة المشبوهة المكتشفة",
  "Integration Status": "حالة التكامل",
  "Telegram alerts": "تنبيهات تيليجرام",
  "Arduino alarm": "إنذار أردوينو",
  "System health": "صحة النظام",
  "AI Insight": "رؤية الذكاء الاصطناعي",
  "No incident has been detected yet. Add a monitored target or use an authorized watched path to create records.": "لم يتم اكتشاف أي حادث حتى الآن. أضف هدفًا مراقبًا أو استخدم مسار مراقبة مصرحًا لإنشاء السجلات.",
  "No incident has been detected yet. Add a monitored target or send authorized test traffic to a watched path to create records.": "لم يتم اكتشاف أي حادث حتى الآن. أضف هدفًا مراقبًا أو أرسل حركة اختبار مصرح بها إلى مسار مراقب لإنشاء السجلات.",
  "Open AI Analysis": "فتح تحليل الذكاء الاصطناعي",
  "Alerts Feed": "تغذية التنبيهات",
  "Telegram delivered • Arduino triggered": "تم تسليم تيليجرام • تم تشغيل أردوينو",
  "Under investigation by analyst": "قيد التحقيق من قبل المحلل",
  "Incident Trend": "اتجاه الحوادث",
  "Daily activity by time window": "النشاط اليومي حسب النافذة الزمنية",
  "NESS Platform": "منصة NESS",
  "NESS Platform / Dashboard": "منصة NESS / لوحة التحكم",
  "NESS Platform / Incidents": "منصة NESS / الحوادث",
  "NESS Platform / Alerts": "منصة NESS / التنبيهات",
  "NESS Platform / Evidence": "منصة NESS / الأدلة",
  "NESS Platform / AI Analysis": "منصة NESS / تحليل الذكاء الاصطناعي",
  "NESS Platform / Logs": "منصة NESS / السجلات",
  "NESS Platform / Reports": "منصة NESS / التقارير",
  "NESS Platform / Reports / Generate": "منصة NESS / التقارير / إنشاء",
  "NESS Platform / Users": "منصة NESS / المستخدمون",
  "NESS Platform / Roles & Permissions": "منصة NESS / الأدوار والصلاحيات",
  "NESS Platform / Settings": "منصة NESS / الإعدادات",
  "NESS Platform / My Profile": "منصة NESS / ملفي الشخصي",
  "NESS Platform / My Profile / Change Password": "منصة NESS / ملفي الشخصي / تغيير كلمة المرور",
  "NESS Platform / Access Denied": "منصة NESS / وصول مرفوض",
  "NESS Platform / Empty State": "منصة NESS / حالة فارغة",
  "NESS Platform / Loading": "منصة NESS / التحميل",
  "NESS Platform / Error / 404": "منصة NESS / خطأ / 404",
  "NESS Platform / Error / 500": "منصة NESS / خطأ / 500",
  "Incidents Management": "إدارة الحوادث",
  "Incidents List": "قائمة الحوادث",
  "Search, filter, assign, and review detected events": "البحث والتصفية والتعيين ومراجعة الأحداث المكتشفة",
  "All severities": "كل مستويات الخطورة",
  "All statuses": "كل الحالات",
  "All categories": "كل الفئات",
  "All alerts": "كل التنبيهات",
  "Critical only": "الحرجة فقط",
  "High and Critical": "العالية والحرجة",
  "Attack Family": "عائلة الهجوم",
  "Attack Type": "نوع الهجوم",
  "New Incident": "حادث جديد",
  "Manual incident created": "تم إنشاء حادث يدوي",
  "Evidence ID": "معرّف الدليل",
  "Digital Evidence Repository": "مستودع الأدلة الرقمية",
  "Preserved logs, request captures, and custody metadata": "السجلات ولقطات الطلب وبيانات سلسلة الحيازة محفوظة",
  "Evidence details will load from the database when an evidence ID is provided.": "سيتم تحميل تفاصيل الدليل من قاعدة البيانات عند توفير معرّف الدليل.",
  "No evidence selected": "لم يتم تحديد دليل",
  "No Data Available": "لا توجد بيانات متاحة",
  "Empty State": "حالة فارغة",
  "This reusable empty state is used when a module has no matching records.": "تُستخدم هذه الحالة الفارغة القابلة لإعادة الاستخدام عندما لا توجد سجلات مطابقة في الوحدة.",
  "Loading State": "حالة التحميل",
  "Loading View": "واجهة التحميل",
  "Reusable skeleton state for slow data operations": "حالة تحميل قابلة لإعادة الاستخدام لعمليات البيانات البطيئة",
  "Access Denied": "وصول مرفوض",
  "Your current role does not have permission to open this protected NESS section.": "دورك الحالي لا يملك صلاحية فتح هذا القسم المحمي في NESS.",
  "Return safely": "العودة بأمان",
  "Return to dashboard": "العودة إلى لوحة التحكم",
  "Back to dashboard": "العودة إلى لوحة التحكم",
  "Open dashboard": "فتح لوحة التحكم",
  "404 Page": "صفحة 404",
  "Page Not Found": "الصفحة غير موجودة",
  "The page you requested is not available in the NESS console.": "الصفحة التي طلبتها غير متاحة في وحدة تحكم NESS.",
  "500 Error": "خطأ 500",
  "System Error": "خطأ في النظام",
  "An internal error occurred. The SOC dashboard remains available if the session is valid.": "حدث خطأ داخلي. ستظل لوحة عمليات الأمن متاحة إذا كانت الجلسة صالحة.",
  "Real-time Alert Feed": "تغذية التنبيهات الفورية",
  "Alerts delivered and stored by the NESS backend": "التنبيهات التي تم تسليمها وحفظها بواسطة خادم NESS",
  "Delivery Queue": "قائمة انتظار التسليم",
  "Delivery": "التسليم",
  "Channel": "القناة",
  "Event": "الحدث",
  "No failed notifications": "لا توجد إشعارات فاشلة",
  "Pause feed": "إيقاف التغذية مؤقتًا",
  "Resume feed": "استئناف التغذية",
  "Telegram Status": "حالة تيليجرام",
  "Arduino": "أردوينو",
  "Arduino Alarm": "إنذار أردوينو",
  "Report Settings": "إعدادات التقارير",
  "Generate Report": "إنشاء تقرير",
  "Generate Professional Report": "إنشاء تقرير احترافي",
  "Choose incident, evidence, and report sections": "اختر الحادث والأدلة وأقسام التقرير",
  "Report Type": "نوع التقرير",
  "Report Title": "عنوان التقرير",
  "Prepared By": "أعد بواسطة",
  "Include Sections": "الأقسام المضمنة",
  "Include evidence chain-of-custody": "تضمين سلسلة حيازة الأدلة",
  "Include AI recommendations": "تضمين توصيات الذكاء الاصطناعي",
  "Raw Logs Appendix": "ملحق السجلات الخام",
  "Generate Preview": "إنشاء معاينة",
  "Generate or open a report from the database to preview it here.": "أنشئ تقريرًا أو افتحه من قاعدة البيانات لمعاينته هنا.",
  "No report selected": "لم يتم تحديد تقرير",
  "Professional incident and monitoring reports": "تقارير احترافية للحوادث والمراقبة",
  "Daily SOC Summary": "ملخص عمليات الأمن اليومي",
  "Executive Summary": "الملخص التنفيذي",
  "Recommendations": "التوصيات",
  "Recommended Priority": "الأولوية الموصى بها",
  "Report Preview": "معاينة التقرير",
  "NESS Incident Investigation Report": "تقرير تحقيق حادث NESS",
  "Report ID": "معرّف التقرير",
  "Prepared": "تم الإعداد",
  "Incident Investigation": "تحقيق الحادث",
  "Incident details will load from the database when an incident ID is provided.": "سيتم تحميل تفاصيل الحادث من قاعدة البيانات عند توفير معرّف الحادث.",
  "No incident selected": "لم يتم تحديد حادث",
  "Select Incident": "اختيار حادث",
  "Select an incident from the database.": "اختر حادثًا من قاعدة البيانات.",
  "Incident Overview": "نظرة عامة على الحادث",
  "Detected": "تم الاكتشاف",
  "Method": "الطريقة",
  "Location": "الموقع",
  "Assigned To": "مُسند إلى",
  "Captured Payload": "الحمولة الملتقطة",
  "Copy": "نسخ",
  "Payload copied": "تم نسخ الحمولة",
  "No payload recorded": "لا توجد حمولة مسجلة",
  "Raw Request Data": "بيانات الطلب الخام",
  "No evidence records.": "لا توجد سجلات أدلة.",
  "Investigation Notes": "ملاحظات التحقيق",
  "Save notes": "حفظ الملاحظات",
  "Analyze Incident": "تحليل الحادث",
  "Status Timeline": "الخط الزمني للحالة",
  "Status History": "سجل الحالة",
  "No status history.": "لا يوجد سجل حالة.",
  "No status history": "لا يوجد سجل حالة",
  "Assignment": "الإسناد",
  "Assign": "إسناد",
  "Start Investigation": "بدء التحقيق",
  "Mark Resolved": "وضع علامة تم الحل",
  "Incident not found": "لم يتم العثور على الحادث",
  "Evidence Details": "تفاصيل الدليل",
  "Open Incident": "فتح الحادث",
  "Linked to": "مرتبط بـ",
  "Evidence Type": "نوع الدليل",
  "Captured": "تم الالتقاط",
  "SHA256 Integrity Hash": "بصمة سلامة SHA256",
  "Raw Evidence Record": "سجل الدليل الخام",
  "Chain of Custody": "سلسلة الحيازة",
  "Captured by": "تم الالتقاط بواسطة",
  "NESS Engine": "محرك NESS",
  "Storage status": "حالة التخزين",
  "Copy Hash": "نسخ البصمة",
  "Hash copied": "تم نسخ البصمة",
  "Evidence not found": "لم يتم العثور على الدليل",
  "Target Health Summary": "ملخص صحة الهدف",
  "Websites, servers, APIs, and network nodes monitored by NESS": "مواقع الويب والخوادم وواجهات API وعقد الشبكة التي يراقبها NESS",
  "Target Details": "تفاصيل الهدف",
  "Run Check": "تشغيل الفحص",
  "Health": "الصحة",
  "Risk Score": "درجة المخاطر",
  "Last Check": "آخر فحص",
  "Monitoring Configuration": "إعدادات المراقبة",
  "URL": "الرابط",
  "Host": "المضيف",
  "Target URL": "رابط الهدف",
  "Save Target": "حفظ الهدف",
  "Linked Incidents": "الحوادث المرتبطة",
  "Target not found": "لم يتم العثور على الهدف",
  "Add Target": "إضافة هدف",
  "Last Scan": "آخر فحص",
  "Run AI Incident Analysis": "تشغيل تحليل حادث بالذكاء الاصطناعي",
  "Run analysis on a stored incident to generate a defensive summary and recommendations.": "شغّل التحليل على حادث محفوظ لإنشاء ملخص دفاعي وتوصيات.",
  "Run analysis to create stored recommendations.": "شغّل التحليل لإنشاء توصيات محفوظة.",
  "Defensive AI analysis based on stored incident evidence": "تحليل دفاعي بالذكاء الاصطناعي بناءً على أدلة الحادث المحفوظة",
  "Generate defensive analysis from stored incident evidence": "إنشاء تحليل دفاعي من أدلة الحادث المخزنة",
  "AI Incident Analysis": "تحليل الحادث بالذكاء الاصطناعي",
  "AI History": "سجل الذكاء الاصطناعي",
  "AI Summary": "ملخص الذكاء الاصطناعي",
  "Confidence": "الثقة",
  "Model": "النموذج",
  "Result": "النتيجة",
  "Model Name": "اسم النموذج",
  "AI Model Settings": "إعدادات نموذج الذكاء الاصطناعي",
  "Confidence Threshold": "حد الثقة",
  "Generate Incident Report": "إنشاء تقرير حادث",
  "Report Configuration": "إعدادات التقرير",
  "Create a PDF report from database records": "إنشاء تقرير PDF من سجلات قاعدة البيانات",
  "Include digital evidence": "تضمين الأدلة الرقمية",
  "Include AI analysis": "تضمين تحليل الذكاء الاصطناعي",
  "Include status timeline": "تضمين الخط الزمني للحالة",
  "Generate PDF Report": "إنشاء تقرير PDF",
  "System, Security, and Audit Logs": "سجلات النظام والأمن والتدقيق",
  "Filterable operational log viewer": "عارض سجلات تشغيلية قابل للتصفية",
  "Search logs": "البحث في السجلات",
  "Export Logs": "تصدير السجلات",
  "Logs exported": "تم تصدير السجلات",
  "Users Management": "إدارة المستخدمين",
  "User Management": "إدارة المستخدمين",
  "Add User": "إضافة مستخدم",
  "Edit User": "تعديل المستخدم",
  "Full Name": "الاسم الكامل",
  "Account status": "حالة الحساب",
  "Leave blank to keep current password": "اتركه فارغًا للاحتفاظ بكلمة المرور الحالية",
  "User Profile": "ملف المستخدم",
  "My Profile": "ملفي الشخصي",
  "Current operator preferences and account information": "تفضيلات المشغل ومعلومات الحساب الحالية",
  "Interface Language": "لغة الواجهة",
  "English": "الإنجليزية",
  "Arabic": "العربية",
  "Change Password": "تغيير كلمة المرور",
  "Update current operator account password": "تحديث كلمة مرور حساب المشغل الحالي",
  "Update Password": "تحديث كلمة المرور",
  "Current password": "كلمة المرور الحالية",
  "New password": "كلمة المرور الجديدة",
  "Confirm new password": "تأكيد كلمة المرور الجديدة",
  "Confirm password": "تأكيد كلمة المرور",
  "Minimum 8 characters": "8 أحرف على الأقل",
  "Password changed successfully": "تم تغيير كلمة المرور بنجاح",
  "Secure Login": "تسجيل دخول آمن",
  "Sign in securely": "تسجيل الدخول بأمان",
  "Access the NESS security operations console with an authorized account.": "ادخل إلى وحدة عمليات الأمن NESS باستخدام حساب مصرح له.",
  "Email or Operator ID": "البريد الإلكتروني أو معرّف المشغل",
  "Remember device": "تذكر الجهاز",
  "Forgot password?": "هل نسيت كلمة المرور؟",
  "Forgot Password": "نسيت كلمة المرور",
  "Forgot password": "نسيت كلمة المرور",
  "Login": "تسجيل الدخول",
  "2FA": "التحقق الثنائي",
  "Two-Factor Verification": "التحقق الثنائي",
  "Enter the six-digit code sent to the SOC administrator channel.": "أدخل الرمز المكوّن من ستة أرقام المرسل إلى قناة مدير عمليات الأمن.",
  "Verify and open dashboard": "تحقق وافتح لوحة التحكم",
  "Lock Screen": "قفل الشاشة",
  "Administrator session locked": "جلسة المدير مقفلة",
  "Your security console is locked. Confirm your password to continue.": "وحدة التحكم الأمنية مقفلة. أكد كلمة المرور للمتابعة.",
  "Unlock session": "فتح الجلسة",
  "Reset Password": "إعادة تعيين كلمة المرور",
  "Reset password": "إعادة تعيين كلمة المرور",
  "Create a new secure password for your NESS operator account.": "أنشئ كلمة مرور آمنة جديدة لحساب مشغل NESS.",
  "Send reset link": "إرسال رابط إعادة التعيين",
  "Registered email": "البريد الإلكتروني المسجل",
  "Enter your registered account email to start the secure password recovery workflow.": "أدخل بريد حسابك المسجل لبدء سير استعادة كلمة المرور الآمن.",
  "Enterprise SOC Prototype": "نموذج أولي لمركز عمليات أمن مؤسسي",
  "Clean cybersecurity monitoring for websites and servers.": "مراقبة أمن سيبراني نظيفة للمواقع والخوادم.",
  "Real-time incidents, digital evidence, AI analysis, Telegram alerts, Arduino status, and professional reports.": "حوادث فورية، أدلة رقمية، تحليل ذكاء اصطناعي، تنبيهات تيليجرام، حالة أردوينو، وتقارير احترافية.",
  "System Settings": "إعدادات النظام",
  "General Settings": "الإعدادات العامة",
  "System Name": "اسم النظام",
  "Default Role": "الدور الافتراضي",
  "5 seconds": "5 ثوانٍ",
  "10 seconds": "10 ثوانٍ",
  "30 seconds": "30 ثانية",
  "Monitoring Settings": "إعدادات المراقبة",
  "Detection Rules": "قواعد الكشف",
  "SQL Injection safe pattern detection": "كشف أنماط حقن SQL الآمنة",
  "XSS attempt detection": "كشف محاولات XSS",
  "Directory Traversal request detection": "كشف طلبات اجتياز المسارات",
  "Port scanning threshold": "حد فحص المنافذ",
  "Telegram Bot Settings": "إعدادات بوت تيليجرام",
  "Bot Token": "رمز البوت",
  "SOC Chat ID": "معرّف محادثة عمليات الأمن",
  "Send Telegram alerts": "إرسال تنبيهات تيليجرام",
  "Arduino Settings": "إعدادات أردوينو",
  "Port / Endpoint": "المنفذ / نقطة النهاية",
  "Alarm Policy": "سياسة الإنذار",
  "Trigger Arduino for critical alerts": "تشغيل أردوينو للتنبيهات الحرجة",
  "Critical threshold enabled": "تم تفعيل حد الخطورة الحرجة",
  "Notification Settings": "إعدادات الإشعارات",
  "Roles and Permissions Matrix": "مصفوفة الأدوار والصلاحيات",
  "Clear access levels for NESS security operations console": "مستويات وصول واضحة لوحدة عمليات الأمن NESS",
  "Administrators, Security Operators, and Security Analysts": "المديرون ومشغلو الأمن ومحللو الأمن",
  "View dashboard": "عرض لوحة التحكم",
  "Review alerts": "مراجعة التنبيهات",
  "Create reports": "إنشاء التقارير",
  "Manage users": "إدارة المستخدمين",
  "Change settings": "تغيير الإعدادات",
  "Run AI analysis": "تشغيل تحليل الذكاء الاصطناعي",
  "Export evidence": "تصدير الأدلة",
  "View incident details": "عرض تفاصيل الحادث",
  "View real-time alerts": "عرض التنبيهات الفورية",
  "Search and filter incidents": "البحث وتصفية الحوادث",
  "Review digital evidence": "مراجعة الأدلة الرقمية",
  "Update incident status": "تحديث حالة الحادث",
  "Generate PDF reports": "إنشاء تقارير PDF",
  "Track incidents by INTS": "تتبع الحوادث بواسطة INTS",
  "Create user accounts": "إنشاء حسابات مستخدمين",
  "Update user information": "تحديث معلومات المستخدم",
  "Assign roles and permissions": "إسناد الأدوار والصلاحيات",
  "Configure system settings": "تهيئة إعدادات النظام",
  "User Permission Overrides": "تجاوزات صلاحيات المستخدم",
  "Save User Permissions": "حفظ صلاحيات المستخدم",
  "Use Role Defaults": "استخدام افتراضيات الدور",
  "No assigned incidents.": "لا توجد حوادث مسندة.",
  "Assigned Incidents": "الحوادث المسندة",
  "Save Profile": "حفظ الملف الشخصي",
  "Last Login": "آخر تسجيل دخول",
  "Profile": "الملف الشخصي",
  "Source": "المصدر",
  "Events": "الأحداث",
  "No live incidents": "لا توجد حوادث مباشرة",
  "Now": "الآن",
  "Action completed": "تم تنفيذ الإجراء",
  "Data refreshed from the NESS database": "تم تحديث البيانات من قاعدة بيانات NESS",
  "Session closed": "تم إغلاق الجلسة",
  "Invalid server response": "استجابة الخادم غير صالحة",
  "Authentication required": "المصادقة مطلوبة",
  "Access denied": "تم رفض الوصول",
  "Access denied for this role": "تم رفض الوصول لهذا الدور",
  "Account is not active": "الحساب غير نشط",
  "Initial Administrator Setup": "إعداد المدير الأولي",
  "Create the first Administrator account. No sample credentials are shipped with the project.": "أنشئ أول حساب مدير. لا يتم شحن المشروع بأي بيانات اعتماد تجريبية.",
  "Initial Administrator created": "تم إنشاء المدير الأولي",
  "Two-factor verification required": "التحقق الثنائي مطلوب",
  "Logged in successfully": "تم تسجيل الدخول بنجاح",
  "If the account exists, reset instructions were generated": "إذا كان الحساب موجودًا، فقد تم إنشاء تعليمات إعادة التعيين",
  "Reset token generated for this local deployment": "تم إنشاء رمز إعادة التعيين لهذا التشغيل المحلي",
  "Passwords do not match": "كلمات المرور غير متطابقة",
  "Password reset successfully": "تمت إعادة تعيين كلمة المرور بنجاح",
  "Verification completed": "اكتمل التحقق",
  "Session unlocked": "تم فتح الجلسة",
  "Password updated in the database": "تم تحديث كلمة المرور في قاعدة البيانات",
  "No database records are available for this page yet.": "لا توجد سجلات في قاعدة البيانات متاحة لهذه الصفحة حتى الآن.",
  "Analysis saved in the database": "تم حفظ التحليل في قاعدة البيانات",
  "PDF report generated": "تم إنشاء تقرير PDF",
  "Report ID not found": "لم يتم العثور على معرّف التقرير",
  "Incident status updated": "تم تحديث حالة الحادث",
  "Notes saved": "تم حفظ الملاحظات",
  "Incident assigned": "تم إسناد الحادث",
  "No active users available": "لا يوجد مستخدمون نشطون متاحون",
  "Alert marked as reviewed": "تم وضع علامة على التنبيه كمراجع",
  "Target checked": "تم فحص الهدف",
  "Target saved": "تم حفظ الهدف",
  "Target added": "تمت إضافة الهدف",
  "User saved in database": "تم حفظ المستخدم في قاعدة البيانات",
  "User updated": "تم تحديث المستخدم",
  "Profile updated": "تم تحديث الملف الشخصي",
  "Settings saved in database": "تم حفظ الإعدادات في قاعدة البيانات",
  "Permissions reset to role defaults": "تمت إعادة الصلاحيات إلى افتراضيات الدور",
  "User permissions saved": "تم حفظ صلاحيات المستخدم",
  "Alert reviewed": "تمت مراجعة التنبيه",
  "Incident assignment is stored through backend users module": "يتم حفظ إسناد الحادث عبر وحدة المستخدمين الخلفية",
  "Check": "فحص",
  "Investigate": "تحقيق",
  "Deactivate": "تعطيل",
  "Activate": "تفعيل",
  "Review": "مراجعة",
  "Profile saved": "تم حفظ الملف الشخصي",
  "Permissions saved": "تم حفظ الصلاحيات",
  "Filters cleared": "تم مسح المرشحات",
  "Notifications opened": "تم فتح الإشعارات",
  "Secure lock screen opened": "تم فتح شاشة القفل الآمنة",
  "Lock": "قفل",
  "Notifications": "الإشعارات",
  "Open menu": "فتح القائمة",
  "NESS Dashboard": "لوحة تحكم NESS",
  "Chart exported": "تم تصدير المخطط",
  "Evidence package exported": "تم تصدير حزمة الأدلة",
  "Report title": "عنوان التقرير",
  "Prepared by": "أعد بواسطة",
  "SOC chat ID": "معرّف محادثة عمليات الأمن",
  "Telegram bot token": "رمز بوت تيليجرام",
  "COM port or serial endpoint": "منفذ COM أو نقطة نهاية تسلسلية",
  "NESS-AI Incident Classifier": "مصنف حوادث NESS-AI",
  "name@example.com": "name@example.com",
  "Search by ID, target, attack type": "ابحث بالمعرّف أو الهدف أو نوع الهجوم",
  "Search evidence, incident, hash": "ابحث في الدليل أو الحادث أو البصمة",
  "Repeat password": "كرر كلمة المرور",
  "Interface language": "لغة الواجهة",
  "Path": "المسار",
  "Query": "الاستعلام",
  "User-Agent": "وكيل المستخدم",
  "Description": "الوصف",
  "Detected At": "وقت الاكتشاف",
  "AI / Defensive Analysis": "تحليل دفاعي / ذكاء اصطناعي",
  "NESS | Dashboard": "NESS | لوحة التحكم",
  "NESS | Incidents": "NESS | الحوادث",
  "NESS | Alerts": "NESS | التنبيهات",
  "NESS | Evidence": "NESS | الأدلة",
  "NESS | AI Analysis": "NESS | تحليل الذكاء الاصطناعي",
  "NESS | Logs": "NESS | السجلات",
  "NESS | Reports": "NESS | التقارير",
  "NESS | Generate": "NESS | إنشاء",
  "NESS | Users": "NESS | المستخدمون",
  "NESS | Roles & Permissions": "NESS | الأدوار والصلاحيات",
  "NESS | Settings": "NESS | الإعدادات",
  "NESS | My Profile": "NESS | ملفي الشخصي",
  "NESS | Change Password": "NESS | تغيير كلمة المرور",
  "NESS | Access Denied": "NESS | وصول مرفوض",
  "NESS | Empty State": "NESS | حالة فارغة",
  "NESS | Loading": "NESS | التحميل",
  "NESS | 404": "NESS | 404",
  "NESS | 500": "NESS | 500",
  "NESS | SOC Dashboard": "NESS | لوحة عمليات الأمن",
  "NESS | Real-time Alerts": "NESS | التنبيهات الفورية",
  "NESS | Secure Login": "NESS | تسجيل دخول آمن",
  "NESS | Forgot Password": "NESS | نسيت كلمة المرور",
  "NESS | Reset Password": "NESS | إعادة تعيين كلمة المرور",
  "NESS | Two-Factor Verification": "NESS | التحقق الثنائي",
  "NESS | Lock Screen": "NESS | قفل الشاشة",
  "NESS | Incident Details": "NESS | تفاصيل الحادث",
  "NESS | Evidence Details": "NESS | تفاصيل الدليل",
  "NESS | Target Details": "NESS | تفاصيل الهدف",
  "NESS | Report Preview": "NESS | معاينة التقرير",
  "NESS | User Profile": "NESS | ملف المستخدم",
  "404": "404",
  "500": "500",
  "0": "0",
  "4": "4",
  "12": "12",
  "AU": "AU",
  "--": "--",
  "html": "html",
  "•": "•"
};

  const AR_EXTRA = {
  "Cyber Range": "المختبر السيبراني",
  "Network Devices": "أجهزة الشبكة",
  "Live Network Traffic": "حركة الشبكة المباشرة",
  "INTS Tracking": "تتبع INTS",
  "INTS Incident Tracking": "تتبع الحوادث بنظام INTS",
  "Cyber Range Nodes": "عُقد المختبر السيبراني",
  "Online Network Devices": "أجهزة الشبكة المتصلة",
  "Network Flows 24h": "تدفقات الشبكة خلال 24 ساعة",
  "Network Threats 24h": "تهديدات الشبكة خلال 24 ساعة",
  "Network Sensor State": "حالة مستشعر الشبكة",
  "Loaded from SQLite": "محمّل من SQLite",
  "Today from SQLite": "بيانات اليوم من SQLite",
  "Open Critical incidents": "الحوادث الحرجة المفتوحة",
  "Live integrated lab devices": "أجهزة المختبر المدمج المباشرة",
  "Automatic discovery": "اكتشاف تلقائي",
  "Passive sensor metadata": "بيانات وصفية من المستشعر",
  "Automatic network detections": "اكتشافات الشبكة التلقائية",
  "Live capture engine": "محرك الالتقاط المباشر",
  "Realtime engine": "محرك الوقت الحقيقي",
  "Automatic AI": "الذكاء الاصطناعي التلقائي",
  "Automatic log analysis": "تحليل السجلات التلقائي",
  "Lab device sync": "مزامنة أجهزة المختبر",
  "Gateway sensor": "مستشعر البوابة",
  "Running": "يعمل",
  "Stopped": "متوقف",
  "Checking": "جارٍ الفحص",
  "Checking...": "جارٍ الفحص...",
  "Waiting": "في الانتظار",
  "Operational": "يعمل بشكل طبيعي",
  "Setup Required": "يتطلب إعدادًا",
  "Degraded": "متدهور",
  "Recorded": "مسجل",
  "Normal": "طبيعي",
  "Security": "أمني",
  "Security Event": "حدث أمني",
  "Cyber Range Device Inventory": "جرد أجهزة المختبر السيبراني",
  "Cyber range device inventory": "جرد أجهزة المختبر السيبراني",
  "IP Address": "عنوان IP",
  "MAC Address": "عنوان MAC",
  "Role / Runtime": "الدور / بيئة التشغيل",
  "Network Segments": "مقاطع الشبكة",
  "Observed Traffic": "الحركة المرصودة",
  "Observed Flows": "التدفقات المرصودة",
  "Last Seen": "آخر ظهور",
  "Search device, IP, MAC, role": "ابحث عن جهاز أو IP أو MAC أو دور",
  "These records come from the integrated NESS cyber lab. Devices and services are created automatically; no LAN scanning or manual target entry is required.": "تأتي هذه السجلات من مختبر NESS السيبراني المدمج. يتم إنشاء الأجهزة والخدمات تلقائيًا دون فحص شبكة LAN أو إدخال أهداف يدويًا.",
  "IP, MAC, runtime role, services, state, observed traffic, and risk are synchronized from the integrated lab.": "تتم مزامنة عنوان IP وMAC والدور والخدمات والحالة والحركة المرصودة ومستوى المخاطر من المختبر المدمج.",
  "Live Network Topology": "مخطط الشبكة المباشر",
  "NESS Cyber Range": "مختبر NESS السيبراني",
  "Packet-Tracer-style view of the integrated NESS training network. Devices, switches, routes, services, traffic, incidents, and alerts are tied directly to the running lab.": "عرض مرئي بأسلوب Packet Tracer لشبكة NESS التدريبية المدمجة. ترتبط الأجهزة والسويتشات والمسارات والخدمات والحركة والحوادث والتنبيهات مباشرة بالمختبر العامل.",
  "NESS live cyber range topology": "مخطط مختبر NESS السيبراني المباشر",
  "Start Lab": "تشغيل المختبر",
  "Stop Lab": "إيقاف المختبر",
  "Reset Lab": "إعادة ضبط المختبر",
  "Gateway Sensor Status": "حالة مستشعر البوابة",
  "Gateway Sensor": "مستشعر البوابة",
  "Online Devices": "الأجهزة المتصلة",
  "Traffic / 24h": "الحركة / 24 ساعة",
  "Packets / 24h": "الحزم / 24 ساعة",
  "Flows / 24h": "التدفقات / 24 ساعة",
  "Suspicious Flows": "التدفقات المشبوهة",
  "Device Inspector": "فاحص الجهاز",
  "Select a node in the topology": "اختر عقدة من مخطط الشبكة",
  "Click any device, switch, or the NESS gateway.": "انقر على أي جهاز أو سويتش أو بوابة NESS.",
  "Live Packet & Service Console": "وحدة الحزم والخدمات المباشرة",
  "Waiting for integrated cyber-lab traffic...": "في انتظار حركة المختبر السيبراني المدمج...",
  "Integrated Lab Scenarios": "سيناريوهات المختبر المدمج",
  "Every action below stays inside the local NESS training lab. No external target is accepted.": "كل الإجراءات أدناه تبقى داخل مختبر NESS التدريبي المحلي، ولا يُسمح بأي هدف خارجي.",
  "Scenario History": "سجل السيناريوهات",
  "Recorded execution history from the NESS database": "سجل التنفيذ المحفوظ في قاعدة بيانات NESS",
  "Choose a scenario after the lab is running.": "اختر سيناريو بعد تشغيل المختبر.",
  "Run": "تشغيل",
  "Scenario": "السيناريو",
  "Result": "النتيجة",
  "Scenario completed": "اكتمل السيناريو",
  "Scenario failed": "فشل السيناريو",
  "No scenario runs yet.": "لم يتم تشغيل أي سيناريو بعد.",
  "Logical Address": "العنوان المنطقي",
  "Segment": "المقطع",
  "Services": "الخدمات",
  "Local Runtime": "بيئة التشغيل المحلية",
  "Implementation": "التنفيذ",
  "NESS integrated virtual device": "جهاز افتراضي مدمج في NESS",
  "Employee workstation": "محطة عمل الموظف",
  "Controlled security test host": "جهاز اختبار أمني مضبوط",
  "NESS gateway and IDS sensor": "بوابة NESS ومستشعر كشف التسلل",
  "Training web server": "خادم ويب تدريبي",
  "Training data service": "خدمة بيانات تدريبية",
  "Virtual users switch": "سويتش المستخدمين الافتراضي",
  "Virtual DMZ switch": "سويتش DMZ الافتراضي",
  "Virtual data switch": "سويتش البيانات الافتراضي",
  "All Segments": "كل المقاطع",
  "Users / DMZ / Data": "المستخدمون / DMZ / البيانات",
  "Gateway + IDS Sensor": "بوابة + مستشعر IDS",
  "Client performs a four-step connectivity test to the Web Server. Reachability uses real local sockets while the topology records logical echo traffic.": "ينفذ جهاز العميل اختبار اتصال من أربع خطوات إلى خادم الويب. يستخدم الوصول مقابس محلية حقيقية بينما يسجل المخطط حركة الصدى المنطقية.",
  "Client sends a real HTTP request to the integrated Web Server and NESS records the logical route.": "يرسل العميل طلب HTTP حقيقيًا إلى خادم الويب المدمج ويسجل NESS المسار المنطقي.",
  "Client sends a real HTTP message to Web Server; Web Server stores it through a real local TCP connection to the DB service.": "يرسل العميل رسالة HTTP حقيقية إلى خادم الويب، ثم يحفظها الخادم عبر اتصال TCP محلي حقيقي بخدمة قاعدة البيانات.",
  "Test host exploits the intentionally vulnerable lab login endpoint.": "ينفذ جهاز الاختبار اختبار حقن على نقطة تسجيل الدخول الضعيفة عمدًا داخل المختبر.",
  "Test host sends a reflected XSS payload to the isolated training web app.": "يرسل جهاز الاختبار حمولة XSS منعكسة إلى تطبيق الويب التدريبي المعزول.",
  "Test host reads the disposable lab secret using a traversal flaw.": "يقرأ جهاز الاختبار ملفًا تدريبيًا مؤقتًا باستخدام ثغرة اجتياز المسار.",
  "Test host probes a fixed set of TCP ports on the lab web server.": "يفحص جهاز الاختبار مجموعة ثابتة من منافذ TCP على خادم الويب التدريبي.",
  "Test host sends repeated failed logins to trigger rate detection.": "يرسل جهاز الاختبار محاولات دخول فاشلة متكررة لتفعيل كشف معدل الطلبات.",
  "Test host generates a bounded ICMP burst inside the lab.": "ينشئ جهاز الاختبار دفعة ICMP محدودة داخل المختبر.",
  "Test host probes a bounded set of DMZ addresses.": "يفحص جهاز الاختبار مجموعة محدودة من عناوين DMZ.",
  "Integrated Cyber Lab": "المختبر السيبراني المدمج",
  "Enable integrated cyber lab": "تفعيل المختبر السيبراني المدمج",
  "Start lab automatically with NESS": "تشغيل المختبر تلقائيًا مع NESS",
  "Flow Retention (hours)": "مدة الاحتفاظ بالتدفقات (بالساعات)",
  "Runs directly with NESS on Windows/Python — no WSL, VMware, VirtualBox, Docker, Npcap, or administrator setup": "يعمل مباشرة مع NESS على Windows/Python دون WSL أو VMware أو VirtualBox أو Docker أو Npcap أو إعدادات مسؤول.",
  "The lab starts from": "يبدأ المختبر من",
  ". Its Web and Database services use real local sockets, while NESS maintains the complete logical topology, traffic, detections, incidents, evidence and live visualization.": ". تستخدم خدمات الويب وقاعدة البيانات مقابس محلية حقيقية، بينما يدير NESS المخطط المنطقي الكامل والحركة والاكتشافات والحوادث والأدلة والعرض المباشر.",
  "Python virtual fabric + local sockets": "نسيج Python افتراضي + مقابس محلية",
  "Integrated virtual devices": "أجهزة افتراضية مدمجة",
  "Integrated devices + gateway": "أجهزة مدمجة + بوابة",
  "Integrated local cyber lab": "مختبر سيبراني محلي مدمج",
  "Integrated lab": "المختبر المدمج",
  "No VM / WSL / Docker": "بدون VM / WSL / Docker",
  "Local Only": "محلي فقط",
  "Checking integrated lab backend...": "جارٍ فحص محرك المختبر المدمج...",
  "Checking cyber range...": "جارٍ فحص المختبر السيبراني...",
  "Checking lab runtime": "جارٍ فحص بيئة تشغيل المختبر",
  "Backend configuration": "إعدادات المحرك الخلفي",
  "Backend not ready": "المحرك الخلفي غير جاهز",
  "Integrated lab ready • no VM / WSL / Docker required": "المختبر المدمج جاهز • لا يحتاج VM أو WSL أو Docker",
  "No packet yet": "لا توجد حزمة بعد",
  "Last Packet": "آخر حزمة",
  "Last packet": "آخر حزمة",
  "0 packets captured": "تم التقاط 0 حزمة",
  "Observed bytes": "البايتات المرصودة",
  "Captured packet metadata": "بيانات وصفية للحزم الملتقطة",
  "Source → destination records update automatically from the isolated lab.": "تتحدث سجلات المصدر ← الوجهة تلقائيًا من المختبر المعزول.",
  "Flow records are generated from the integrated training network and its real local TCP/HTTP/UDP service I/O, then correlated with the logical NESS topology.": "يتم إنشاء سجلات التدفقات من شبكة التدريب المدمجة ومن اتصالات خدمات TCP/HTTP/UDP المحلية الحقيقية، ثم ربطها بمخطط NESS المنطقي.",
  "WebSocket stream generated from integrated lab traffic and service events": "تدفق WebSocket مولد من حركة المختبر المدمج وأحداث الخدمات",
  "Real routed cyber-range traffic": "حركة موجّهة حقيقية داخل المختبر السيبراني",
  "Native WebSocket push": "دفع WebSocket أصلي",
  "Open Live Traffic": "فتح الحركة المباشرة",
  "Open Topology": "فتح مخطط الشبكة",
  "View Devices": "عرض الأجهزة",
  "Automatic AI Pipeline": "مسار الذكاء الاصطناعي التلقائي",
  "Real-Time Automatic AI Analysis": "تحليل الذكاء الاصطناعي التلقائي بالوقت الحقيقي",
  "NESS analyzes incidents automatically as they are detected.": "يحلل NESS الحوادث تلقائيًا فور اكتشافها.",
  "NESS is monitoring automatically in real time. New incidents will be classified, analyzed, scored, and predicted without manual action.": "يراقب NESS تلقائيًا في الوقت الحقيقي. سيتم تصنيف الحوادث الجديدة وتحليلها وحساب مخاطرها والتنبؤ بها دون تدخل يدوي.",
  "Open Live AI Console": "فتح وحدة الذكاء الاصطناعي المباشرة",
  "Saved Analyses": "التحليلات المحفوظة",
  "Loading the live AI console…": "جارٍ تحميل وحدة الذكاء الاصطناعي المباشرة…",
  "No saved analysis loaded yet.": "لم يتم تحميل أي تحليل محفوظ بعد.",
  "Security Logs & Analysis": "سجلات الأمن والتحليل",
  "System Log Records": "سجلات النظام",
  "Actual audit, security, system, AI and report events": "أحداث التدقيق والأمن والنظام والذكاء الاصطناعي والتقارير الفعلية",
  "Security Log Analysis": "تحليل السجلات الأمنية",
  "Analyze Security Logs": "تحليل السجلات الأمنية",
  "Analyze the actual system_logs records stored by NESS": "تحليل سجلات system_logs الفعلية المحفوظة بواسطة NESS",
  "All levels": "كل المستويات",
  "All protocols": "كل البروتوكولات",
  "Time Window": "النافذة الزمنية",
  "Last 1 hour": "آخر ساعة",
  "Last 6 hours": "آخر 6 ساعات",
  "Last 24 hours": "آخر 24 ساعة",
  "Last 7 days": "آخر 7 أيام",
  "Last 30 days": "آخر 30 يومًا",
  "Search source, destination, classification": "ابحث بالمصدر أو الوجهة أو التصنيف",
  "Search incident, event or notes": "ابحث بالحادث أو الحدث أو الملاحظات",
  "Complete Incident Numbering and Tracking System history from the live database.": "السجل الكامل لنظام ترقيم وتتبع الحوادث من قاعدة البيانات المباشرة.",
  "Tracking Code": "رمز التتبع",
  "Tracking History": "سجل التتبع",
  "Linked detections": "الاكتشافات المرتبطة",
  "Automatic AI classification & prediction": "التصنيف والتنبؤ التلقائي بالذكاء الاصطناعي",
  "Automatic security log analysis": "تحليل السجلات الأمنية تلقائيًا",
  "Inspect all NESS HTTP requests": "فحص جميع طلبات HTTP في NESS",
  "Log Analysis Interval (seconds)": "فاصل تحليل السجلات (بالثواني)",
  "All automatic services are enabled by default": "جميع الخدمات التلقائية مفعلة افتراضيًا",
  "Enable security monitoring engine": "تفعيل محرك المراقبة الأمنية",
  "High request-rate / brute-force threshold": "حد معدل الطلبات المرتفع / القوة الغاشمة",
  "Arduino Connection": "اتصال أردوينو",
  "Test Physical Alarm": "اختبار الإنذار المادي",
  "Connect the programmed board by USB": "صل اللوحة المبرمجة عبر USB",
  "AUTO or COM4": "AUTO أو COM4",
  "Export Package": "تصدير الحزمة",
  "No alerts loaded yet.": "لم يتم تحميل أي تنبيهات بعد.",
  "No incidents available yet": "لا توجد حوادث متاحة بعد",
  "No user selected": "لم يتم تحديد مستخدم",
  "User profile details will load from the database when a user ID is provided.": "سيتم تحميل تفاصيل ملف المستخدم من قاعدة البيانات عند توفير معرف المستخدم.",
  "User updated successfully": "تم تحديث المستخدم بنجاح",
  "Open login page": "فتح صفحة تسجيل الدخول",
  "Redirecting to NESS Login": "جارٍ التحويل إلى تسجيل دخول NESS",
  "NESS | Redirect": "NESS | إعادة توجيه",
  "NESS | Cyber Range Devices": "NESS | أجهزة المختبر السيبراني",
  "NESS | Cyber Range Topology": "NESS | مخطط المختبر السيبراني",
  "NESS | Live Cyber Range Traffic": "NESS | حركة المختبر السيبراني المباشرة",
  "NESS | Generate Report": "NESS | إنشاء تقرير",
  "NESS Platform / Cyber Range / Devices": "منصة NESS / المختبر السيبراني / الأجهزة",
  "NESS Platform / Cyber Range / Live Traffic": "منصة NESS / المختبر السيبراني / الحركة المباشرة",
  "NESS Platform / Operations / Cyber Range": "منصة NESS / العمليات / المختبر السيبراني",
  "NESS Platform / Investigation / INTS": "منصة NESS / التحقيق / INTS",
  "NESS Platform / Investigation / Logs": "منصة NESS / التحقيق / السجلات",
  "Capture Point": "نقطة الالتقاط",
  "Automation Running": "الأتمتة تعمل",
  "Real-Time Automation": "الأتمتة في الوقت الحقيقي",
  "All alerts": "كل التنبيهات",
  "All categories": "كل الفئات",
  "All statuses": "كل الحالات",
  "All severities": "كل مستويات الخطورة",
  "Interface Language": "لغة الواجهة",
  "English": "الإنجليزية",
  "Arabic": "العربية",
  "Language": "اللغة",
  "Save language preference": "حفظ تفضيل اللغة",
  "Language changed": "تم تغيير اللغة",
  "Switch to English": "التبديل إلى الإنجليزية",
  "Switch to Arabic": "التبديل إلى العربية",
  "Open menu": "فتح القائمة",
  "Notifications": "الإشعارات",
  "Lock": "قفل",
  "Notifications opened": "تم فتح الإشعارات",
  "Secure lock screen opened": "تم فتح شاشة القفل الآمنة",
  "Data refreshed from the NESS database": "تم تحديث البيانات من قاعدة بيانات NESS",
  "Session closed": "تم إغلاق الجلسة",
  "Profile saved": "تم حفظ الملف الشخصي",
  "Chart exported": "تم تصدير المخطط",
  "Events": "الأحداث",
  "Now": "الآن",
  "No live incidents": "لا توجد حوادث مباشرة",
  "pkts": "حزم",
  "Incident": "حادث",
  "Investigate": "تحقيق",
  "Review": "مراجعة",
  "Edit": "تعديل",
  "Profile": "الملف الشخصي",
  "Deactivate": "تعطيل",
  "Activate": "تفعيل",
  "Create user accounts": "إنشاء حسابات المستخدمين",
  "Update user information": "تحديث معلومات المستخدم",
  "Assign roles and permissions": "تعيين الأدوار والصلاحيات",
  "Configure system settings": "تهيئة إعدادات النظام",
  "View dashboard": "عرض لوحة التحكم",
  "View real-time alerts": "عرض التنبيهات الفورية",
  "View incident details": "عرض تفاصيل الحوادث",
  "Search and filter incidents": "البحث في الحوادث وتصفيتها",
  "Review digital evidence": "مراجعة الأدلة الرقمية",
  "Update incident status": "تحديث حالة الحادث",
  "Generate PDF reports": "إنشاء تقارير PDF",
  "View automatic AI analysis": "عرض تحليل الذكاء الاصطناعي التلقائي",
  "Analyze security logs": "تحليل السجلات الأمنية",
  "Track incidents by INTS": "تتبع الحوادث باستخدام INTS",
  "SQL Injection": "حقن SQL",
  "Reflected XSS": "XSS منعكس",
  "Directory Traversal": "اجتياز المسار",
  "Port Scan": "فحص المنافذ",
  "Authentication Burst": "دفعة محاولات المصادقة",
  "ICMP Burst": "دفعة ICMP",
  "Host Sweep": "استكشاف المضيفين",
  "Normal HTTP": "HTTP طبيعي",
  "Send Message": "إرسال رسالة",
  "Client → Web Ping": "اختبار اتصال العميل ← خادم الويب",
  "Started": "بدأ",
  "Completed": "مكتمل",
  "Failed": "فشل",
  "Threat": "تهديد",
  "Detected": "تم الاكتشاف",
  "Classification": "التصنيف",
  "Risk": "المخاطر",
  "Prediction": "التنبؤ",
  "Confidence": "الثقة",
  "Model": "النموذج",
  "Source": "المصدر",
  "Destination": "الوجهة",
  "Protocol": "البروتوكول",
  "Packets": "الحزم",
  "Bytes": "البايتات",
  "Risk Score": "درجة المخاطر",
  "Predicted Severity": "الخطورة المتوقعة",
  "Threat Probability": "احتمال التهديد",
  "Automatic AI Analysis": "تحليل الذكاء الاصطناعي التلقائي",
  "Generated automatically by the real-time engine": "تم إنشاؤه تلقائيًا بواسطة محرك الوقت الحقيقي",
  "Risk / Predicted Priority": "المخاطر / الأولوية المتوقعة",
  "Analysis saved in the database": "تم حفظ التحليل في قاعدة البيانات",
  "Settings saved in database": "تم حفظ الإعدادات في قاعدة البيانات",
  "Lab scenario completed": "اكتمل سيناريو المختبر",
  "Running cyber range...": "جارٍ تشغيل المختبر السيبراني...",
  "Start cyber range...": "جارٍ تشغيل المختبر السيبراني...",
  "Stop cyber range...": "جارٍ إيقاف المختبر السيبراني...",
  "Reset cyber range...": "جارٍ إعادة ضبط المختبر السيبراني..."
};
  Object.assign(AR, AR_EXTRA);
  Object.assign(AR, {
    "Creation, alerts, assignments, status changes, evidence, AI analysis, reports and review events": "أحداث الإنشاء والتنبيهات والإسناد وتغييرات الحالة والأدلة وتحليل الذكاء الاصطناعي والتقارير والمراجعة",
    "Green links are active. Packet pulses come from real local service I/O and logical NESS network events.": "الروابط الخضراء نشطة، وتظهر نبضات الحزم من اتصالات الخدمات المحلية الحقيقية وأحداث شبكة NESS المنطقية.",
    "Live Transport": "النقل المباشر",
    "NESS Gateway": "بوابة NESS",
    "Stored routed flows": "التدفقات الموجّهة المحفوظة"
  });

  Object.assign(AR, {
    "Initial Administrator Setup": "إعداد مدير النظام الأول",
    "Create the first Administrator account. No sample credentials are shipped with the project.": "أنشئ حساب مدير النظام الأول. لا توجد بيانات دخول تجريبية مرفقة مع المشروع.",
    "Create Administrator": "إنشاء مدير النظام",
    "Initial Administrator created": "تم إنشاء مدير النظام الأول",
    "Two-factor verification required": "مطلوب التحقق بخطوتين",
    "Logged in successfully": "تم تسجيل الدخول بنجاح",
    "Reset token generated for this local deployment": "تم إنشاء رمز إعادة تعيين لهذا التشغيل المحلي",
    "If the account exists, reset instructions were generated": "إذا كان الحساب موجودًا فقد تم إنشاء تعليمات إعادة التعيين",
    "Passwords do not match": "كلمتا المرور غير متطابقتين",
    "Password reset successfully": "تمت إعادة تعيين كلمة المرور بنجاح",
    "Verification completed": "اكتمل التحقق",
    "Session unlocked": "تم إلغاء قفل الجلسة",
    "Password updated in the database": "تم تحديث كلمة المرور في قاعدة البيانات",
    "Authentication required": "مطلوب تسجيل الدخول",
    "Access denied": "تم رفض الوصول",
    "Invalid server response": "استجابة الخادم غير صالحة",
    "No database records are available for this page yet.": "لا توجد سجلات في قاعدة البيانات لهذه الصفحة حتى الآن.",
    "No alerts recorded yet.": "لا توجد تنبيهات مسجلة حتى الآن.",
    "Security Alert": "تنبيه أمني",
    "Automatic AI analysis is queued and will appear here as soon as the real-time engine finishes classification and prediction.": "تمت جدولة التحليل التلقائي بالذكاء الاصطناعي وسيظهر هنا فور انتهاء محرك الوقت الحقيقي من التصنيف والتنبؤ.",
    "No INTS events recorded.": "لا توجد أحداث INTS مسجلة.",
    "Open Full INTS": "فتح سجل INTS الكامل",
    "No assigned incidents.": "لا توجد حوادث مسندة.",
    "No AI analysis has been generated for this incident.": "لم يتم إنشاء تحليل ذكاء اصطناعي لهذا الحادث.",
    "No history records.": "لا توجد سجلات تاريخية.",
    "Include digital evidence": "تضمين الأدلة الرقمية",
    "Include AI analysis": "تضمين تحليل الذكاء الاصطناعي",
    "Include status timeline": "تضمين الخط الزمني للحالة",
    "Generate PDF Report": "إنشاء تقرير PDF",
    "Copy Hash": "نسخ البصمة",
    "Hash copied": "تم نسخ البصمة",
    "Live feed paused": "تم إيقاف البث المباشر مؤقتًا",
    "Live feed resumed": "تم استئناف البث المباشر",
    "Connection error": "خطأ في الاتصال",
    "Status unavailable": "الحالة غير متاحة",
    "Telegram delivery configured": "تم إعداد إرسال تيليجرام",
    "Configure Bot Token and Chat ID in Settings": "قم بإعداد رمز البوت ومعرف المحادثة من الإعدادات",
    "Cyber range data refreshed": "تم تحديث بيانات المختبر السيبراني",
    "Security log analysis saved": "تم حفظ تحليل السجلات الأمنية",
    "Analyzing database logs...": "جارٍ تحليل سجلات قاعدة البيانات...",
    "Analysis failed": "فشل التحليل",
    "Analysis ID": "معرف التحليل",
    "Logs Analyzed": "السجلات المحللة",
    "Findings": "النتائج",
    "No saved analyses yet.": "لا توجد تحليلات محفوظة حتى الآن.",
    "No INTS records found.": "لم يتم العثور على سجلات INTS.",
    "Profile updated": "تم تحديث الملف الشخصي",
    "User updated": "تم تحديث المستخدم",
    "Unavailable": "غير متاح",
    "Alarm triggered": "تم تشغيل الإنذار",
    "Integrated Virtual Fabric": "نسيج افتراضي مدمج",
    "10.10.x.x segmented lab": "مختبر مقسم 10.10.x.x",
    "Network node": "عقدة شبكة",
    "THREAT": "تهديد",
    "SCENARIO": "سيناريو",
    "Automatic AI completed": "اكتمل تحليل الذكاء الاصطناعي التلقائي",
    "NESS analyzed": "حلّل NESS",
    "automatically in real time": "تلقائيًا في الوقت الحقيقي",
    "risk": "المخاطر",
    "predicted priority": "الأولوية المتوقعة",
    "was detected automatically and has been queued for real-time AI classification and prediction.": "تم اكتشافه تلقائيًا وإدراجه للتصنيف والتنبؤ بالذكاء الاصطناعي في الوقت الحقيقي.",
    "NESS is monitoring automatically in real time. New suspicious activity will be detected, classified, analyzed, scored, predicted, stored, and displayed without manual analysis.": "يراقب NESS تلقائيًا في الوقت الحقيقي. سيتم اكتشاف الأنشطة المشبوهة الجديدة وتصنيفها وتحليلها وحساب مخاطرها والتنبؤ بها وحفظها وعرضها دون تحليل يدوي.",
    "Arduino:": "أردوينو:",
    "Risk": "المخاطر",
    "logs": "سجلات",
    "packets": "حزم",
    "No packet yet": "لا توجد حزمة بعد",
    "Backend not ready": "المحرك الخلفي غير جاهز"
  });

  const SKIP_SELECTOR = 'script,style,code,pre,.log-viewer,.code-block,[data-i18n-skip]';
  const ATTRS = ['placeholder','aria-label','title','data-toast'];
  const html = document.documentElement;
  const textState = new WeakMap();
  const attrState = new WeakMap();
  const titleState = { source: document.title || '', rendered: document.title || '' };
  let observer = null;
  let applying = false;
  let queueScheduled = false;
  const pendingRoots = new Set();

  const normalize = value => String(value ?? '').replace(/\s+/g,' ').trim();
  const PHRASE_KEYS = Object.keys(AR)
    .filter(k => k.length > 2 && /[A-Za-z]/.test(k))
    .sort((a,b)=>b.length-a.length);
  const PHRASE_PATTERNS = PHRASE_KEYS.map(key => [
    key,
    new RegExp(`(^|[^A-Za-z0-9_])(${key.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')})(?=$|[^A-Za-z0-9_])`, 'g')
  ]);

  function readStoredLanguage(){
    try{
      const value = localStorage.getItem(STORAGE_KEY);
      return value === 'ar' || value === 'en' ? value : DEFAULT_LANG;
    }catch(_){ return DEFAULT_LANG; }
  }
  function writeStoredLanguage(value){
    try{ localStorage.setItem(STORAGE_KEY, value); }catch(_){}
  }
  function lang(){ return readStoredLanguage(); }
  function isArabic(){ return lang() === 'ar'; }
  function preserveSpace(original, translated){
    const raw = String(original ?? '');
    const lead = raw.match(/^\s*/)?.[0] || '';
    const trail = raw.match(/\s*$/)?.[0] || '';
    return lead + translated + trail;
  }
  function splitTranslate(s, sep){
    if(!s.includes(sep)) return null;
    const parts = s.split(sep);
    if(parts.length < 2) return null;
    const converted = parts.map(part => t(part.trim(), true));
    const glue = sep === '/' ? ' / ' : sep === ':' ? ': ' : ` ${sep} `;
    return converted.join(glue);
  }
  function patternTranslate(s){
    let m;
    if((m=s.match(/^NESS Platform\s*\/\s*(.+)$/))) return 'منصة NESS / ' + m[1].split('/').map(x=>t(x.trim(), true)).join(' / ');
    if((m=s.match(/^NESS\s*\|\s*(.+)$/))) return 'NESS | ' + t(m[1].trim(), true);
    if((m=s.match(/^Last delivery:\s*(.+)$/))) return 'آخر تسليم: ' + m[1];
    if((m=s.match(/^Last packet:\s*(.+)$/))) return 'آخر حزمة: ' + m[1];
    if((m=s.match(/^Report ID:\s*(.+?)\s*•\s*Prepared:\s*(.+)$/))) return `معرّف التقرير: ${m[1]} • تم الإعداد: ${m[2]}`;
    if((m=s.match(/^Linked to\s+(.+)$/))) return 'مرتبط بـ ' + m[1];
    if((m=s.match(/^Latest incident\s+(.+?)\s+was classified as\s+(.+?)\s+from\s+(.+?)\. Open AI Analysis to generate recommendations\.$/))) return `آخر حادث ${m[1]} تم تصنيفه كـ ${m[2]} من ${m[3]}. افتح تحليل الذكاء الاصطناعي لإنشاء التوصيات.`;
    if((m=s.match(/^User\s+(.+)$/))) return 'المستخدم ' + t(m[1], true);
    if((m=s.match(/^Status changed to\s+(.+)\s+from console$/))) return 'تم تغيير الحالة إلى ' + t(m[1], true) + ' من لوحة التحكم';
    if((m=s.match(/^Request failed:\s*(\d+)$/))) return 'فشل الطلب: ' + m[1];
    if((m=s.match(/^No\s+(.+)\s+records\.$/))) return 'لا توجد سجلات ' + t(m[1], true) + '.';
    if((m=s.match(/^(\d+)\s+packets?\s*•\s*(.+)$/))) return `${m[1]} حزمة • ${m[2]}`;
    if((m=s.match(/^(\d+)\s+pkts$/))) return `${m[1]} حزمة`;
    if((m=s.match(/^Running\s+(.+)\s+inside the integrated local lab\.\.\.$/))) return `جارٍ تشغيل ${m[1]} داخل المختبر المحلي المدمج...`;
    if((m=s.match(/^Scenario:\s*(.+)$/))) return 'السيناريو: ' + m[1];
    if((m=s.match(/^Result:\s*(.+)$/))) return 'النتيجة: ' + m[1];
    if((m=s.match(/^Cyber range:\s*(.+)$/))) return 'المختبر السيبراني: ' + t(m[1], true);
    if((m=s.match(/^Incident\s+(.+)$/))) return 'الحادث ' + m[1];
    return null;
  }
  function phraseReplace(s){
    if(!/[A-Za-z]/.test(s)) return null;
    let out = s;
    for(const [key, rx] of PHRASE_PATTERNS){
      if(!out.includes(key)) continue;
      out = out.replace(rx, (match, before, phrase) => `${before}${AR[phrase] || phrase}`);
    }
    return out !== s ? out : null;
  }
  function t(value, internal=false){
    const raw = String(value ?? '');
    const s = normalize(raw);
    if(!s || lang() !== 'ar') return raw;
    let translated = AR[s] || patternTranslate(s);
    if(!translated) translated = splitTranslate(s, '•') || splitTranslate(s, '—') || splitTranslate(s, '/');
    if(!translated && s.includes(':') && !/^[A-Za-z]+:\/\/|^[A-Fa-f0-9:]+$/.test(s)) translated = splitTranslate(s, ':');
    if(!translated) translated = phraseReplace(s);
    return translated ? (internal ? translated : preserveSpace(raw, translated)) : raw;
  }
  function matches(displayed, englishKey){
    const d = normalize(displayed);
    const k = normalize(englishKey);
    return d === k || d === AR[k] || d.includes(k) || (!!AR[k] && d.includes(AR[k]));
  }
  function parentSkippable(node){
    if(!node) return true;
    const el = node.nodeType === 1 ? node : node.parentElement;
    return !!el?.closest?.(SKIP_SELECTOR);
  }
  function translateTextNode(node){
    if(!node || node.nodeType !== Node.TEXT_NODE || parentSkippable(node)) return;
    const current = node.nodeValue ?? '';
    let state = textState.get(node);
    if(!state){
      state = {source: current, rendered: current};
      textState.set(node, state);
    }else if(current !== state.rendered){
      // The application changed this text node; treat the new value as the English source.
      state.source = current;
      state.rendered = current;
    }
    const desired = isArabic() ? t(state.source) : state.source;
    if(current !== desired){
      state.rendered = desired;
      node.nodeValue = desired;
    }else{
      state.rendered = current;
    }
  }
  function translateAttribute(el, attr){
    if(!el?.hasAttribute?.(attr) || parentSkippable(el)) return;
    let perEl = attrState.get(el);
    if(!perEl){ perEl = new Map(); attrState.set(el, perEl); }
    const current = el.getAttribute(attr) ?? '';
    let state = perEl.get(attr);
    if(!state){
      state = {source: current, rendered: current};
      perEl.set(attr, state);
    }else if(current !== state.rendered){
      state.source = current;
      state.rendered = current;
    }
    const desired = isArabic() ? t(state.source) : state.source;
    if(current !== desired){
      state.rendered = desired;
      el.setAttribute(attr, desired);
    }else{
      state.rendered = current;
    }
  }
  function translateAttributes(el){
    if(!el || parentSkippable(el)) return;
    for(const attr of ATTRS) translateAttribute(el, attr);
  }
  function walk(root){
    if(!root || parentSkippable(root)) return;
    if(root.nodeType === Node.TEXT_NODE){ translateTextNode(root); return; }
    if(root.nodeType !== Node.ELEMENT_NODE && root.nodeType !== Node.DOCUMENT_FRAGMENT_NODE) return;
    if(root.nodeType === Node.ELEMENT_NODE) translateAttributes(root);
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT, {
      acceptNode(node){ return parentSkippable(node) ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT; }
    });
    let node;
    while((node = walker.nextNode())){
      if(node.nodeType === Node.TEXT_NODE) translateTextNode(node);
      else if(node.nodeType === Node.ELEMENT_NODE) translateAttributes(node);
    }
  }
  function setDirection(){
    const ar = isArabic();
    html.lang = ar ? 'ar' : 'en';
    html.dir = ar ? 'rtl' : 'ltr';
    document.body?.classList.toggle('rtl', ar);
    const current = document.title || '';
    if(current !== titleState.rendered){
      titleState.source = current;
      titleState.rendered = current;
    }
    const desired = ar ? t(titleState.source, true) : titleState.source;
    if(document.title !== desired){
      titleState.rendered = desired;
      document.title = desired;
    }
  }
  function controlMarkup(){
    return `<div class="ness-language-switch" data-i18n-skip role="group" aria-label="Interface Language">
      <button type="button" data-ness-lang="en" aria-label="Switch to English">EN</button>
      <button type="button" data-ness-lang="ar" aria-label="Switch to Arabic">AR</button>
    </div>`;
  }
  function injectSwitcher(){
    if(document.querySelector('.ness-language-switch')) return;
    const target = document.querySelector('.topbar-actions') || document.querySelector('.auth-panel') || document.body;
    if(!target) return;
    target.insertAdjacentHTML('afterbegin', controlMarkup());
  }
  function syncSwitchers(){
    document.querySelectorAll('[data-ness-lang]').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.nessLang === lang());
      btn.setAttribute('aria-pressed', btn.dataset.nessLang === lang() ? 'true' : 'false');
    });
    document.querySelectorAll('[data-language-select]').forEach(select => {
      if(select.value !== lang()) select.value = lang();
    });
    // Backward-compatible support for old profile/settings language selectors.
    document.querySelectorAll('select:not([data-language-select])').forEach(select => {
      const label = select.closest('.field')?.querySelector('label')?.textContent || '';
      if(!matches(label, 'Interface Language')) return;
      const wanted = isArabic() ? ['ar','Arabic','العربية'] : ['en','English','الإنجليزية'];
      const option = [...select.options].find(opt => wanted.includes(opt.value) || wanted.includes(normalize(opt.textContent)));
      if(option && select.value !== option.value) select.value = option.value;
    });
  }
  function bindSwitchers(){
    document.querySelectorAll('[data-ness-lang]').forEach(btn => {
      if(btn.dataset.boundLang) return;
      btn.dataset.boundLang = '1';
      btn.addEventListener('click', () => setLanguage(btn.dataset.nessLang));
    });
    document.querySelectorAll('[data-language-select]').forEach(select => {
      if(select.dataset.boundLangSelect) return;
      select.dataset.boundLangSelect = '1';
      select.addEventListener('change', () => setLanguage(select.value === 'ar' ? 'ar' : 'en'));
    });
    document.querySelectorAll('select:not([data-language-select])').forEach(select => {
      const label = select.closest('.field')?.querySelector('label')?.textContent || '';
      if(!matches(label, 'Interface Language') || select.dataset.boundLangSelect) return;
      select.dataset.boundLangSelect = '1';
      select.addEventListener('change', () => {
        const v = normalize(select.value || select.selectedOptions?.[0]?.textContent);
        setLanguage(v === 'ar' || v === 'Arabic' || v === 'العربية' ? 'ar' : 'en');
      });
    });
  }
  function apply(root=document.body){
    if(!root || applying) return;
    applying = true;
    try{
      setDirection();
      if(root === document.body) injectSwitcher();
      walk(root);
      if(root === document.body){
        bindSwitchers();
        syncSwitchers();
      }
    }finally{
      applying = false;
    }
  }
  function schedule(root=document.body){
    if(!root) return;
    pendingRoots.add(root.nodeType === Node.TEXT_NODE ? root : root);
    if(queueScheduled) return;
    queueScheduled = true;
    const runner = () => {
      queueScheduled = false;
      const roots = [...pendingRoots];
      pendingRoots.clear();
      for(const item of roots) apply(item);
      if(document.body){ bindSwitchers(); syncSwitchers(); }
    };
    if(typeof requestAnimationFrame === 'function') requestAnimationFrame(runner);
    else setTimeout(runner, 0);
  }
  function setLanguage(next){
    const normalized = next === 'ar' ? 'ar' : 'en';
    const previous = lang();
    writeStoredLanguage(normalized);
    apply(document.body);
    if(previous !== normalized){
      window.dispatchEvent(new CustomEvent('ness:languageChanged', {detail:{language:normalized, direction:normalized === 'ar' ? 'rtl' : 'ltr'}}));
    }
  }
  function observe(){
    if(observer || !document.body) return;
    observer = new MutationObserver(mutations => {
      for(const mutation of mutations){
        if(mutation.type === 'childList'){
          mutation.addedNodes.forEach(node => {
            if(node.nodeType === Node.TEXT_NODE || node.nodeType === Node.ELEMENT_NODE) schedule(node);
          });
        }else if(mutation.type === 'characterData'){
          const node = mutation.target;
          const state = textState.get(node);
          const current = node.nodeValue ?? '';
          if(state && current === state.rendered) continue; // our own translation write
          if(state){ state.source = current; state.rendered = current; }
          schedule(node);
        }else if(mutation.type === 'attributes'){
          const el = mutation.target;
          const attr = mutation.attributeName;
          const perEl = attrState.get(el);
          const state = perEl?.get(attr);
          const current = el.getAttribute(attr) ?? '';
          if(state && current === state.rendered) continue; // our own translation write
          if(state){ state.source = current; state.rendered = current; }
          schedule(el);
        }
      }
    });
    observer.observe(document.body, {
      childList:true,
      subtree:true,
      characterData:true,
      attributes:true,
      attributeFilter:ATTRS
    });
  }

  window.NESS_I18N = {
    t,
    apply,
    refresh: schedule,
    setLanguage,
    getLanguage:lang,
    isArabic,
    matches,
    dictionary:AR
  };

  document.addEventListener('DOMContentLoaded', () => {
    apply(document.body);
    observe();
  });
})();
