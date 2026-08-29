# تقرير نشر وقبول الـBackend الهجين على VPS

تاريخ سجل القبول: 2026-08-29
فرع العمل: `newBackend-cloud-integration`
النطاق: External handoff + Internal Sources + PostgreSQL + BERT + Correlation/STIX + MISP + VPS hardening

## النتيجة التنفيذية

اكتملت البنية الهجينة المطلوبة لمشروع التخرج عمليًا:

- جهاز الزميل مسؤول عن External Sources وينشر JSON بإصدار معلوم وصلاحية publish فقط.
- الـVPS يشغّل CTI Gateway وDionaea وSSH journal collector وMISP.
- جهاز Ammar يشغّل FastAPI وPostgreSQL والمعالجة الثقيلة وDNRTI BERT ثم sklearn fallback.
- PostgreSQL هي قاعدة المشروع المركزية، بينما MISP نسخة مشاركة ومراجعة غير منشورة افتراضيًا.
- Wazuh غير منشور عمدًا على الخادم الحالي؛ موصله البرمجي باقٍ ومختبر كخيار مستقبلي.

لا يتضمن هذا التقرير عنوان الخادم، المفاتيح، التوكنات، عناوين المهاجمين، أو السجلات الخام.

## لماذا نستطيع القول إن العمل صحيح؟

التحقق تم على أربع طبقات مستقلة:

1. اختبارات وحدات وتكامل وحالات رفض وعدم تكرار.
2. تحقق حي من الخدمات والمنافذ والأنفاق على الـVPS.
3. تتبع بيانات من المصدر الخام إلى PostgreSQL ثم CTI/BERT/Regex/Correlation/STIX/MISP.
4. قراءة النتيجة مرة أخرى من الوجهة بدل الاكتفاء بنجاح HTTP.

## 1. أدلة الاختبارات الآلية

الأمر:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test*.py" -v
```

النتيجة:

```text
Ran 232 tests in 108.557s
OK
```

كما نجح:

```text
Focused backend/VPS regression: 20 tests passed
Ruff: all selected changed backend/VPS files passed
Python compileall: passed
Root Docker Compose config: valid
VPS Docker Compose config: valid
PowerShell tunnel script syntax: valid
Server bash deployment scripts syntax: valid
git diff --check: passed
```

تغطي الاختبارات HMAC وETag/304 وpagination والحدود والأخطاء، عدم تكرار External/Internal/MISP، sessionization وIsolation Forest، BERT priority، Regex IoCs، privacy/redaction، risk/correlation، STIX، API authentication/roles، وMISP mapping والتحقق بعد الإرسال.

## 2. حالة الـVPS الحية

المواصفات المستخدمة: 6 vCPU، و12 GB RAM، و200 GB SSD، وUbuntu 24.04، مع 4 GB swap.

حالة القبول النهائية:

```text
CTI Gateway: healthy
Dionaea: running
MISP Core 2.5.44: healthy
MISP Modules 3.0.9: healthy
MariaDB: healthy
Valkey/Redis: healthy
SSH collector timer: active
Docker firewall service: active
fail2ban: active
unattended-upgrades: active
Gateway health: dionaea=true, host-auth=true, web-access=true
MISP heartbeat: HTTP 200
```

بعد تشغيل MISP كانت الذاكرة المتاحة قرابة 9.6 GB، والـswap غير مستخدم، والمتبقي على القرص قرابة 182 GB. هذه لقطة قبول وليست ضمانًا لسعة مستقبلية غير محدودة.

## 3. الحماية والعزل

- SSH يعمل بالمفتاح فقط؛ تم تعطيل password وkeyboard-interactive والتحقق من الإعداد الفعلي.
- اكتشفنا أن ملف cloud-init أسبق من ملف hardening القديم، لذلك نقلنا السياسة إلى `00-cti-hardening.conf` وتحققنا باتصال ثانٍ.
- Gateway على `127.0.0.1:8088` وMISP على `127.0.0.1:8080/8443` فقط.
- الاتصال من جهاز Ammar يتم بنفقي SSH محليين، وليس بنشر قواعد البيانات أو MISP للعامة.
- توكن النشر الخاص بالزميل منفصل عن توكنات القراءة وMISP.
- Dionaea لا يملك Docker socket أو مفاتيح MISP/PostgreSQL أو volumes مشتركة.
- Docker networks منفصلة، و`DOCKER-USER` يمنع الاتصالات الصادرة الجديدة من شبكات الحساس والبوابة مع السماح بالردود established.
- مفاتيح `.vps-client.env` و`.vps-publisher.env` و`.misp-client.env` مستبعدة من Git.

العزل الحالي قوي بالنسبة لمختبر محلي محدود التكلفة، لكنه ليس بديلًا عن VPS منفصل للحساس؛ جميع الحاويات ما زالت تشترك في kernel واحد.

## 4. دليل انتقال External Sources

استخدمنا سجلًا اصطناعيًا محكومًا بعنوان:

```text
Controlled CTI pipeline validation record
```

النتيجة:

- Gateway قبله بتوكن publish المنفصل.
- أزال حقل `api_token` التجريبي من metadata.
- Backend تحقق من HMAC والعقد وسجله مرة واحدة.
- BERT استخرج `CVE-2026-1234` كـexploit بثقة تقريبًا `0.9988`، و`Lazarus Group` كـthreat_actor بثقة تقريبًا `0.8774`.
- Regex استخرج CVE وIPv4 التجريبي المحجوز للتوثيق.
- الحدث أصبح CTI موحدًا بحالة `transformed` وRisk Score قابل للتفسير.
- إعادة السحب أعادت `not_modified=true` و0 collected و0 stored.

ظهر أثناء إعادة السحب خطأ 422: كان checkpoint المكتمل يُعاد استخدامه كأنه page cursor. تم الفصل بينهما: ETag لإعادة التحقق بين التشغيلات، و`next_cursor` داخل نفس pagination فقط. أضيف اختبار regression لهذه الحالة.

## 5. دليل Internal Sources

لقطة التشغيل الحي اللاحقة:

| المصدر | Raw collected | Sessions | Outliers promoted | CTI events |
|---|---:|---:|---:|---:|
| Dionaea | 777 | 30 | 3 | 3 |
| SSH auth | 53 | 11 | 1 | 1 |
| Gateway web access | 6 | 2 | 0 | 0 |

الأرقام تثبت أن كل Log لا يصبح تهديدًا. السجلات تُحفظ خامًا، ثم تُجمع Sessions، ثم يُحفظ كل Session، وفقط Outliers تتحول إلى CTI events.

## 6. دليل PostgreSQL

لقطة القاعدة بعد القبول:

```text
raw_items: 931
threat_events: 20
indicators: 40
entities: 62
outlier_sessions: 57
correlations: 9
pipeline_runs: 13
```

التوزيع:

```text
External CTI events: 13
Internal CTI events: 7
Sessions retained: 57
Promoted outliers: 7
Retained non-threat sessions: 50
Controlled external raw rows: 1
Sensitive api_token keys in that raw row: 0
Invalid event time bounds after repair: 0
Invalid indicator time bounds after repair: 0
```

وجود 931 raw مقابل 20 CTI event يثبت الفصل بين المصدر الخام والنتيجة التحليلية وعدم تضخيم كل telemetry إلى threat intelligence.

يوجد حدث `wazuh_session` تاريخي من بيانات اختبار سابقة؛ لا يعني وجود Wazuh Server حي.

## 7. دليل BERT وML

`/api/v1/ml/status` أعاد:

```text
runtime backend: transformer
primary_model_loaded: true
primary: dnrti_bert_ner
secondary: dnrti_sklearn_ner
BERT held-out F1: 0.781165733250363
BERT held-out accuracy: 0.9376270038383382
sklearn secondary held-out entity F1: 0.6379024228343844
all_quality_gates_passed: true
```

هذه المقاييس من تقارير DNRTI test المحفوظة وليست ادعاء دقة production live. النظام يعرض backend المحمل فعليًا، ولا يخلط جودة test مع نتائج التشغيل.

## 8. Correlation وSTIX

تشغيل Correlation أعاد:

```text
simple correlations: 7
similarity correlations: 2
total: 9
risk recalculated events: 20
```

تصدير الحدث الاصطناعي أنشأ STIX Bundle من 4 objects تشمل:

```text
identity
indicator
report
vulnerability
```

## 9. MISP live acceptance

تم تنزيل وبناء الصور على الـVPS مباشرة. النسخ المثبتة والمثبتة بالـpin:

```text
MISP Docker commit: 223b675c4480730832f928e113b6f2e5260b450d
MISP Core: v2.5.44-slim
MISP Modules: v3.0.9-slim
```

اختبار الإرسال النهائي:

```text
event created: true
attributes requested: 2
attributes added: 2
attributes verified after read-back: 2
types: vulnerability, ip-src
published: false
```

ثم كررنا الإرسال:

```text
event created: false
attributes added: 0
attributes verified: 2
published: false
```

أثناء القبول اكتشفنا أن `first_seen` كان بعد `last_seen` في السجل الاصطناعي بسبب فرق التوقيت. MISP رفض المؤشرات رغم نجاح إنشاء Event. أصلحنا الترتيب في central persistence وMISP mapping، وأصبح العميل يضيف كل مؤشر ثم يقرأ الحدث مرة أخرى ويفشل إذا نقص أي مؤشر. هذا أقوى من الاعتماد على HTTP 200 وحده.

تم حذف Event التشخيصي غير المنشور الذي احتوى 4 مؤشرات تجريبية، وإزالة blocklist الخاصة بمعرفه، ثم إنشاء Event القبول النهائي النظيف بمؤشرين. لم تُحذف بيانات حقيقية أو منشورة.

## 10. إعادة التحقق بعد تغيير الشبكة

بتاريخ 2026-08-29 فُحص الوصول بعد أن ظهرت في Chrome رسالة `ERR_NETWORK_CHANGED` ثم `ERR_CONNECTION_TIMED_OUT` عند فتح:

```text
https://<VPS_IP>/api/v1/integrations/status
```

هذا ليس عنوان الـBackend في المعمارية الحالية. الـVPS لا ينشر FastAPI المركزي أو Gateway/MISP على المنفذ العام 80/443. FastAPI يعمل محليًا على جهاز Ammar في `http://127.0.0.1:8000`، وGateway/MISP يصل إليهما عبر SSH tunnels فقط. كما أن `/api/v1/integrations/status` محمي ويتطلب JWT Bearer؛ لا يُختبر من شريط العنوان دون مصادقة. العنوان الصحيح للعرض والتجربة هو:

```text
http://127.0.0.1:8000/docs
```

نتيجة إعادة الفحص الحية:

- PostgreSQL: healthy، و`/api/v1/health` أعاد `status=ok` و`database=true`.
- External Feed وDionaea وSSH host-auth وGateway web-access: `configured=true` و`reachable=true` مع تحقق العقد وHMAC.
- MISP: `reachable=true` وأعاد الإصدار `2.5.44`.
- Wazuh: بقي `deferred_not_deployed` كما هو موثق، وليس فشلًا في الخدمة الحالية.
- DNRTI BERT: الـruntime الفعلي `transformer`، والنموذج الأساسي محمّل، وكل quality gates المسجلة نجحت. بلغ held-out F1 للنموذج الأساسي `0.7812` مقابل `0.6379` للنموذج الاحتياطي، مع التنبيه أن هذه مقاييس dataset اختبار محفوظ وليست دقة production حية.

أثناء الفحص علقت طلبات `/ml/status` اللاحقة لأن عملية Uvicorn داخل Docker دخلت حالة `zombie`، مع بقاء health العام مستجيبًا. رفض Docker إعادة تشغيل الحاوية منفردة، لذلك أُعيد تشغيل Docker Desktop ثم شُغلت حاويتا `db` و`backend` من جديد. بقيت بيانات PostgreSQL وملفات الرفع محفوظة في named volumes. بعد الاستعادة نجح `/ml/status` خلال نحو 21 ثانية في أول تحميل لـBERT. إذا تكررت الحالة بعد sleep أو network change، تكون خطوات الاستعادة:

```powershell
docker desktop restart
docker compose --env-file .env --env-file .vps-client.env --env-file .misp-client.env up -d db backend
```

ثم يُعاد تشغيل نفق SSH إذا اختفت المنافذ المحلية `18088` و`18443`، ويُتحقق من `/api/v1/health` قبل أي pull أو MISP send.

## 11. ما لا ندعي أنه مكتمل

- Wazuh Manager/Indexer/Dashboard غير منشور عمدًا.
- Dionaea على نفس kernel الخاص بالـVPS؛ VPS مستقل للحساس أفضل مستقبلًا.
- لا يوجد DNS/TLS production أو WireGuard/mTLS حاليًا؛ الإدارة الخاصة تستخدم SSH tunnels.
- لا يوجد off-host restore test بعد.
- Dark Web collector غير مختبر على Onion حي.
- Risk Score rule-based explainable وليس AI model مدربًا.
- Relationship extraction rule-based prototype.
- المعالجة synchronous؛ Celery/Kafka مؤجلان.
- MongoDB غير مستخدمة لأن PostgreSQL + JSON تفي بالغرض الحالي.
- لا يوجد ادعاء enterprise SOC أو high availability.

## جواب جاهز للمناقش

> تأكدنا من صحة العمل باختبارات آلية شاملة عددها 232 تشمل حالات الرفض وعدم التكرار، ثم باختبار حي من External/Dionaea/SSH/Web إلى PostgreSQL وBERT وRegex وCorrelation وSTIX، وبعدها أرسلنا Event غير منشور إلى MISP وقرأناه مرة أخرى وتحققنا من كل مؤشر. قاعدة القبول احتفظت بـ931 سجلًا خامًا لكنها أنشأت 20 CTI Event فقط، واحتفظت بـ57 Session ورقّت 7 Outliers فقط؛ لذلك لا نتعامل مع كل Log كتهديد. كما نوثق ما لم ننفذه، مثل Wazuh وHA والـbackup restore، ولا نساوي بين كود connector وبين خدمة حية.

## الملفات المرجعية

- `docs/architecture/cloud_distributed_architecture.md`
- `docs/architecture/future_bound_work.md`
- `docs/operations/vps_deployment_plan.md`
- `docs/operations/external_collaborator_handoff.md`
- `docs/api/external_feed_contract.md`
- `docs/api/internal_sensor_contract.md`
- `infra/vps/README.md`
