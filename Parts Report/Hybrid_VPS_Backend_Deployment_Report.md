# تقرير قبول الـBackend الهجين: جهاز Ammar + VPS

تاريخ القبول: 2026-08-30
فرع العمل: `newBackend-cloud-integration`
النطاق: External Sources، Internal Sources، PostgreSQL، DNRTI BERT، CTI APIs، STIX، MISP، وأمن وتشغيل الـVPS

## النتيجة التنفيذية

اكتمل Backend مشروع التخرج ضمن المعمارية ذات العقدتين المتفق عليها:

- الـVPS يشغّل External Sources وCTI Gateway وDionaea وحساسات SSH/Web وMISP بصورة مستمرة.
- جهاز Ammar يشغّل FastAPI وPostgreSQL والمعالجة الثقيلة؛ `dnrti_bert_ner` هو النموذج الأساسي و`dnrti_sklearn_ner` هو البديل الثانوي.
- لا يعتمد التشغيل على جهاز زميل أو صديق.
- PostgreSQL هي قاعدة المشروع المركزية. MISP نسخة مشاركة ومراجعة غير منشورة افتراضيًا، وليست بديلًا عن PostgreSQL.
- Wazuh Manager/Indexer/Dashboard غير منشور عمدًا على خادم 12 GB؛ موصل Wazuh موجود ومختبر، لكنه لا يُقدَّم كخدمة حية.
- كل واجهات الـBackend المطلوبة للـFrontend موجودة خلف JWT في FastAPI/Swagger.

لا يحتوي هذا التقرير على عنوان الخادم أو مفاتيح SSH أو كلمات مرور أو Tokens أو عناوين مهاجمين حقيقية.

## المعمارية المقبولة

```text
Internet
  -> VPS External Sources
     -> validated run JSON
     -> cumulative CTI Gateway snapshot
  -> VPS Dionaea / SSH journal / Gateway web telemetry
     -> signed sensor JSON APIs

VPS loopback services
  -> SSH tunnels
  -> Ammar FastAPI
     -> PostgreSQL raw_items
     -> classification
     -> DNRTI BERT + Regex IoCs + rule-based relationships
     -> threat_events / indicators / entities / sessions
     -> STIX / MISP / Frontend APIs
```

الخدمات الخاصة على الـVPS مربوطة بـloopback فقط:

| الخدمة | VPS loopback | المنفذ المحلي عبر SSH |
|---|---|---|
| Gateway feed/sensors | `127.0.0.1:8088` | `127.0.0.1:18088` |
| External control API | `127.0.0.1:8090` | `127.0.0.1:18090` |
| MISP HTTPS | `127.0.0.1:8443` | `127.0.0.1:18443` |

PostgreSQL وGateway وExternal Control وMISP وDocker API ليست منافذ عامة.

## لماذا نستطيع القول إن العمل صحيح؟

القبول لا يعتمد على نجاح HTTP فقط، بل على خمس طبقات:

1. اختبارات وحدات وتكامل وحالات رفض وعدم تكرار.
2. صحة الخدمات الحية والأنفاق والحدود الشبكية.
3. انتقال حقيقي للبيانات من VPS إلى PostgreSQL.
4. قراءة النتائج النهائية من PostgreSQL وMISP بدل الاكتفاء بطلب الإرسال.
5. توثيق صريح لما لم يُنفذ أو لم يُختبر حيًا.

## 1. الاختبارات الآلية النهائية

الأمر:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -v
```

النتيجة:

```text
Ran 241 tests in 107.793s
OK
```

كما نجحت:

```text
Python compileall: passed
Local Docker Compose config: valid
VPS Docker Compose config: valid
PowerShell tunnel script syntax: valid
Ruff: all selected changed Python files passed
git diff --check: passed
```

تغطي الاختبارات العقود وHMAC وGZip وETag/304 وpagination والحدود، cumulative snapshot، الحفظ الذري، عدم التكرار قبل BERT، External collectors، SSRF/privacy، Internal sessionization، Isolation Forest، BERT priority، Regex IoCs، MISP mapping/read-back، STIX parsing، JWT/roles/audit، Risk Score، ورفض الدفعات غير الصحيحة قبل persistence.

## 2. حالة الـVPS الحية

المواصفات: 6 vCPU، 12 GB RAM، 200 GB SSD، Ubuntu 24.04، و4 GB swap.

لقطة القبول:

```text
CTI Gateway: healthy
External Sources: healthy
Dionaea: running
MISP Core 2.5.44: healthy
MISP Modules 3.0.9: healthy
MariaDB: healthy
Valkey/Redis: healthy
External collection timer: active
SSH collector timer: active
Storage maintenance timer: active
Docker firewall service: active
Gateway health: HTTP 200
External health: HTTP 200
MISP heartbeat: HTTP 200
```

نسخ MISP المثبتة:

```text
MISP Docker commit: 223b675c4480730832f928e113b6f2e5260b450d
MISP Core: v2.5.44-slim
MISP Modules: v3.0.9-slim
```

## 3. External Sources الحية

واجهة الإدارة المركزية أعادت:

```text
registered sources: 21
enabled: 17
disabled: 4
types: RSS, CERT, vulnerability, Hacker News, Reddit, Telegram
```

أول دورة شاملة على الـVPS انتهت `partial` مع عزل فشل المصادر:

```text
accepted source observations: 1,985
run export after External-only deduplication: 1,803
duplicates removed: 182
review records: 68
completed enabled sources: 14 of 17
```

تم إصلاح مصدرين والتحقق منهما حيًا:

- GitHub Global Advisories كان يرفض fractional-second `modified` بقيمة 422؛ أصبح الموصل يرسل whole-second ISO-8601. وظيفة المصدر قبلت 494 observation، وصدر ملفًا نهائيًا من 445 سجلًا بعد قواعد المراجعة/التكرار.
- NVD أعاد صفحة أكبر من الحد عندما كان الحجم 2,000؛ أصبح page size يساوي 100 مع checkpointed pagination. وظيفة المصدر قبلت 498 observation، وصدر ملفًا نهائيًا من 410 سجلات.

المصدر المتبقي المعزول هو CISA Advisories HTML/RSS؛ عنوان Contabo الحالي يحصل على HTTP 403 من WAF، بينما CISA KEV JSON يعمل. لم نحاول تجاوز WAF أو استخدام Proxy غير معتمد.

آخر دورة مجدولة:

```text
run: ext-20260830T023620Z-e43aa62efbe4
status: partial
accepted records: 880
review records: 47
failed provider: CISA Advisories
```

## 4. إصلاح فقد الدفعات وبناء Snapshot تراكمي

اكتشف اختبار القبول أن Gateway القديم كان يستبدل آخر export فقط. لو كان جهاز Ammar مطفأ أثناء دورتين، فقد يفوّت الدفعة الأولى. تم إصلاح ذلك كما يلي:

- كل publish جديد يُدمج حسب stable `external_id` في Snapshot تراكمي.
- السجل الجديد يُضاف، والمتغير يستبدل نسخته السابقة، والمتطابق يبقى مرة واحدة.
- الدمج تحت Lock ثم Atomic Write.
- رفض تجاوز الحدود يحافظ على Snapshot السابق.
- الحدود: 20 MB لكل publish، و100 MB/20,000 عنصر للـSnapshot.
- Gateway يضغط الصفحات الكبيرة بـGZip، بينما يبقى HMAC على JSON الأصلي الذي يتحقق منه العميل بعد فك الضغط.

أُعيد تشغيل التصديرات التاريخية المحفوظة من الأقدم إلى الأحدث:

| Run export | عناصر الدفعة | إجمالي Snapshot بعد الدمج |
|---|---:|---:|
| Initial all-enabled | 1,803 | 2,629 |
| GitHub retry export | 445 | 3,060 |
| NVD retry export | 410 | 3,423 |
| Scheduled export | 874 | 4,184 |
| Latest scheduled export | 880 | 4,184 |

في إعادة نشر آخر 880 سجلًا:

```text
inserted: 0
updated: 119
unchanged: 761
final unique snapshot: 4,184
```

## 5. القبول الحي من Gateway إلى BERT/PostgreSQL

سحب آخر export قبل الدمج:

```text
collected: 880
processed: 880
stored: 880
failed: 0
pages: 4
JSON bytes after decompression: 3,683,825
elapsed: 370.69 seconds
```

الإعادة المتطابقة:

```text
not_modified: true
collected/processed/stored: 0/0/0
elapsed: 1.16 seconds
```

بعد بناء Snapshot التراكمي، أُضيفت مقارنة PostgreSQL قبل النموذج. الحقول التي تؤثر على المعالجة فقط تُقارن؛ collected timestamps المتغيرة لا تفرض BERT جديدًا. كما أصبح جلب الهويات الموجودة دفعيًا بدل استعلام لكل سجل.

نتيجة السحب التراكمي:

```text
collected: 4,184
database unchanged and skipped before BERT: 880
changed or new and processed: 3,304
stored: 3,304
failed: 0
pages: 17
JSON bytes after decompression: 17,201,280
elapsed: 1,264.01 seconds
```

الإعادة النهائية بعد بناء أحدث Backend:

```text
not_modified: true
collected/processed/stored: 0/0/0
elapsed: 0.44 seconds
```

الزمن الكبير لأول Snapshot موثق بصدق: المعالجة الحالية Synchronous وBERT يعمل محليًا على CPU. Celery/Redis أو worker queue تحسين مستقبلي لعرض progress وعدم إبقاء طلب HTTP مفتوحًا، وليس شرطًا لصحة النتيجة الحالية.

## 6. Internal Sources الحية

نتيجة السحب الحي:

| المصدر | Logs collected | Sessions | Outliers promoted | CTI events |
|---|---:|---:|---:|---:|
| Dionaea | 4,627 | 105 | 11 | 11 |
| SSH Auth | 0 جديد بعد checkpoint | 0 | 0 | 0 |
| Gateway Web | 53 | 5 | 1 | 1 |

إعادة السحب بعد أقل من دقيقتين أثبتت incremental checkpoints:

| المصدر | جديد فقط | Sessions | Outliers |
|---|---:|---:|---:|
| Dionaea | 35 | 1 | 0 |
| SSH Auth | 0 | 0 | 0 |
| Gateway Web | 2 | 1 | 0 |

هذا يثبت أن النظام لا يعيد آلاف السجلات السابقة ولا يعامل كل Log كتهديد. السجلات تحفظ Raw أولًا، ثم تُبنى Sessions، ثم تحتفظ القاعدة بالـNormal والـOutlier، وفقط Outliers تتحول إلى CTI Events.

## 7. PostgreSQL بعد القبول

العدادات النهائية:

| الجدول | Rows |
|---|---:|
| `raw_items` | 9,832 |
| `pipeline_runs` | 23 |
| `threat_events` | 4,216 |
| `indicators` | 2,666 |
| `entities` | 13,021 |
| `extracted_relationships` | 31,451 |
| `enrichments` | 0 |
| `correlations` | 9 |
| `outlier_sessions` | 169 |
| `audit_logs` | 35 |
| `sources` | 24 |

التوزيع:

```text
External CTI events: 4,197
Internal CTI events: 19
Sessions: 169
Outliers: 19
Normal retained sessions: 150
Pipeline runs completed: 23 of 23
```

كون `raw_items=9,832` بينما `threat_events=4,216` ووجود 150 Session طبيعية محفوظة يثبت الفصل بين المصدر الخام والنتيجة التحليلية.

`enrichments=0` يعني أن endpoint الإثراء الاختياري لكل CVE لم يُشغَّل على قاعدة القبول النهائية. لا يعني ذلك غياب NVD من External Sources؛ بيانات NVD موجودة ضمن الـFeed. لا ندعي live NVD enrichment منفصلًا دون تشغيله وقراءة صفوفه.

الـ9 Correlations تعود لاختبار القبول المحكوم السابق. لم نعد تشغيل correlation النصي التربيعي على 4,216 Event؛ هذه الحدود موثقة لأن Relationship/Similarity extraction ما زال Prototype في نطاق مشروع التخرج.

## 8. DNRTI BERT ونتائج ML

`GET /api/v1/ml/status` أعاد حيًا:

```text
runtime backend: transformer
primary_model_loaded: true
primary: dnrti_bert_ner
secondary fallback: dnrti_sklearn_ner
minimum confidence: 0.50
chunk chars/overlap: 600/100
all quality gates: passed
```

مقاييس held-out المحفوظة:

| النموذج | Precision | Recall | Entity F1 | Accuracy |
|---|---:|---:|---:|---:|
| DNRTI BERT primary | 0.7614 | 0.8020 | 0.7812 | 0.9376 |
| sklearn secondary | 0.5226 | 0.8186 | 0.6379 | 0.8833 token accuracy |

هذه مقاييس test split محفوظة وليست ادعاء production accuracy. لم نعد تدريب BERT في هذه المرحلة، لذلك لا ندعي ارتفاع F1. التحسينات كانت تشغيلية: primary/fallback صحيحان، تحميل مرة واحدة، chunk overlap، confidence filtering، dedup، وتجاوز السجلات المتطابقة قبل inference.

## 9. STIX وMISP

تصدير الحدث المحكوم أنشأ STIX 2.1 Bundle صالحًا للـparse:

```text
bundle objects: 4
types: identity, indicator, report, vulnerability
```

MISP health حي:

```text
configured: true
reachable: true
version: 2.5.44
heartbeat: HTTP 200
```

إعادة إرسال Event القبول المحكوم:

```text
event created: false
attributes requested: 2
attributes added: 0
attributes verified after read-back: 2
published: false
```

هذا يثبت UUID mapping وعدم التكرار وread-back verification. المؤشرات كانت بيانات اختبار محجوزة وليست عناوين مهاجمين حقيقية، والحدث بقي غير منشور.

## 10. أمن وتشغيل الـVPS

- SSH يعتمد المفاتيح فقط؛ Password وkeyboard-interactive معطلان.
- Gateway وExternal Control وMISP لا تُنشر للعامة.
- Read/Publish/Sensor/Control/MISP credentials مستقلة ومخزنة خارج Git.
- Dionaea لا يملك Docker socket أو مفاتيح MISP/PostgreSQL أو volumes خاصة بهما.
- `DOCKER-USER` يمنع الاتصالات الصادرة الجديدة من شبكة الحساس والبوابة مع السماح بالردود القائمة.
- MISP وDionaea يشتركان في kernel واحد لأن هذا مختبر منخفض التكلفة؛ Honeypot مستقل يبقى أفضل مستقبلًا.
- أول نقل كبير كشف reset في نفق SSH العام. السبب كان ازدحام pre-auth و`MaxStartups` مع اختلاف عنوان خروج Codex عن جلسة المستخدم. استُخدم listener مؤقت بالمفتاح فقط وقاعدة UFW مقيّدة بعنوان المصدر أثناء العمل، ولم يُفتح للعامة.

حادثة تخزين موثقة: upstream Dionaea all-level text log وصل إلى نحو 106 GB. تم truncation لذلك text log فقط بعد التحقق، بينما بقيت JSON incidents وbistreams/binaries الأدلة المعتمدة. الصورة المشتقة الآن تقيد النص إلى warning/error، وlogrotate إلى 25 MB مع أربع نسخ مضغوطة، وretention يحذف bistreams بعد 7 أيام وcaptured binaries بعد 30 يومًا. لا تُشغّل captured payloads.

## 11. جاهزية الـFrontend

الـFrontend لا يحتاج اتصالًا مباشرًا بـVPS أو PostgreSQL أو MISP. يستخدم FastAPI فقط:

```text
POST /api/v1/auth/login
GET  /api/v1/dashboard/summary
GET  /api/v1/events
GET  /api/v1/events/{event_id}
GET  /api/v1/indicators
GET  /api/v1/outliers
GET  /api/v1/runs
GET  /api/v1/integrations/status
GET  /api/v1/integrations/external-control/sources
POST /api/v1/integrations/external-control/jobs
POST /api/v1/integrations/external-control/manual-sources
POST /api/v1/integrations/external-feed/pull
POST /api/v1/integrations/dionaea/pull
POST /api/v1/integrations/host-auth/pull
POST /api/v1/integrations/web-access/pull
GET  /api/v1/ml/status
GET  /api/v1/events/{event_id}/stix
POST /api/v1/events/{event_id}/misp
```

Dashboard acceptance:

```text
events: 4,216
indicators: 2,666
correlations: 9
sessions: 167 at dashboard capture time
outliers: 19
severity: high=10, medium=27, low=4,179
pipeline: external=4,197, internal=19
```

لاحقًا أضاف repeat pull جلستين طبيعيتين فأصبح جدول sessions النهائي 169، بينما ظل events/outliers كما هما.

## 12. ما لا ندعي أنه مكتمل

- Wazuh Manager/Indexer/Dashboard غير منشور.
- Live Onion/Tor collection غير مفعّل ولا توجد قائمة Onion تشغيلية معتمدة.
- CISA Advisories HTML/RSS يفشل بـ403 من عنوان الـVPS؛ CISA KEV يعمل.
- المعالجة الكبيرة Synchronous وليست Celery/Redis workers.
- Risk Score قواعد قابلة للتفسير، وليس نموذج AI مدربًا.
- Relationship extraction وtext-similarity correlation ما زالا Rule-based/Prototype.
- لا يوجد off-host restore test مكتمل.
- لا يوجد production DNS/TLS أو HA أو enterprise SOC claim.
- MongoDB غير مستخدمة؛ PostgreSQL مع JSON columns تفي بالغرض وتمنع ازدواج مصدر الحقيقة.

هذه حدود معلنة وليست مكونات نكتب عنها كأنها حية.

## جواب جاهز للمناقش

> تأكدنا من صحة الـBackend بثلاثة أنواع من الأدلة: 241 اختبارًا آليًا تشمل الرفض وعدم التكرار، واختبار حي للخدمات على الـVPS، وتتبع فعلي للبيانات حتى PostgreSQL وBERT وRegex وSTIX وMISP. استوردنا Snapshot خارجيًا من 4,184 سجلًا؛ تجاوزنا 880 سجلًا متطابقًا قبل BERT وعالجنا 3,304 دون فشل، ثم أعادت الإعادة 304 وصفر تخزين. كما جمع Dionaea 4,627 Log لكنه كوّن 105 Sessions ورقّى 11 Outlier فقط. القاعدة النهائية احتفظت بـ9,832 Raw و169 Session منها 150 طبيعية، بينما أنشأت 4,216 CTI Event فقط. وأعدنا إرسال Event إلى MISP فوجد الحدث السابق، أضاف صفر Attribute، وتحقق من الاثنين وبقي غير منشور. لذلك النتيجة ليست ادعاءً نظريًا، ومع ذلك نوثق بوضوح أن Wazuh وOnion وCelery وHA ليست مكتملة.

## الملفات المرجعية

- `docs/architecture/cloud_distributed_architecture.md`
- `docs/architecture/future_bound_work.md`
- `docs/operations/vps_deployment_plan.md`
- `docs/operations/vps_external_sources.md`
- `docs/api/external_feed_contract.md`
- `docs/api/internal_sensor_contract.md`
- `infra/vps/README.md`
