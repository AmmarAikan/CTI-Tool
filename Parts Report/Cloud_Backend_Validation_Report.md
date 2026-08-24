# تقرير إثبات صحة الـBackend والتكامل السحابي

تاريخ التقرير: 2026-08-24
فرع العمل: `newBackend-cloud-integration`

## الخلاصة

الـBackend المحلي جاهز من ناحية العقود والعمل البرمجي لاستقبال ثلاثة مصادر بعيدة: External Feed، وWazuh Indexer، وDionaea JSON Sensor API. المعالجة الثقيلة، ومنها DNRTI BERT، تبقى في جهاز Ammar، والنتائج الخام والمعالجة تُحفظ في PostgreSQL ضمن نموذج CTI موحد. MISP يبقى منصة مشاركة ومراجعة، وWazuh يبقى منصة SIEM، ولا يحل أي منهما محل قاعدة المشروع المركزية.

هذا التقرير لا يدّعي أن Wazuh Server أو MISP Server أو الـpublic honeypot قد نُشرت؛ نشرها واختبارها الفعلي ينتظر شراء الـVPS ووصول SSH. الموجود الآن هو الكود المحلي، العقود، الحماية، الاختبارات، وخطة القبول.

## ماذا تم تنفيذه في هذه المرحلة؟

### External Feed الخاص بجهاز الزميل

- عقد JSON بإصدار `1.0` ومعرّفات ثابتة لكل سجل.
- Bearer authentication وHTTPS إجباري افتراضيًا.
- HMAC-SHA256 اختياري للتحقق من سلامة bytes نفسها.
- pagination محدودة، cursor/checkpoint، وETag/304.
- حد أقصى للحجم وعدد الصفحات، ومنع تغيّر `feed_id` أو `schema_version` بين الصفحات.
- رفض الدفعة كاملة قبل التخزين إذا فشل العقد أو التوقيع.
- إزالة التكرار داخل الدفعة، ثم upsert في قاعدة البيانات لمنع التكرار بين التشغيلات.

الواجهات:

```text
GET  /api/v1/integrations/external-feed/health
POST /api/v1/integrations/external-feed/pull
```

### Wazuh

- بقي رفع JSON/JSONL/NDJSON القديم متاحًا للاختبار.
- أُضيف عميل Wazuh Indexer حقيقي يقرأ `wazuh-alerts*` عبر API مصادق عليه.
- القراءة محدودة إلى batch قابل للضبط.
- استُخدم `search_after` مع timestamp وحقل alert `id` كـtiebreaker حتى لا نفقد أحداثًا لها نفس الوقت، ولا نقع في تكرار أول صفحة. قابلية ترتيب الحقل تُفحص من live index mapping عند النشر.
- checkpoint غير السري يُحفظ في `sources.config`، بينما بيانات الدخول تبقى في البيئة.
- Index pattern وtimestamp field قابلان للضبط والتحقق.

الواجهات:

```text
GET  /api/v1/integrations/wazuh/health
POST /api/v1/integrations/wazuh/pull
```

### Dionaea

- بقي Dionaea المحلي المعزول ورفع JSON متاحين للعرض بدون إنترنت.
- أُضيف عميل API مستقل لسحب Dionaea JSON الخام من حساس الـVPS.
- يستخدم HTTPS وBearer وHMAC وحدود حجم/صفحات وcheckpoint.
- بقي مسار Wazuh موازيًا: Dionaea الخام يحفظ الدليل الأصلي، وWazuh يضيف القواعد والتنبيهات والمراقبة.

الواجهات:

```text
GET  /api/v1/integrations/dionaea/health
POST /api/v1/integrations/dionaea/pull
```

### BERT ونتائج الـML

ترتيب النماذج لم يتغير:

1. Primary: `ml/models/dnrti_bert_ner`
2. Secondary: `ml/models/dnrti_sklearn_ner/model.joblib`
3. Safe degradation: لا يعيد Entities إذا تعذر النموذجان، ولا يسقط الـpipeline.

التحسينات التشغيلية:

- تحميل BERT مرة واحدة لكل backend process بدل تحميله مع كل طلب.
- تقسيم التقارير الطويلة إلى chunks متداخلة حتى لا يقتصر الاستخراج على أول جزء أو تضيع entity عند الحد.
- دمج entities المكررة مع الاحتفاظ بأعلى ثقة.
- حد ثقة `NER_MIN_CONFIDENCE` قابل للضبط.
- واجهة دليل لا تعرض ملفات النموذج أو أسرارًا:

```text
GET /api/v1/ml/status
```

المقاييس المحفوظة على held-out DNRTI test split:

| النموذج | Precision | Recall | Entity F1 | Accuracy |
|---|---:|---:|---:|---:|
| DNRTI BERT primary | 0.7614 | 0.8020 | 0.7812 | 0.9376 |
| sklearn secondary | 0.5226 | 0.8186 | 0.6379 | 0.8833 token accuracy |

BERT أعلى من البديل في Entity F1 بحوالي `0.1433`. نعتمد F1 كدليل أهم من accuracy لأن وسم `O` كثير في NER ويمكن أن يرفع accuracy حتى مع ضعف بعض فئات entities.

مهم: تحسين chunking/caching/filtering يحسن تغطية النصوص الطويلة وثبات التشغيل، لكنه لا يُقدَّم كادعاء أن held-out F1 ارتفع؛ لم نعد تدريب النموذج في هذه المرحلة. التقرير المحفوظ يذكر epoch واحدة، وأي إعادة تدريب لاحقة يجب أن تكون تجربة منفصلة تحفظ النموذج الحالي وتقارن على نفس test split قبل الاستبدال.

### Risk Score وCorrelation وNVD

أصبح NVD وCorrelation يعيدان تشغيل معادلة Risk واحدة بدل وجود معادلات متفرقة. العوامل المخزنة مع الحدث هي:

```text
base severity أو CVSS
+ indicator count
+ confidence
+ source diversity
+ correlation count
+ internal outlier flag
= score من 0 إلى 100
```

تُحفظ `risk_factors` و`risk_context` لتفسير النتيجة للمناقش. كما تُحفظ `source_severity` الأصلية قبل تحويلها إلى severity مشتقة من الـRisk؛ لذلك إعادة الحساب لا تضخم النتيجة تكراريًا.

### MISP

- mapping إلى الأنواع والفئات المناسبة للمؤشرات.
- UUID ثابت للـEvent ولكل Attribute حتى يكون التتبع وإعادة الاختبار مستقرين.
- `first_seen` و`last_seen` للمؤشرات عندما تتوفر.
- tags للمصدر وseverity.
- الإرسال غير منشور `published=false` افتراضيًا.
- dry-run قبل الإرسال الحقيقي، والإرسال الحقيقي Admin فقط.

لا ندّعي أن repeat-send/upsert متوافق مع نسخة MISP الفعلية قبل اختبار السيرفر؛ UUIDs الثابتة تقلل الغموض، لكن سلوك التكرار النهائي يجب تسجيله بعد النشر.

## كيف نثبت للمناقش أن العمل صحيح؟

### 1. صحة كل وحدة

يُشغّل الأمر التالي اختبارات مع SQLite مؤقتة ولا يلمس PostgreSQL المحلي:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

النتيجة المسجلة لهذه المرحلة: `33 tests passed`.

كما نجح:

```text
Ruff checks: passed على جميع الملفات المتغيرة
Python compileall: passed
docker compose config: valid
Docker image: graduationproject-backend:latest built successfully
Local Compose smoke test: PostgreSQL healthy
GET /api/v1/health: {"status":"ok","database":true}
```

تغطي الاختبارات:

- أولوية BERT ثم sklearn fallback.
- classification قبل NER وعدم تشغيل NER للنص غير السيبراني.
- Regex IoCs وإزالة التكرار.
- تقسيم النص الطويل، confidence filtering، ودمج entities.
- External pagination وHMAC الصحيح.
- تكامل External Feed كاملًا مع قاعدة مؤقتة وإثبات idempotency عند تشغيله مرتين.
- رفض HMAC الخاطئ والعنصر بلا stable ID.
- رفض HTTP غير المشفر افتراضيًا.
- Wazuh `search_after` والتطبيع إلى Internal RawRecord.
- تكامل Wazuh Indexer كاملًا مع قاعدة مؤقتة وإثبات عدم تكرار raw/event/session.
- Dionaea remote JSON وحفظ raw event/checkpoint.
- تكامل Dionaea Sensor كاملًا مرتين وإثبات idempotency وredaction في CTI copy.
- جلسات Dionaea/Wazuh وIsolation Forest والـsmall-batch fallback المسمى بوضوح.
- عدم تحويل كل log إلى تهديد؛ فقط outlier sessions تصبح CTI events.
- idempotency عند رفع Wazuh مرتين.
- STIX bundle قابل للـparse بمكتبة `stix2`.
- MISP dry-run وUUID mapping ثابت.
- تفسير Risk وعدم تضخيم severity عند إعادة الحساب.
- API authentication، roles، dashboard، والأدلة المخزنة.

### 2. صحة النموذج

الدليل ليس جملة «النموذج يعمل»، بل:

- train/validation/test splits محفوظة.
- held-out metrics محفوظة في `ml/reports/`.
- مقارنة primary وsecondary على test evidence.
- model artifacts موجودة.
- `/ml/status` يعرض backend الفعلي وquality gates.
- نموذج BERT لا يُستبدل إلا إذا نجحت مقارنة قابلة للإعادة على نفس الاختبار.

### 3. صحة انتقال البيانات

لكل ingestion توجد سلسلة يمكن تتبعها:

```text
source
-> pipeline_runs
-> raw_items (الدليل الخام)
-> threat_events (النتيجة الموحدة)
-> indicators/entities/relationships
-> enrichments/correlations/risk factors
-> STIX أو MISP أو Frontend API
```

يمكن إظهارها من Swagger عبر:

```text
/integrations/status
/runs
/sources
/events/{event_id}
/indicators
/outliers
/correlations
/dashboard/summary
/audit
```

### 4. اختبارات سلبية، لا happy path فقط

العمل الصحيح يجب أن يرفض البيانات غير الموثوقة. لهذا نختبر توقيعًا خاطئًا، HTTP، schema ناقصة، stable ID مفقودًا، pagination غير مستقرة، حجمًا زائدًا، وعدم المصادقة. الدفعة البعيدة لا تُخزن جزئيًا عندما يفشل التحقق.

### 5. إثبات الـVPS بعد SSH

لا يكفي أن تعمل health endpoints. سجل القبول النهائي يجب أن يحتوي على:

- Wazuh: agent حقيقي، controlled alert، ظهوره في Dashboard/Indexer ثم PostgreSQL، وتكرار pull بلا duplicate.
- Dionaea: interaction آمن ومصرح، ظهوره في raw JSON، ثم Wazuh، ثم backend، مع redaction في CTI copy.
- MISP: health/version، dry-run، ثم unpublished event حقيقي وattributes المتوقعة.
- External feed: valid pull، ثم رفض wrong token/signature/schema، ثم إعادة pull بلا duplicate.
- الشبكة: إثبات أن `9200` و`55000` وsensor API وقواعد البيانات غير عامة.
- النسخ الاحتياطي: backup وrestore على نسخة تجريبية.
- الموارد: RAM/disk/index growth بعد حمل تجريبي.

## ما الذي لا ندّعي أنه مكتمل؟

- لا يوجد وصول SSH أو نشر VPS حتى تاريخ التقرير.
- لا يوجد Wazuh/MISP live end-to-end test بعد.
- لا يوجد public Dionaea live capture بعد.
- الـRelationship extraction ما زال rule-based prototype.
- Risk Score قواعد قابلة للتفسير، وليس نموذج AI مدربًا.
- التشغيل ما زال synchronous؛ Celery/Redis مؤجلان.
- MongoDB غير مستخدمة لأن PostgreSQL + JSON يفيان بحاجة المشروع الحالية.
- لا يوجد live onion validation للـDark Web collector.
- لا يوجد ادعاء enterprise SOC/high availability.

هذه ليست عيوبًا مخفية؛ هي حدود Graduation Project موثقة ومعايير إكمالها محددة.

## قرار الموارد

الخطة المشار إليها Cloud VPS 4 تعطي حاليًا 4 vCores و8 GB RAM و100 GB SSD، وهي تقريبًا الحد الأدنى الرسمي لـWazuh single-node وحده. لذلك لا نوصي بوضع Wazuh + MISP + public honeypot عليها. نقطة بداية عملية لـWazuh/MISP هي 8 vCores و24 GB RAM و300 GB، مع حساس Dionaea منفصل كلما أمكن.

المراجع الرسمية وخطة المنافذ والقبول موجودة في:

- `docs/architecture/cloud_distributed_architecture.md`
- `docs/operations/vps_deployment_plan.md`
- `docs/api/external_feed_contract.md`
- `docs/api/dionaea_sensor_contract.md`

## جواب مختصر جاهز للمناقش

> تأكدنا من صحة النظام على ثلاث طبقات: اختبارات وحدات وتكامل مع قاعدة مؤقتة تشمل حالات الرفض والتكرار، مقاييس held-out موثقة لنموذج BERT ومقارنته بالنموذج الاحتياطي، وتتبع كامل من raw source إلى CTI event وIoCs وRisk وSTIX/MISP. الخدمات السحابية لا نعدها مكتملة بالكود فقط؛ سنضيف لها سجل قبول حي يثبت alert من Wazuh، وDionaea event خام، وMISP event غير منشور، وإعادة ingestion بلا تكرار، مع إثبات عزل المنافذ والنسخ الاحتياطي.
