# تدقيق جاهزية الواجهة الأمامية لـ External Sources

**نوع العمل:** تدقيق قراءة فقط

**تاريخ التدقيق:** 2026-09-02

**النطاق:** External Sources وواجهة Gateway الخاصة به فقط. لم يشمل التدقيق Internal Sources أو Analysis، ولم يتم تشغيل مهام جمع أو إرسال عناوين أو تعديل مصادر أو حالة تشغيل.

## 1. الملخص التنفيذي

واجهة External Sources الحالية هي واجهة تحكم داخلية، وليست API عامة للمتصفح. تحتوي على 14 مساراً في FastAPI تغطي الصحة، تشغيل المصادر، الوظائف اليدوية، قراءة المصادر، حالة الوظيفة، الإلغاء، آخر تصدير، وملف المراجعة الأخير.

الجاهزية الحالية:

- **جاهز الآن:** الصحة، قراءة قائمة المصادر وحالة مصدر، قراءة حالة وظيفة معروفة، ملخص آخر تصدير، قراءة آخر ملف مراجعة، وتشغيل مصدر أو كل المصادر للمستخدم المخول.
- **جاهز مع قيود:** تشغيل وإلغاء الوظائف، الإرسال اليدوي، قراءة التصدير الكامل، وإظهار مصادر Dark Web. هذه العمليات غير قابلة للتصفح أو البحث أو الإدارة التفصيلية، وبعضها يعرض بيانات تشغيلية واسعة.
- **يتطلب تحسيناً في Backend:** تاريخ الوظائف وقائمته، pagination/filtering/sorting/search، retry، preview للرابط اليدوي، إجراءات المراجعة، وCRUD للمصادر.
- **غير مطبق حالياً:** وكيل External Sources عبر Gateway، OpenAPI في التشغيل الحي، CORS/CSRF policy للمتصفح، وهوية مستخدم مستقلة عن static bearer token.

تمت قراءة تعريفات FastAPI والنماذج والصلاحيات، ومراجعة Gateway والاختبارات والعقود. كما تم إجراء GET فقط على الخدمة الحية. لم تتم محاولة تشغيل وظيفة أو إرسال URL.

## 2. مصادر الحقيقة في الكود

- [integration/api.py](../../backend/app/pipeline/ingestion/external/integration/api.py): تعريف المسارات، نماذج الاستجابة، معالجة الأخطاء، وOpenAPI المشروط.
- [integration/schemas.py](../../backend/app/pipeline/ingestion/external/integration/schemas.py): نماذج الطلب والاستجابة الصارمة.
- [integration/auth.py](../../backend/app/pipeline/ingestion/external/integration/auth.py): Bearer authentication وRole/Permission policy.
- [integration/local.py](../../backend/app/pipeline/ingestion/external/integration/local.py): تركيب التطبيق المحلي، static token، وتشغيل الذاكرة للوظائف.
- [infra/vps/gateway/app.py](../../infra/vps/gateway/app.py): Gateway ومسارات feed/sensors، ولا يحتوي proxy لمسارات External control.
- [external_sources_rest_integration.md](../../docs/architecture/external_sources_rest_integration.md): حدود Phase 11 ومتطلبات الإنتاج المستقبلية.

## 3. جرد FastAPI الكامل

كل المسارات أدناه تبدأ بـ `/api/v1/external-sources` ما لم يذكر خلاف ذلك.

| الطريقة والمسار | الغرض | الطلب | الاستجابة | المصادقة والصلاحية | حالات النجاح والخطأ | Gateway | الجاهزية |
|---|---|---|---|---|---|---|---|
| `GET /health` | فحص صحة External Sources | لا يوجد | `HealthResponse`: `status`, `service`, `api_version` | بدون مصادقة | `200`; لا يوجد خطأ مخصص | غير مكشوف عبر Gateway | جاهز الآن |
| `POST /jobs` | تشغيل مصادر محددة أو كل المصادر المفعلة | `CollectionRequestBody`: `source_ids[]`, `scope` (`all_enabled`)، `force`, `options` | `JobStatusResponse` بحالة `queued` و`job_id` و`command_id` | Bearer؛ `jobs:create` | `202`; `401`, `403`, `404`, `409`, `422`, `503` | لا | جاهز مع قيود |
| `POST /sources/{source_id}/jobs` | تشغيل مصدر واحد | `SourceCollectionRequestBody`: `force` | `JobStatusResponse` | Bearer؛ `jobs:create` | `202`; `401`, `403`, `404`, `409`, `422`, `503` | لا | جاهز مع قيود |
| `POST /manual-sources` | إرسال URL يدوي إلى مسار المعالجة | `ManualURLRequestBody`: `url` من نوع `HttpUrl`، `force` | `JobStatusResponse` | Bearer؛ `manual:create` | `202`; `401`, `403`, `422`; الأخطاء اللاحقة تظهر داخل حالة الوظيفة | لا | جاهز مع قيود |
| `POST /manual-sources/recheck` | إعادة فحص URL يدوي | `ManualURLRequestBody`: `url`، `force` | `JobStatusResponse` | Bearer؛ `manual:create` | `202`; `401`, `403`, `422` | لا | جاهز مع قيود |
| `GET /sources` | قائمة المصادر المسجلة وحالتها | لا يوجد | `list[SourceResponse]`: `source_id`, `name`, `source_type`, `status`, `metadata` الآمنة | Bearer؛ `sources:read` | `200`; `401`, `403`, `500` | لا | جاهز الآن |
| `GET /sources/{source_id}` | حالة مصدر واحد | لا يوجد | `SourceResponse` | Bearer؛ `sources:read` | `200`; `401`, `403`, `404`, `422`, `500` | لا | جاهز الآن |
| `POST /sources/{source_id}/enable-requests` | طلب تفعيل مصدر مع إدخاله في حالة مراجعة | لا يوجد | `SourceResponse`، ويجب أن تكون الحالة `pending_review` أو `disabled` | Bearer؛ `sources:request_enable`، وDark Web يحتاج أيضاً `dark_web:approve` | `200`; `401`, `403`, `404`, `409`, `422`, `500` | لا | جاهز مع قيود |
| `POST /sources/{source_id}/disable` | تعطيل مصدر | لا يوجد | `SourceResponse` | Bearer؛ `sources:disable` | `200`; `401`, `403`, `404/500` بحسب خطأ الخدمة، `422` لمعرف غير صالح | لا | جاهز مع قيود |
| `GET /jobs/{job_id}` | قراءة حالة وظيفة واحدة | لا يوجد | `JobStatusResponse`: الحالة، التواريخ، progress، result، error | Bearer؛ `jobs:read` | `200`; `401`, `403`, `404`, `500` | لا | جاهز مع قيود |
| `POST /jobs/{job_id}/cancel` | طلب إلغاء تعاوني لوظيفة | لا يوجد | `JobStatusResponse`؛ قد تصبح `cancellation_requested` أو `cancelled` | Bearer؛ `jobs:cancel` | `200`; `401`, `403`, `404`; الخطأ غير المتوقع يصنف كـ `job_not_found` في هذا المسار | لا | جاهز مع قيود |
| `GET /exports/latest` | قراءة آخر تصدير متحقق، بما فيه dataset وmanifest | لا يوجد | `LatestExportResponse`: معرف التشغيل، counts، hash، dataset، manifest | Bearer؛ `exports:read` | `200`; `401`, `403`, `404`, `500` | لا | جاهز مع قيود |
| `GET /exports/latest/summary` | قراءة ملخص آخر تصدير دون dataset/manifest | لا يوجد | `LatestExportSummaryResponse`: معرف التشغيل، الحالة، hash، counts، وقت الإكمال | Bearer؛ `exports:read` | `200`; `401`, `403`, `404`, `500` | لا | جاهز الآن |
| `GET /reviews/latest` | قراءة آخر عناصر المراجعة المسقطة بشكل آمن | لا يوجد | `LatestReviewResponse`: `run_id` و`records[]` من `ReviewRecordResponse` | Bearer؛ `reviews:read` | `200`; `401`, `403`, `404`, `503`, `500` | لا | جاهز مع قيود |

### 3.1 النماذج المشتركة

`JobStatusResponse` يستخدم حالات ثابتة: `queued`, `running`, `completed`, `partial`, `failed`, `cancellation_requested`, `cancelled`. يحتوي `result` و`error` ككائنين اختياريين، لكن لا يوجد نموذج تفصيلي ثابت لمحتوى `result` لكل نوع وظيفة.

`IntegrationErrorResponse` هو العقد الموحد لأخطاء External Sources:

```json
{
  "schema_version": "1.0",
  "code": "string",
  "message": "safe message",
  "retryable": false,
  "details": {}
}
```

تلتقط طبقة FastAPI أخطاء التحقق في `422 request_validation_failed` مع قائمة `details.fields`، وتمنع إظهار trace أو نص الاستثناء الداخلي. بعض أخطاء Gateway لا تستخدم هذا العقد، بل تعيد FastAPI `detail`، لذلك لا يمكن للواجهة استخدام معالج أخطاء واحد للواجهتين دون طبقة تطبيع.

## 4. OpenAPI

- الكود ينشئ OpenAPI و`/docs` فقط عندما يكون `EXTERNAL_API_DOCS_ENABLED=true`.
- عند التفعيل، يضيف OpenAPI مخطط `HTTPBearer` ويضع security على كل المسارات عدا `/health`، ويصف نماذج الطلب والاستجابة وبعض أخطاء collection/export/review.
- في التشغيل الحي الذي تم فحصه: `GET http://127.0.0.1:8090/openapi.json` أعاد `404`، ولذلك لا تستطيع واجهة خارجية اكتشاف العقد آلياً من الخدمة الحالية.
- لا يوجد OpenAPI مكشوف لـ Gateway؛ التطبيق ينشئ FastAPI مع `docs_url=None` و`redoc_url=None`.
- توصية أمنية: لا يُفتح OpenAPI علناً. الأفضل نشر نسخة عقد versioned أو endpoint داخلي خلف الهوية المعتمدة، مع إبقاء أسرار التشغيل ومعلومات المصادر الحساسة خارج الوثيقة.

## 5. Gateway والتعرض الشبكي

Gateway الحالي يعرّف هذه المسارات فقط:

| الطريقة والمسار | الغرض | المصادقة | الاستجابة/القيود |
|---|---|---|---|
| `GET /health` | صحة Gateway واستعداد feed وحالة streams | بدون مصادقة | `200` مع flags للصحة؛ أعاد الحي `200` |
| `POST /api/v1/external-feed/publish` | نشر export إلى feed | Bearer مستقل للنشر | `202`; حجم محدود؛ أخطاء `401`, `413`, `422`؛ ليس مسار واجهة External Sources |
| `GET /api/v1/external-feed` | قراءة feed المنشور | Bearer مستقل للقراءة | Pagination بـ `limit` و`cursor`، ETag، توقيع HMAC؛ أخطاء `401`, `404`, `413`, `422` |
| `GET /api/v1/sensors/{stream_name}` | قراءة streams: `dionaea`, `host-auth`, `web-access` | Bearer مستقل للحساسات | Pagination وتوقيع HMAC؛ أخطاء `401`, `404`, `413`, `422` |

لا يوجد في Gateway proxy لأي من مسارات `/api/v1/external-sources`. تحقق `GET /api/v1/external-sources/health` عبر Gateway وأعاد `404`. لذلك فإن متغير الاتصال الخاص بـ External control يشير إلى خدمة التحكم مباشرة عبر loopback/SSH tunnel، وليس إلى Gateway.

النتيجة العملية: الواجهة لا تملك حالياً نقطة دخول browser-safe موحدة عبر Gateway. قراءة feed عبر Gateway ليست بديلاً عن التحكم بالمصادر أو الوظائف أو المراجعة.

## 6. المصادقة والصلاحيات

### 6.1 آلية المصادقة الحالية

External Sources يستخدم `Authorization: Bearer <token>` ويقارن token ثابتاً عبر مقارنة آمنة. في تركيب `local.py` يكون principal افتراضياً محلياً، وتأتي الأدوار من `EXTERNAL_API_ROLES`. هذا مناسب لمسار داخلي مؤقت، لكنه ليس هوية مستخدم كاملة للواجهة.

`/health` عام. كل مسار آخر يتطلب Bearer، ثم permission محدداً. غياب الرأس أو صيغته غير الصحيحة يعيد `401 authentication_required`، وفشل التحقق يعيد `401 authentication_failed`، وفشل الصلاحية يعيد `403 authorization_denied`.

### 6.2 مصفوفة الأدوار

| الدور | الصلاحيات المهمة |
|---|---|
| `viewer` | قراءة الصحة والمصادر والوظائف والتصدير والمراجعة |
| `operator` | صلاحيات viewer، إنشاء الوظائف، إلغاء الوظائف، الإرسال اليدوي، تعطيل المصادر، وطلب التفعيل |
| `source_approver` | قراءة المصادر والوظائف، طلب التفعيل، تعطيل المصادر؛ لا يملك `dark_web:approve` |
| `dark_web_approver` | قراءة المصادر والوظائف، طلب التفعيل، تعطيل المصادر، و`dark_web:approve` |
| `admin` | `*` وفق Authorizer الحالي |

صلاحية `sources:request_enable` اسمها يدل على طلب تفعيل، وليست موافقة نهائية. مسار Dark Web يطلب `dark_web:approve` إضافية، لكن التنفيذ الحالي لا يوفر endpoint مستقلاً للموافقة أو الرفض.

### 6.3 ملاحظات المتصفح

- لم يتم العثور على `CORSMiddleware` أو سياسة CORS أو CSRF في مسار External Sources/Gateway.
- Bearer token في تطبيق browser يحتاج قناة هوية آمنة وإدارة جلسة، ولا ينبغي تضمينه في JavaScript عام أو تخزينه بطريقة مكشوفة.
- إذا بقيت الواجهة على origin مختلف، فستحتاج CORS allowlist ضيقة ومحددة، ويفضل أن يكون Gateway هو نقطة الدخول نفسها لتقليل cross-origin exposure.
- CSRF يصبح مهماً عند استخدام cookies أو جلسات تلقائية. إذا استمر Bearer في `Authorization` مع عدم وجود cookie تلقائي، الخطر مختلف، لكن حماية origin وتهيئة CORS ما زالت مطلوبة.
- Gateway يسجل طلبات الويب محلياً؛ يجب التأكد أن سياسة التسجيل لا تسجل Authorization أو body الحساس. الكود الحالي يستبعد بعض الحقول الحساسة من payloads، لكن المسار المعماري الكامل للواجهة لم يُنفذ بعد.

## 7. ربط الشاشات بالـ API

| الشاشة | إجراء المستخدم | Endpoint | جاهز | المتطلب المفقود | أصغر إصلاح موصى به |
|---|---|---|---|---|---|
| Dashboard | عرض صحة الخدمة وملخص آخر تشغيل | `GET /health` + `GET /exports/latest/summary` | نعم | لا يوجد تجميع موحد أو SLA واضح | إضافة endpoint read-only مركب للملخص أو تجميع الاستدعاءات في BFF |
| قائمة المصادر وحالتها | عرض كل المصادر والحالة والنوع | `GET /sources` | نعم | لا pagination/filtering، ولا تفاصيل تشغيلية كافية | إضافة query filters وcursor pagination مع metadata آمنة |
| Run one source | تشغيل مصدر محدد | `POST /sources/{id}/jobs` | مع قيود | لا preview لتأثير `force` ولا رابط مباشر لتحديث الوظيفة | الإبقاء على 202 وإضافة operation metadata وpolling contract ثابت |
| Run all enabled sources | تشغيل كل المصادر المفعلة | `POST /jobs` مع `scope=all_enabled` | مع قيود | لا توجد قائمة بالوظائف أو progress تفصيلي دائم | إضافة `GET /jobs` مع حالة aggregate وpagination |
| Job status and history | متابعة وظيفة أو تصفح التاريخ | `GET /jobs/{id}` | حالة وظيفة واحدة فقط | لا listing/history/filter/search/sort، والـ runner في الذاكرة محلياً | إضافة JobRepository دائم و`GET /jobs` بمعايير query مستقرة |
| Job cancellation | إلغاء وظيفة | `POST /jobs/{id}/cancel` | مع قيود | لا retry، ولا سبب/سياسة انتقال حالات موثقة بالكامل | إضافة `POST /jobs/{id}/retry` وتوثيق state machine وidempotency |
| Manual URL submission | إرسال URL | `POST /manual-sources` | مع قيود | الإرسال يبدأ عملية مباشرة دون preview مستقل، ولا نتيجة synchronous للتحقق | إضافة `POST /manual-sources/preview` read-only لا يحفظ ولا يجمع |
| Manual URL recheck | إعادة الفحص | `POST /manual-sources/recheck` | مع قيود | لا listing للجذور اليدوية ولا حالة آخر فحص | إضافة قراءة آمنة للجذور بمعرفات opaque وحالة آخر فحص |
| Accepted exports | عرض البيانات المقبولة | `GET /exports/latest` | مع قيود | آخر export فقط، dataset قد يكون كبيراً، لا pagination أو download contract | إضافة endpoint export metadata/list وdownload/page bounded منفصل |
| Export summaries | عرض العدادات والـ hash | `GET /exports/latest/summary` | نعم | لا تاريخ للتصديرات | إضافة `GET /exports` بصفحة metadata فقط |
| Review queue | عرض عناصر المراجعة | `GET /reviews/latest` | مع قيود | قراءة آخر artifact فقط؛ لا approve/reject/assign/resolve ولا pagination | إضافة Review resource دائم مع حالات وإجراءات مدققة |
| Dark Web source visibility | إظهار وجود المصدر وحالته | `GET /sources` أو `GET /sources/{id}` | مع قيود | لا تعرض الواجهة سبب الحالة أو policy summary، ولا يجب كشف عنوان أو مسار Onion | إضافة safe policy/status fields مصممة صراحة دون URL أو path |
| Dark Web administration | طلب تفعيل/تعطيل مصدر | `POST /sources/{id}/enable-requests`, `POST /sources/{id}/disable` | مع قيود | لا create/edit/delete، ولا approve/reject مستقل، ولا audit UI | إضافة workflow إداري منفصل بمراجعة ثنائية وسجل تدقيق |
| Health and service status | التحقق من External وGateway | External `GET /health`، Gateway `GET /health` | نعم محلياً | لا proxy موحد ولا readiness تفصيلية للـ dependencies | إضافة Gateway read-only proxy أو BFF health contract |

## 8. فجوات القدرة الأمامية ذات الأولوية

### أولوية 1: تاريخ الوظائف والموثوقية

1. لا يوجد `GET /jobs`؛ الواجهة لا تستطيع بناء شاشة history أو البحث في الوظائف السابقة.
2. `InProcessJobRunner` تخزينه في الذاكرة وغير durable؛ إعادة تشغيل الخدمة تفقد حالة الوظائف.
3. لا يوجد retry endpoint، ولا نموذج واضح لتمييز retry الآمن من إعادة التشغيل القسري.
4. `progress` و`result` عامان؛ يلزم عقد versioned لكل نوع عملية أو projection موحد.

**الإصلاح الأصغر:** إضافة `GET /jobs` بصفحة cursor، وحالات/تواريخ/مصدر آمنة، ثم نقل القراءة إلى job store دائم قبل الاعتماد على history إنتاجي. يضاف `POST /jobs/{job_id}/retry` لاحقاً مع idempotency وشروط للحالات النهائية فقط.

### أولوية 2: workflow للمصادر والمراجعة

1. `enable-requests` ينشئ طلباً أو حالة مراجعة، لكنه ليس approve endpoint.
2. لا يوجد reject أو assign أو resolve لعناصر review.
3. لا توجد endpoints لإنشاء أو تعديل أو حذف مصدر.
4. Dark Web يحتاج صراحة إلى workflow منفصل يمنع كشف العنوان والمسار وبيانات Tor.

**الإصلاح الأصغر:** تعريف موارد `source-change-request` و`review-item` بحالات انتقال محددة، مع permissions منفصلة، audit record، وحقول projection آمنة. لا ينبغي تحويل endpoint الطلب الحالي إلى موافقة ضمنية.

### أولوية 3: Manual URL safety UX

1. `POST /manual-sources` و`recheck` يعيدان `202` ويبدآن job؛ لا يوجد preview قبل الحفظ أو التتبع.
2. لا توجد قراءة للجذور اليدوية أو نتيجة policy check قابلة للعرض دون بدء جمع.
3. يجب أن يظل preview read-only، وألا يعيد محتوى حساساً أو يسمح بتجاوز SSRF/onion policy.

**الإصلاح الأصغر:** إضافة `POST /manual-sources/preview` أو endpoint مكافئ بصلاحية منفصلة، يعيد canonical policy decision، route category، وسبباً آمناً فقط دون حفظ أو network fetch.

### أولوية 4: عقود القراءة والعرض

1. لا pagination/filtering/sorting/search في External control endpoints.
2. `/exports/latest` يجمع dataset وmanifest في استجابة واحدة وقد لا يناسب شاشة أو متصفحاً.
3. `/reviews/latest` و`/exports/latest` يعرضان آخر artifact فقط، لا تاريخاً.
4. لا يوجد endpoint موحد لحالة الخدمة dependencies أو latest job/export/review.

**الإصلاح الأصغر:** إضافة query contract موحد باستخدام cursor opaque وحدود قصوى، ثم endpoints metadata/history منفصلة عن payloads الكبيرة.

### أولوية 5: المصادقة عبر Gateway وCORS/CSRF

1. لا يوجد Gateway proxy لـ External Sources control.
2. static bearer token المحلي ليس نموذج هوية مستخدم للواجهة الإنتاجية.
3. لا توجد CORS policy أو CSRF policy ظاهرة.
4. Gateway feed authentication والتوقيع HMAC يخدمان feed ingestion، وليس جلسة مستخدم للـ dashboard.

**الإصلاح الأصغر:** وضع BFF/Gateway داخلي موثق خلف identity provider، مع allowlist للـ origin، جلسة قصيرة أو token exchange، CSRF عند استخدام cookies، وإخفاء service token عن المتصفح. يجب أن تبقى الخدمة المباشرة loopback-only.

## 9. التحقق الحي الآمن

تم استخدام GET فقط، مع مصادقة القراءة حيث يلزم، وتلخيص رموز HTTP وأشكال الاستجابة دون طباعة bodies أو أسرار أو محتوى حساس:

| الفحص | النتيجة |
|---|---|
| External `GET /api/v1/external-sources/health` | `200`، استجابة health متوقعة |
| Gateway `GET /health` | `200`، استجابة Gateway متوقعة |
| External `GET /openapi.json` | `404`، OpenAPI مغلق في live configuration |
| Gateway `GET /api/v1/external-sources/health` | `404`، لا يوجد proxy لهذا المسار |
| مصادق عليه: `GET /api/v1/external-sources/sources` | `200`، قائمة JSON |
| مصادق عليه: `GET /api/v1/external-sources/sources/{unknown}` | `404`، عقد خطأ External موحد |
| مصادق عليه: `GET /api/v1/external-sources/jobs/{unknown}` | `404`، عقد خطأ External موحد |
| مصادق عليه: `GET /api/v1/external-sources/exports/latest/summary` | `200`، summary keys متوقعة |
| مصادق عليه: `GET /api/v1/external-sources/reviews/latest` | `200`، review keys متوقعة |
| مصادق عليه: `GET /api/v1/external-sources/exports/latest` | `200`، dataset/manifest keys متوقعة؛ لم تُطبع القيم |

لم يتم استخدام `POST`، ولم يتم تشغيل وظيفة، ولم يتم إرسال URL أو إلغاء وظيفة، ولم يتم تعديل release أو symlink أو container أو environment.

## 10. التصنيف النهائي

### Ready now

- Health check لـ External Sources.
- Health check لـ Gateway.
- قراءة قائمة المصادر وحالة مصدر.
- قراءة summary لآخر export.
- قراءة آخر review artifact للعرض فقط.
- قراءة حالة وظيفة مفردة عند معرفة `job_id`.

### Frontend can use with limitation

- تشغيل مصدر واحد.
- تشغيل كل المصادر المفعلة.
- الإلغاء التعاوني.
- الإرسال اليدوي وإعادة الفحص.
- قراءة آخر export الكامل.
- إظهار Dark Web كمصدر آمن الهوية والنوع والحالة فقط.
- OpenAPI في بيئة داخلية مؤقتة فقط عند تفعيله خلف حماية، وليس في live الحالي.

### Backend improvement required

- قائمة وتاريخ الوظائف.
- pagination/filtering/sorting/search للوظائف والمصادر والتصديرات والمراجعات.
- retry وcontract موحد للـ progress/result.
- preview لعنوان يدوي دون حفظ أو جمع.
- review actions: approve/reject/assign/resolve.
- source CRUD وworkflow تفعيل صريح.
- API موحد وآمن عبر Gateway أو BFF.
- identity provider، token exchange، CORS allowlist، وCSRF policy عند استخدام cookies.
- OpenAPI/contract distribution داخلي versioned.

### Not currently implemented

- Gateway proxy لمسارات External control.
- `GET /jobs` للتاريخ.
- retry endpoint.
- manual URL preview endpoint.
- approve/reject review endpoint.
- create/edit/delete source endpoints.
- review queue actions.
- safe Dark Web administration workflow مستقل.
- CORS/CSRF configuration مخصصة لمسار الواجهة.

## 11. المرحلة التالية الموصى بها

المرحلة التالية الأصغر والأكثر تأثيراً هي **External Sources Frontend Contract Phase**، بهذا الترتيب:

1. تثبيت عقد versioned للقراءة: `GET /jobs`، `GET /exports`، و`GET /reviews` مع cursor pagination وfilter/sort محدودين.
2. إضافة job store دائم وstate machine موثقة، ثم retry بشروط آمنة.
3. تعريف manual preview read-only قبل endpoint الإرسال.
4. تعريف review/source workflow مستقل مع permissions وaudit events للموافقة والرفض والتعديل.
5. إنشاء BFF/Gateway داخلي للواجهة مع identity provider وCORS/CSRF policy مناسبة، مع إبقاء service token بعيداً عن browser.
6. نشر OpenAPI داخلياً أو artifact versioned بعد اكتمال هذه العقود، مع عدم كشف بيانات المصادر الحساسة.

لا ينبغي بدء تصميم أو تنفيذ الواجهة قبل تثبيت هذه العقود، لأن الشاشة الحالية ستضطر إلى تخمين history وworkflow وحالات الأخطاء غير الموجودة في API.

## 12. الخلاصة

External Sources قابل للاستخدام كلوحة تشغيل داخلية محدودة، وليس كواجهة Frontend مكتملة. أقوى أجزاء العقد الحالية هي القراءة الآمنة، health، التحكم المتدرج بالصلاحيات، وإخفاء metadata الحساسة. أكبر العوائق هي غياب التاريخ والتصفح، غياب إجراءات المراجعة وإدارة المصدر، وعدم وجود نقطة دخول browser-safe عبر Gateway. هذه الفجوات محددة ويمكن معالجتها في مرحلة Backend تعاقدية صغيرة قبل تنفيذ الواجهة.
