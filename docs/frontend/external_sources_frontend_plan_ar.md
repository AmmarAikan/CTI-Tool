# خطة معمارية الواجهة الأمامية لـ External Sources

**نوع العمل:** تدقيق معماري للقراءة فقط وخطة مستقبلية

**تاريخ التدقيق:** 2026-09-02

**الفرع والمرجع:** `feature/frontend-integration` عند `ff72b30`

## 1. الحكم الحالي

لا يوجد تطبيق Frontend حاليًا في المستودع. لا توجد مجلدات أو ملفات package/config أو مكونات React/Vue/Angular/Svelte متتبعة. ملفات HTML الموجودة تحت `tests/external_sources/fixtures/` بيانات fixtures للاختبارات وليست واجهة مستخدم.

الموجود حاليًا هو:

- FastAPI مركزي تحت `backend/app/`، وهو المسار الذي يجب أن يستخدمه المتصفح.
- مصادقة مستخدمين محلية عبر JWT في `POST /api/v1/auth/login` و`GET /api/v1/auth/me`.
- أدوار `admin` و`analyst` و`viewer`، مع تدقيق للعمليات الحساسة.
- مسارات dashboard وevents وintegrations، ومسارات External control مركزية تحت `/api/v1/integrations/external-control`.
- External Sources خدمة خاصة، وخدمة Gateway loopback. لا ينبغي للمتصفح الاتصال مباشرة بخدمة External أو حمل service token.
- الالتزام `ff72b30` يضيف proxy آمنًا في Gateway لمسارات External Sources، مع تحقق JWT، allowlist للمسارات، تمرير service token داخليًا، حدود للحجم والمهلة، وتنقية الأخطاء. هذا لا يحول Gateway إلى واجهة عامة للمتصفح.

**القرار:** إنشاء SPA عربية/ثنائية الاتجاه داخل مشروع Frontend مستقل، وتوجيه كل طلبات المتصفح إلى FastAPI المركزي عبر نفس origin أو BFF داخلي. يبقى اتصال FastAPI بخدمة External عبر القناة الخاصة القائمة. يمكن لاحقًا جعل central client يستخدم Gateway proxy كطبقة انتقال، لكن لا يُبنى تصميم الواجهة على كشف Gateway مباشرة.

## 2. إطار العمل المقترح

### الاختيار

- **React + TypeScript + Vite** كتطبيق مستقل تحت `frontend/`.
- React Router للمسارات، وTanStack Query لإدارة cache والطلبات وpolling، وReact Hook Form مع Zod للنماذج والتحقق المحلي.
- مكتبة مكونات خفيفة تعتمد على CSS variables وملفات CSS محلية، مع Lucide React للأيقونات.
- لا يُضاف أي اعتماد أو كود في هذه المرحلة؛ هذا اختيار تخطيطي فقط.

### سبب الاختيار

يتناسب React/TypeScript مع واجهة تشغيل كثيفة البيانات، حالات الوظائف غير المتزامنة، والصلاحيات المتغيرة. Vite يبقي البناء صغيرًا ومستقلًا عن FastAPI، ويسمح بتشغيل SPA محليًا ثم نشر ملفاتها خلف reverse proxy مع API على نفس origin.

### حدود الإصدار الأول

لا يشمل الإصدار الأول إدارة collectors من المتصفح، أو عرض عناوين Onion أو مسارات الملفات، أو استبدال dashboard المركزي، أو أي شاشة تتطلب endpoint غير موجود. لا تُخمن الواجهة تاريخ الوظائف أو إجراءات المراجعة؛ تُعرض هذه كـ `غير متاح` إلى أن يثبت عقد backend.

## 3. الهيكل المقترح

```text
frontend/
  src/
    app/                 router, providers, auth bootstrap
    api/                 typed client, endpoint functions, error normalization
    auth/                session store, route guards, permission helpers
    features/
      overview/          dashboard summary and service health
      external-sources/  sources list, source actions, safe metadata
      jobs/              job detail, status timeline, polling
      manual-sources/    URL submission and recheck
      exports/           latest export summary
      reviews/            read-only latest review until workflow exists
      events/             CTI event list/detail and existing backend views
    components/          table, status badge, alert, modal, empty/loading states
    i18n/                Arabic and English messages, direction switching
    styles/              tokens, layout, RTL-safe utilities
    types/               API response and domain types
  public/
  package.json
  tsconfig.json
  vite.config.ts
```

يجب أن يكون `api/` طبقة واحدة typed؛ لا تستدعي الصفحات `fetch` مباشرة. ويجب أن تكون بيانات API منفصلة عن view models حتى يمكن تغيير endpoint المركزي أو إضافة BFF دون إعادة بناء الشاشات.

## 4. الشاشات ومسارات التنقل

| الشاشة | المسار المقترح | البيانات الحالية | الإجراء/القيد |
|---|---|---|---|
| تسجيل الدخول | `/login` | `POST /auth/login` | لا تعرض تفاصيل فشل المصادقة؛ تمنع الانتقال قبل session صالحة. |
| الملخص التشغيلي | `/` | `/dashboard/summary`، `/integrations/status`، external health، latest export summary | قراءة فقط افتراضيًا؛ تعرض آخر تحديث وحالة كل dependency. |
| مصادر External | `/external-sources` | `/integrations/external-control/sources` | عرض `id/name/type/status` فقط؛ لا Onion URL أو path أو credentials. |
| تفاصيل مصدر | `/external-sources/:sourceId` | المصدر إن أضافه backend، أو القائمة الحالية | زر التشغيل حسب الصلاحية؛ زر التفعيل/التعطيل لا يظهر كأنه موافقة نهائية. |
| بدء جمع | modal من قائمة المصادر | `POST .../jobs` أو `.../sources/:id/jobs` | تأكيد واضح لـ `force`؛ بعد `202` الانتقال إلى job detail. |
| الوظيفة | `/external-sources/jobs/:jobId` | `GET .../jobs/:jobId` | عرض state/progress/result/error الآمن؛ إيقاف polling في terminal state. |
| إدخال URL يدوي | `/external-sources/manual` | `POST .../manual-sources` و`recheck` | HTTP(S) فقط؛ لا preview قبل إضافة endpoint رسمي؛ لا تعرض محتوى أو عنوان Onion غير مصرح. |
| آخر Export | `/external-sources/exports` | latest summary حاليًا | عرض counts وhash ووقت الإكمال؛ لا تحميل dataset الكبير في شاشة الملخص. |
| Review | `/external-sources/reviews` | latest review فقط عند توفر route مركزي | قراءة فقط في الإصدار الأول؛ approve/reject/assign مؤجلة حتى وجود عقد workflow. |
| أحداث CTI | `/events` و`/events/:id` | `/events`، STIX، MISP وفق الدور | جزء من dashboard المركزي، وليس ملكية جديدة لـ External Sources. |
| الإدارة | `/admin/users` | `/users` و`/audit` | admin فقط؛ لا تُضمّن أسرار التكامل أو service tokens. |

## 5. التكامل مع Gateway وFastAPI

### المسار الموصى به للمتصفح

```text
Browser SPA
  -> same-origin /api/v1/*
  -> central FastAPI authentication and authorization
  -> ExternalControlClient
  -> SSH tunnel/private route
  -> VPS External Sources
```

يجب أن تستخدم الواجهة المسارات المركزية التالية:

- `GET /api/v1/integrations/external-control/health`
- `GET /api/v1/integrations/external-control/sources`
- `POST /api/v1/integrations/external-control/jobs`
- `POST /api/v1/integrations/external-control/sources/{source_id}/jobs`
- `GET /api/v1/integrations/external-control/jobs/{job_id}`
- `POST /api/v1/integrations/external-control/manual-sources`
- `POST /api/v1/integrations/external-control/manual-sources/recheck`
- `GET /api/v1/integrations/external-control/exports/latest`

هذه المسارات تحول أخطاء الاتصال إلى أخطاء مركزية محدودة، ولا تعيد External control token أو المسارات المحلية. أما `/api/v1/external-sources/*` في Gateway فهو مسار داخلي محمي بالـ JWT ومخصص لطبقة proxy، وليس عنوانًا تضعه الواجهة في إعدادات عامة.

### دور proxy في Gateway

يوفر `ff72b30` allowlist لمسارات External، ويقبل JWT بأدوار `admin` و`analyst` للعمليات المتغيرة و`viewer` للقراءة، ويمرر credential الخدمة فقط إلى upstream. يجب اختبار هذا المسار من backend أو شبكة داخلية، مع إبقاء المتصفح على central API. إذا أصبح Gateway نقطة العبور المركزية مستقبلًا، يكون التغيير في إعداد central `ExternalControlClient` لا في كل شاشة.

### بيئات التشغيل

- التطوير: Vite proxy إلى FastAPI، دون وضع service token في `.env` الخاص بالواجهة.
- الاختبار/الإنتاج: نفس origin عبر reverse proxy؛ `/api/*` إلى FastAPI وملفات SPA إلى static server.
- لا تُستخدم CORS واسعة. عند اختلاف origin مؤقتًا، تُحدد allowlist صريحة للنطاقات المعروفة فقط.

## 6. JWT وإدارة الجلسة

يتوافق العميل مع العقد الحالي:

1. يرسل `POST /api/v1/auth/login` ببيانات الاعتماد عبر HTTPS.
2. يتحقق من `token_type` ووجود `access_token` و`role`، ثم يستدعي `/auth/me` عند تهيئة التطبيق.
3. يرسل `Authorization: Bearer <access_token>` لكل route محمي.
4. يراقب انتهاء JWT؛ عند `401` يمسح الجلسة ويعيد المستخدم إلى `/login` مع رسالة عامة.
5. لا يحاول العميل تجديد token من نفسه؛ يضاف refresh-token contract لاحقًا فقط إذا اعتمد backend جلسات refresh آمنة.

الأفضل في الإنتاج أن تكون الواجهة same-origin وتستخدم session cookie محمية `HttpOnly`, `Secure`, `SameSite` إذا قرر الفريق نقل إدارة الجلسة إلى BFF. عند الإبقاء على access token في SPA، لا يوضع في `localStorage`؛ يستخدم مخزن ذاكرة مع فقدان الجلسة عند إعادة التحميل أو آلية موحدة يوافق عليها فريق الأمن. لا يسجل العميل token أو كلمات المرور أو request bodies الحساسة.

## 7. الصلاحيات في الواجهة

التحكم في الواجهة لتحسين التجربة فقط، أما القرار النهائي فيبقى في backend. خريطة الإصدار الحالي:

| الدور | العرض | العمليات |
|---|---|---|
| `viewer` | dashboard، health، sources، jobs المعروفة، summaries، events | قراءة فقط |
| `analyst` | كل عرض viewer | بدء collection، تشغيل مصدر، manual source، recheck، إلغاء حسب ما يسمح به backend، عمليات التكامل المصرح بها |
| `admin` | كل العرض | إدارة المستخدمين، العمليات الإدارية، وإجراءات admin التي يفرضها backend |

يجب إخفاء الزر غير المسموح مع إبقاء route guard يعالج فتح الرابط مباشرة. لا تعرض الواجهة زر `approve` لأن `enable-requests` ليس موافقة نهائية، ولا تعرض Dark Web administration قبل وجود workflow مستقل. Dark Web يظهر كنوع وحالة آمنة فقط، دون عنوان أو مسار أو Tor configuration.

## 8. Polling وحالة الوظائف

الوظائف تعيد `202` وحالة `queued` مع `job_id`. بعد إنشاء الوظيفة:

- خزّن `job_id` في route وquery cache، ثم اطلب الحالة فورًا.
- polling افتراضي كل 2 ثانية في أول 15 ثانية، ثم كل 5 ثوانٍ حتى terminal state، مع حد أقصى زمني قابل للتهيئة مثل 10 دقائق.
- الحالات النهائية: `completed`, `partial`, `failed`, `cancelled`. أوقف polling فيها.
- حالة `cancellation_requested` تبقى قابلة للعرض ولا تعني أن الإلغاء اكتمل.
- عند توقف الشبكة، استخدم backoff محدودًا مع زر `إعادة المحاولة`، ولا تنشئ job جديدًا تلقائيًا.
- لا تعرض progress كنسبة مئوية إلا إذا كان العقد يحدد معناها؛ اعرض label آمنًا مثل `قيد التشغيل` عندما يكون `progress` فارغًا.
- لا يُبنى history أو search أو sort من cache محلي؛ `GET /jobs` وjob store دائم مطلوبان قبل شاشة تاريخ إنتاجية.

## 9. الأخطاء والحالات الطرفية

طبقة `api/` تطبع الأخطاء إلى نموذج موحد للواجهة دون كشف التفاصيل الداخلية:

- `401`: جلسة منتهية أو غير صالحة؛ مسح session وإعادة login.
- `403`: صفحة أو زر غير مصرح؛ رسالة صلاحية عامة دون كشف policy داخلية.
- `404`: مصدر أو job أو export غير موجود؛ حالة empty/not found مناسبة للسياق.
- `409`: تعارض مثل مصدر معطل أو job متزامن؛ عرض السبب الآمن وإيقاف الإرسال المتكرر.
- `422`: أخطاء إدخال الحقول؛ ربط `details.fields` بالحقول عند توفره.
- `502/503/504`: خدمة External أو Gateway غير متاحة؛ عرض degraded state مع retry يدوي ووقت آخر نجاح.
- `413`: payload أكبر من الحد؛ منع رفع أو طلب جديد وإظهار الحد العام فقط.
- JSON غير صالح أو response غير متوقع: `integration_contract_error` عام، مع تسجيل تشخيصي في backend فقط.

كل شاشة تحتاج loading skeleton، empty state، error state، وآخر وقت تحديث. يجب أن تكون عمليات POST idempotent من خلال backend؛ لا تعالج double-click بإنشاء عملية أخرى من المتصفح.

## 10. الاختبار

### اختبارات الواجهة

- TypeScript typecheck وlint وbuild.
- اختبارات وحدات لـ API client، JWT/session، permission helpers، error normalization، polling state machine، وRTL/LTR direction.
- اختبارات مكونات لحالات loading/empty/error وterminal job states.
- اختبارات Playwright لمسار login، viewer read-only، analyst start-and-poll، `401/403/422/503`، عدم تسريب token أو Onion URL في DOM/logs، والتصميم المحمول.
- اختبارات contract باستخدام OpenAPI أو fixtures versioned لمسارات FastAPI المركزية؛ لا تعتمد على خدمة Tor أو collectors الحقيقية.

### اختبارات التكامل

- Mock ExternalControlClient أو upstream Gateway مع استجابات bounded؛ تحقق أن المتصفح لا يرى service token.
- تحقق من أن Gateway يرفض المسارات غير allowlisted، لا يتبع redirects، يحد body/response، ويعيد error schema الآمن كما يغطي `tests/test_gateway_external_proxy.py`.
- اختبار end-to-end اختياري في بيئة داخلية باستخدام GET وjob mock؛ لا تُشغّل collectors أو ترسل URL حقيقيًا ضمن اختبار الواجهة.

## 11. Responsive وRTL/LTR

اللغة الافتراضية المقترحة العربية مع إمكانية English. يحدد التطبيق `dir="rtl"` للعربية و`dir="ltr"` للإنجليزية على عنصر الجذر، ويغير `lang` كذلك. يجب استخدام CSS logical properties مثل `margin-inline` و`padding-inline` و`inset-inline` بدل left/right الثابتة.

على الهاتف:

- تتحول جداول المصادر والوظائف إلى صفوف مضغوطة أو detail disclosure، دون تمرير أفقي عام إلا لجداول البيانات الضرورية.
- تبقى أزرار التشغيل والإلغاء واضحة وبحجم لمس مناسب، وتنتقل النوافذ إلى bottom sheet أو شاشة كاملة.
- لا تعتمد الحالة على اللون وحده؛ يضاف نص وأيقونة وحالة وصولية.
- لا تعرض معرفات job الطويلة كاملة في بطاقة؛ استخدم اختصارًا مرئيًا مع نسخ آمن عند الحاجة، دون تغيير القيمة المرسلة.

على سطح المكتب، يستخدم التخطيط sidebar قابلًا للطي ومحتوى بعرض مقيد، مع إبقاء الجدول قابلاً للمقارنة. الأرقام، hashes، timestamps، وsource/job IDs يمكن عرضها داخل spans ذات `dir="ltr"` حتى لا تنقلب علامات الترقيم في النص العربي. روابط ومسارات API التقنية تعرض LTR، بينما العناوين والوصف العربي RTL.

## 12. مراحل التنفيذ اللاحقة

### المرحلة A: تأسيس دون توسيع backend

إنشاء مشروع React/TypeScript، shell، login، auth store، API client، dashboard، sources read-only، latest export summary، وjob detail مع polling. الاعتماد على المسارات المركزية الموجودة فقط.

### المرحلة B: hardening وتجربة الاستخدام

إضافة permission guards، error normalization، responsive/RTL/LTR، accessibility، Playwright، وcontract fixtures. التحقق من عدم ظهور الأسرار وبيانات Dark Web الحساسة.

### المرحلة C: عقود backend المطلوبة قبل الشاشات الإدارية

إضافة `GET /jobs` دائمًا مع pagination/filtering، export history، review resource وإجراءات approve/reject/assign، manual preview، وsource workflow/audit. بعد تثبيت هذه العقود تُضاف شاشات التاريخ والمراجعة والإدارة.

### المرحلة D: نشر production

تحديد origin وreverse proxy، سياسة CORS عند الضرورة، CSP وقيود تحميل الموارد، مراقبة frontend errors دون بيانات حساسة، وربط central client بالمسار الخاص أو Gateway وفق قرار البنية التحتية. لا يُفتح External control أو Gateway للعامة.

## 13. معايير القبول للواجهة الأولى

- لا يوجد اتصال مباشر من browser إلى `127.0.0.1:8090` أو service token أو بيانات Tor الحساسة.
- login وlogout وحالة session يعملون مع `401` وJWT منتهي.
- viewer لا يستطيع تنفيذ POST حتى عند فتح route مباشرة.
- analyst يستطيع بدء job عبر central API، ويتابعها حتى terminal state، ويرى خطأ آمنًا عند الفشل.
- dashboard يعرض health وlatest export summary مع loading/empty/degraded states.
- المصادر تعرض metadata الآمنة فقط.
- التطبيق يعمل بالعربية RTL وبالإنجليزية LTR على الهاتف وسطح المكتب دون overlap أو كسر للنص.
- اختبارات unit/component/Playwright وtypecheck/build تمر باستخدام mocks، مع إبقاء الاختبارات التشغيلية الحساسة خارج المتصفح.

## 14. مصادر الحقيقة والحدود

- [تقرير جاهزية الواجهة الحالي](external_sources_frontend_readiness_ar.md): جرد المسارات والفجوات وعدم اكتمال workflow/history.
- [تقرير تسليم Dark Web/Tor](../handoffs/external_darkweb_tor_handoff_ar.md): حدود التشغيل وعدم كشف التكوينات الحساسة.
- [توثيق تشغيل External Sources](../operations/vps_external_sources.md): الخدمة loopback، والقنوات الخاصة، واستخدام الواجهة للمسارات المركزية.
- [عقد REST الداخلي](../architecture/external_sources_rest_integration.md): حالات الوظائف، idempotency، النماذج، وحدود الإنتاج.
- [اختبارات Gateway في الالتزام `ff72b30`](../../tests/test_gateway_external_proxy.py): JWT، allowlist، forwarding، الحدود، redirect، وتنقية الأخطاء.
- [FastAPI المركزي](../../backend/app/api/v1/router.py) و[أمن JWT](../../backend/app/core/security.py): مسارات المستخدم، الأدوار، وتوقيع والتحقق من access token.

هذه الوثيقة خطة فقط. لم يتم إنشاء frontend، ولم تُعدّل أي خدمة أو Gateway أو Tor أو إعداد تشغيل.