# تدقيق جودة نتائج CTI في PostgreSQL

تاريخ التدقيق: 2026-09-03

النطاق: نتائج External وInternal المخزنة، IoCs/Observables، كيانات DNRTI BERT، والعلاقات المستخرجة.
المنهج: استعلامات تجميعية حية، عينات سياقية محدودة، مقارنة الكود الحالي بتقرير OpenCTI، ثم Preview ونسخة احتياطية وتطبيق وإعادة Preview لإثبات عدم التكرار.

## الخلاصة

أثبت التدقيق أن بطء BERT ليس أخطر مشكلة في جودة النتائج. القاعدة كانت تحتوي على تضخيم دلالي في العلاقات، وخلط بين العثور على قيمة تقنية وبين إثبات أنها Indicator خبيث. كما ظهرت فئات NER ضعيفة أو عامة لا تصلح تلقائيًا كعقد في رسم CTI البياني.

قاعدة البيانات لا تحتوي Ground Truth بشريًا للوثائق الحية، لذلك لا يمكن استخراج Precision وRecall علميين منها وحدها. الأرقام أدناه تقيس الاتساق، التغطية، ومؤشرات الخطأ. مقاييس الدقة العلمية ما زالت تتطلب مجموعة حية موسومة يدويًا.

## الحالة قبل التصحيح

| القياس | القيمة |
|---|---:|
| Threat events | 9,914 |
| External events | 9,895 |
| Internal events | 19 |
| Technical values في جدول `indicators` | 11,465 |
| DNRTI entities | 41,501 من أصل 41,520 كيانًا |
| العلاقات | 74,192 |
| العلاقات القاعدية External | 74,173 |
| Enrichments | 0 |
| Correlations | 9 |

كل القيم التقنية المستخرجة بالـRegex كانت تحمل `confidence=1.0`. هذه القيمة تعني يقين المطابقة الشكلية فقط، لكنها كانت تنتقل إلى STIX كـ`malicious-activity` وإلى MISP مع `to_ids=true`، وهو استنتاج غير مدعوم.

كان توزيع العلاقات القاعدية:

| النوع | قبل التصحيح |
|---|---:|
| MENTIONS | 40,836 |
| EXPLOITS | 17,043 |
| TARGETS | 7,749 |
| USES | 8,545 |

كان المحرك يبحث عن كلمة مثل `used` في الوثيقة كلها ثم يربط جميع Actors بجميع Tools. أعلى وثيقة أنشأت 5,219 علاقة، و43 وثيقة أنشأت 50 علاقة دلالية أو أكثر. بلغ متوسط طول النصوص التي أنتجت علاقات دلالية 21,705 حرفًا، ما يؤكد أن العلاقة لم تكن محلية سياقيًا.

## ملاحظات NER الحية

أظهرت القيم الأكثر تكرارًا عقدًا عامة أو أنواعًا خاطئة، مثل:

- `attacker` و`attackers` كـThreat Actors بدل أسماء مجموعات محددة.
- `CVSS` و`CVE` و`CVEQL` كـExploits.
- أسماء منتجات وكلمات مثل `WordPress` و`file` و`MEDIUM` كـSample Files.
- `attack` و`attacks` و`campaign` كـAttack Methods.

تقرير الاختبار النظيف يدعم هذا التحفظ: Precision لنوع `SamFile` كان 0.1905 فقط، بينما `Features` و`Purp` لا يملكان دعمًا في مجموعة الاختبار النظيفة. لذلك لم تُحذف النتائج القديمة آليًا. جرى فقط تعليم 20,504 كيانًا في تقرير الصيانة على أنها تحتاج مراجعة، ومنعها من إنشاء علاقات جديدة. سياسة Runtime تمنع الأمثلة الشكلية أو العامة الواضحة مستقبلًا.

## المقارنة مع المرجع وOpenCTI

الورقة **AI-based Holistic Framework for Cyber Threat Intelligence Management** تفصل دورة العمل إلى جمع، تصنيف، استخراج IoCs/IoAs، تخزين، correlation، ثم مشاركة. كما تفرق بين simple exact-value correlation وadvanced document similarity. هذا لا يبرر إنشاء علاقات دلالية من كلمة موجودة في أي مكان داخل وثيقة طويلة.

طبقًا لوثائق OpenCTI، الـObservable قيمة خام ثابتة لا تثبت الخبث، بينما الـIndicator كائن كشف له Pattern وسياق ومدة صلاحية. كما يفصل OpenCTI موثوقية المصدر عن ثقة المعلومة. لذلك اعتمد المشروع الآن السلوك التالي مع الإبقاء على أسماء الجداول القديمة للتوافق:

- القيم التقنية المستخرجة تظهر في API مع `semantic_role=observable`.
- STIX يصدر SCOs مثل `ipv4-addr` و`domain-name` و`file` بدل Indicator من نوع `malicious-activity`.
- معرفات STIX SCO تستخدم UUIDv5 حتميًا من الخصائص المساهمة، فتندمج القيمة نفسها عند تكرار التصدير بدل إنشاء Observable مكرر.
- MISP يستقبل القيم المستخرجة مع `to_ids=false` وتعليق صريح بأن الخبث غير مثبت.
- إنشاء Indicator قابل للكشف سيحتاج لاحقًا enrichment أو ثقة مصدر أو اعتماد محلل وسياسة عمر/انتهاء.

مراجع أساسية:

- الورقة: https://doi.org/10.1109/ACCESS.2025.3533084
- OpenCTI Observables and Indicators: https://docs.opencti.io/latest/usage/exploring-observations/
- OpenCTI Reliability and Confidence: https://docs.opencti.io/latest/usage/reliability-confidence/
- OpenCTI Indicator Lifecycle: https://docs.opencti.io/latest/usage/indicators-lifecycle/
- OASIS STIX 2.1 identifier rules: https://docs.oasis-open.org/cti/stix/v2.1/cs03/stix-v2.1-cs03.html

## التغييرات المطبقة

1. إضافة Refang محافظ على نسخة استخراج فقط؛ النص الأصلي والمطبع لا يتغيران.
2. إضافة IPv6 وASN وMAC والتحقق منها قبل الحفظ.
3. إبقاء الـTLD allowlist حاليًا لتجنب توسيع false positives من أسماء الملفات؛ يحتاج تحسينه إلى Public Suffix parser واختبارات مستقلة.
4. تقييد USES وTARGETS وEXPLOITS على نفس الجملة ونفس أنواع Subject/Object، مع حد أعلى للأزواج.
5. فلترة عقد NER العامة واشتراط شكل ملف حقيقي لـ`sample_file` في النتائج المستقبلية.
6. إضافة خدمة Backfill لها Preview افتراضي و`--apply` صريح، ولا تعيد BERT أو التصنيف.
7. إنشاء نسخة PostgreSQL بصيغة Custom قبل التطبيق وتخزينها في مجلد محلي مستبعد من Git.
8. تسجيل عملية التطبيق في `audit_logs` باسم `apply_cti_quality_backfill`.

## الحالة بعد التصحيح

| القياس | بعد التصحيح | الفرق |
|---|---:|---:|
| Technical observables | 12,010 | +545 |
| Rule-based relationships | 21,462 | -52,711 (-71.06%) |
| كل العلاقات مع Internal | 21,481 | -52,711 |
| DNRTI entities | 41,520 | 0 محذوف |
| Structured internal relationships | 19 | محفوظة بالكامل |

التغطية الجديدة أضافت 340 ظهور IPv6، و85 URL، و66 Domain، و29 IPv4 مفككًا أو غير موجود سابقًا، و3 ASN، وMAC واحدًا، إضافة إلى قيم أخرى ظهرت بعد التطبيع المحافظ.

العلاقات الدلالية القاعدية أصبحت:

| النوع | بعد التصحيح |
|---|---:|
| EXPLOITS | 326 |
| TARGETS | 210 |
| USES | 187 |

أقصى عدد علاقات دلالية في الحدث انخفض من 4,990 إلى 46، ولا يوجد حدث ينتج 50 علاقة دلالية أو أكثر. أعادت المعاينة بعد التطبيق: `events_changed=0` و`observables_added=0` و`rule_relationship_reduction=0`، ما يثبت Idempotence للنتيجة الحالية.

## ما لم يثبت بعد

- لا ندعي أن 20,504 كيانًا كلها خاطئة؛ هي قائمة مراجعة محافظة وليست حذفًا.
- لا توجد عينة حية موسومة يدويًا تكفي لحساب Precision/Recall لكل مصدر ولكل نوع.
- القيم التقنية الجديدة صحيحة نحويًا، لكن الخبث والسياق يحتاجان Enrichment أو اعتماد محلل.
- لا يوجد بعد Source reliability score أو Indicator decay/revocation مثل OpenCTI.
- تقرير OpenCTI المرفق راجع Commit أقدم؛ تم التحقق من الملاحظات الحرجة مقابل الكود الحالي قبل التعديل.

## الخطوة العلمية التالية

اختيار عينة طبقية من 300 إلى 500 وثيقة حية بحسب المصدر والنوع، ثم وسم الكيانات والعلاقات والـObservable/Indicator status بواسطة محللين اثنين وقياس اتفاقهما. بعد ذلك يمكن حساب Precision وRecall وF1 حقيقية، وضبط Thresholds حسب النوع، وبناء قاموس أسماء/Aliases مشابه لـOpenCTI بدل الاعتماد على BERT وحده.
