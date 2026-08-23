# External Sources relevance-classification integration

Phase 6 uses the approved immutable model at
`backend/app/pipeline/ingestion/external/classification/model/cti_svm_model.pkl`.
Its SHA-256 is
`0e929dfebd36c46498047a6f93d3b5d08ba9aad81d48f8f3f68070c6e21d7d8c`,
which matches the preserved prototype artifact exactly.

The canonical runtime does not import `src.classification`. Before inference it
reproduces the prototype's documented training path in this order:

1. Replace `CVE-YYYY-NNNN...` values with `specifiedcve`.
2. Replace IPv4-shaped values with `specifiedip`.
3. Lowercase the complete text.

The serialized pipeline contains TF-IDF and LinearSVC stages. Label `1` maps to
`cti_related`; label `0` maps to `not_cti_related`. LinearSVC does not expose a
calibrated probability, so the exported score remains null rather than treating
its decision margin as a probability.

Empty and inputs shorter than 80 stripped characters are not sent to the model
and are routed to review with `not_run`. Missing models, hash mismatches, load
failures, unknown labels, and prediction failures are routed to review with
`error`. They are never silently accepted or discarded.

Classification applies only to general-purpose sources. RSS, CERT, NVD/CVE,
GitHub Global Security Advisories, CISA KEV, and merged official vulnerability
records use the trusted-source bypass.

## Tested compatibility

Phase 6 was verified with Python 3.14.3, scikit-learn 1.9.0, joblib 1.5.3,
and NumPy 2.5.1. Loading the approved artifact currently emits a joblib/NumPy
2.5 deprecation warning about assigning an array's `shape`. This is tracked as
a compatibility item; the approved model must not be modified or retrained
solely to suppress the warning.
