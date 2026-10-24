# Evaluation Report

## Public benchmark

The public benchmark contains 32 requests and was run with:

```text
python code/evaluation/main.py
```

| Metric | Result |
| --- | ---: |
| Deletion-status accuracy | 32/32 (100.0%) |
| Exact step-sequence accuracy | 10/32 (31.2%) |
| Step precision | 157/168 (93.5%) |
| Step recall | 157/193 (81.3%) |
| Step F1 | 87.0% |

The benchmark also includes four independent fixtures. All four passed:

1. Historical identifier resolution and a remaining search record.
2. Retained security audit data and an account tombstone with redacted direct identifiers.
3. Active data-flow resurrection risk and ordered flow disablement.
4. A non-deletion access request classified as `NOT_APPLICABLE`.

## Full dataset validation

The full run processed all 518 requests and produced 518 sorted output rows. The strict validator passed the generated root `output.csv` with the required header, statuses, JSON step schema, evidence constraints, phase ordering, and consecutive step numbers.

## Improvements made

- Added parser cache versioning so parser changes cannot reuse stale evidence.
- Expanded identifier matches to include all time-valid observations for the matched resource, including compliant and absent snapshots without direct identifiers.
- Extracted identifiers from nested JSON documents.
- Normalized support and analytics service aliases in structured logs.
- Corrected log-state interpretation for active restore candidates, redacted support records, and anonymized analytics profiles.
- Used evidence-declared categories and structured event semantics when choosing deletion versus redaction or anonymization.
- Classified support attachments from participant-visible document origins and recognized audit records by their integrity metadata even when stored in an account-service snapshot.
- Ignored shared visual evidence when it contained identifiers for unrelated subjects, preventing cross-user connector false positives.
- Added temporal workflow-resource fallback for account records absent from the latest account snapshot.
- Expanded deletion intent detection to include deletion-audit wording while retaining explicit non-deletion safeguards.

## Known limitations

The implementation intentionally remains deterministic and evidence-backed. It does not invent missing resources or outsource decisions to a remote model. The remaining step-level misses are primarily cases where participant evidence does not expose a direct identifier for an absent or compliant resource.
