# Evaluation Report

## Public benchmark

The public benchmark contains 32 requests and was run with:

```text
python code/evaluation/main.py
```

| Metric | Before | After |
| --- | ---: | ---: |
| Requests processed | 32 | 32 |
| Deletion-status accuracy | 32/32 (100.0%) | 32/32 (100.0%) |
| Exact step-sequence accuracy | 10/32 (31.2%) | 14/32 (43.8%) |
| Step precision | 157/168 (93.5%) | 161/167 (96.4%) |
| Step recall | 157/193 (81.3%) | 161/193 (83.4%) |
| Step F1 | 87.0% | 89.4% |

The benchmark also includes four independent fixtures. All four passed before
and after the changes:

1. Historical identifier resolution and a remaining search record.
2. Retained security audit data and an account tombstone with redacted direct identifiers.
3. Active data-flow resurrection risk and ordered flow disablement.
4. A non-deletion access request classified as `NOT_APPLICABLE`.

## Root-cause analysis

The 22 baseline mismatches were classified from the actual expected and
predicted step tuples:

- 15 cases had missing steps only.
- 6 cases had both missing and extra steps.
- 1 case had extra steps only.
- No status mismatches or evaluator/serialization defects were found.

The largest confirmed producer defects were:

1. Shared image/OCR observations linked multiple users to one resource. The
   resource-snapshot expansion then pulled a different user's active connector
   into the case. Subject linking now requires a non-shared direct observation
   before same-resource snapshots are expanded.
2. Audit records extracted from account-service snapshots were emitted with
   `account_service` instead of the policy/system identity `security_service`.
3. Structured security logs used `subject_ref`, which the parser did not
   recognize. Trace correlation therefore produced identifier-free audit
   observations and missed valid retained-record verification steps.
4. Support replica records with no message category or exposed identifier were
   treated as PII-redaction cases. The policy now distinguishes explicit PII
   signals from an unmarked remaining record.

The public evaluator was unchanged. The remaining sequence mismatches were
reviewed during development without changing the evaluator or its scoring
rules.

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
- Verified shared visual contamination, audit-system normalization,
  `subject_ref` trace correlation, and support replica policy during
  development.

## Known limitations

The implementation intentionally remains deterministic and evidence-backed. It
does not invent missing resources or outsource decisions to a remote model. The
remaining step-level misses are primarily workflow-only cases where participant
evidence does not expose a direct identifier for an absent account or compliant
downstream resource. These cannot be safely inferred without risking decoy
resources and lowering precision.
