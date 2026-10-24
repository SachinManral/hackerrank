# Repository Review — Ghost Data Still Exists

Reviewed repository: https://github.com/SachinManral/hackerrank
Branch: main
Reviewed HEAD: 85050155320d2791e4debdf7a9f3d8ff9953d676

## Summary

The repository contains a deterministic Python pipeline, evidence ingestion and caching, identity resolution, deletion-policy mapping, an audit planner, strict output validation, a public benchmark runner, the expected reports, the root `output.csv`, and the root `log.txt`.

The README states that runtime Gemini/Groq calls are not required. The usage report records zero runtime model calls and zero token usage. This is a defensible design for reproducibility and cost, but the evidence pipeline still needs to demonstrate stronger step-level accuracy.

## Measured results reported by the repository

These figures are quoted from `code/evaluation/evaluation_report.md`; this review did not execute the repository in the user's local environment.

- Status accuracy: 32/32 (100.0%)
- Exact step-sequence accuracy: 10/32 (31.2%)
- Step precision: 157/168 (93.5%)
- Step recall: 157/193 (81.3%)
- Step F1: 87.0%
- Independent fixtures: 4/4 passed
- Full output: 518 rows, reported as validated

## High-priority findings

### 1. Resource grouping drops the system dimension

In `code/audit.py`, observations are grouped by `resource_id` alone:

```python
res_to_obs.setdefault(obs.resource_id, []).append(obs)
```

The state store and policy analysis also key by resource ID only. If the same resource identifier appears in two systems, observations can be conflated. Prefer a composite key such as `(system_id, resource_id)`, while keeping resource linkage and downstream references consistent. Add a fixture with the same resource ID in two systems and different states before changing this logic.

### 2. No evidence can become a COMPLETE verdict

The current branch sets `COMPLETE` whenever no findings are generated. If the identity bundle matches no evidence and no deletion-worker fallback supplies a resource, `findings` is empty, so the case becomes COMPLETE with no verification steps. The rules define COMPLETE as requiring evidence-backed verification, and absence of evidence is not evidence of deletion.

Add an explicit resolution/completeness gate. Cases with an authorized deletion but no credible evidence of the primary account or relevant resources must not be silently called COMPLETE. The exact fallback must conform to the challenge's available output statuses and public sample behavior; add tests before changing it.

### 3. Historical identity values are not time-bounded

`IdentityResolver` collects all old/new values from `user_audit_log.csv` into one bundle without applying each audit event's `event_time` to the requested cutoff. This risks using identifiers that were only associated with the person after the case's `audit_at`. Build timestamp-aware identity observations and resolve the identity state at the relevant time, while still searching earlier identifiers that could remain in old records.

### 4. Workflow-resource fallback uses a narrow time-window heuristic

`_workflow_resource_candidates` joins activity to `reported_at` by absolute time distance within 15 minutes and does not establish subject identity from the activity row itself. It may pick a nearby unrelated deletion-worker resource. Use event details and resolved identifiers to validate the relationship, make matching deterministic, and test decoy events around the same timestamp.

### 5. The policy CSV is loaded but not fully authoritative

`PolicyEngine._load` loads the rules, but most decisions are based on inferred category and hardcoded branches. Conditions such as active legal holds, retention periods, shared support context, attachment ownership, and tombstone field-level redaction require explicit condition evaluation. Make the CSV policy meaning drive behavior; resource-name heuristics should only be a fallback when evidence lacks a declared category.

### 6. Evidence state parsing requires conservative treatment

Some parsers use broad defaults like `PRESENT`, and several parsing functions catch exceptions and return without recording extraction failures. This is risky for data types such as shared support messages, attachments, analytics profiles, and logs. Keep ingestion error diagnostics and ensure unknown/unparsed state is not silently treated as absence or compliance.

### 7. Audit ordering has a special case that conflicts with the written tie-breaker

`get_step_order_key` gives account-service `VERIFY_RECORD_ABSENT` steps special priority before other systems, despite the problem contract specifying operation order followed by ascending `system_id` and `resource_id`. Remove special-case ordering unless a public sample or explicit official dependency proves it is required. Add a test that verifies ordering across systems.

### 8. Evaluator's step precision/recall omits evidence IDs

The evaluator matches step tuples using phase, operation, system ID, resource ID, and state, but excludes `evidence_id`. Thus it can count a step as correct even when its evidence citation is wrong. Keep that metric if useful, but label it as semantic step matching and add exact full-field matching and per-field accuracy that includes evidence IDs and sequence order.

### 9. Validator only accepts file IDs for citations

`validate.py` builds valid evidence IDs from `evidence_files.csv` only. The contract says finding and complete verification evidence may use a `file_id`, `activity_id`, or `audit_id`. Extend validation to include actual participant-facing IDs from `system_activity.csv` and `user_audit_log.csv`, plus file IDs from the manifest. Do not accept arbitrary fabricated identifiers.

### 10. Dataset ingestion and cache handling

The cache checks a parser version but not evidence file modification times or content hashes. A changed corpus may reuse stale parsed observations. Use a manifest/file fingerprint and parser version in the cache key. Also report missing evidence files and parser failures in a structured diagnostic.

## Recommended order of work

1. Add regression tests for the findings above without changing the official sample files.
2. Fix identifier/resource keys and temporal state resolution.
3. Make policy-condition evaluation explicit and evidence-driven.
4. Improve workflow-event linkage and no-evidence behavior.
5. Correct ordering and citation validation.
6. Improve evaluator metrics to include all step fields.
7. Rerun public benchmark and independent fixtures after each substantial change.
8. Regenerate all 518 target rows only after benchmark and validation pass.
9. Update reports with actual measured results and package a clean `code.zip`.
10. Keep Gemini/Groq optional; introduce API calls only if targeted experiments show a measured improvement on evidence interpretation that cannot be achieved reliably through parsing.

## Important caveats

- This is a source review based on the public GitHub files, not a local execution or hidden-set evaluation.
- Public sample metrics do not establish hidden-set accuracy.
- No changes were made to the repository during this review.
- Do not alter the authoritative append-only `log.txt` by reconstructing or paraphrasing historical entries.
