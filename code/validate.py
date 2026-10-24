"""
validate.py — Strict Output and Schema Validator for Ghost Data Still Exists.

Enforces all challenge constraints:
- Exactly 518 rows, sorted by case_id.
- Header: case_id,deletion_status,steps_json.
- Permitted statuses: COMPLETE, INCOMPLETE, NOT_APPLICABLE.
- Exactly 7 fields per step: step_no, phase, system_id, resource_id, operation, state, evidence_id.
- Consecutive step numbering starting from 1.
- Ordering: FINDING -> REMEDIATION -> VERIFICATION.
- NOT_APPLICABLE must have steps_json = [].
- COMPLETE must contain only evidence-backed VERIFICATION.
- INCOMPLETE must contain FINDING, REMEDIATION, and future VERIFICATION (with empty evidence_id).
- Cites only valid participant-visible evidence identifiers.
"""

import csv
import json
import os
import sys
from typing import Dict, List, Set, Tuple

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(ROOT_DIR, "dataset")

PERMITTED_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}

PERMITTED_OPERATIONS = {
    "FINDING": {
        "REPORT_REMAINING_RECORD": "PRESENT",
        "REPORT_EXPOSED_PII": "PRESENT",
        "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
        "REPORT_RESTORE_RISK": "ACTIVE",
    },
    "REMEDIATION": {
        "DISABLE_DATA_FLOW": "DISABLED",
        "BLOCK_RESTORE": "BLOCKED",
        "DELETE_RECORD": "ABSENT",
        "REDACT_RECORD": "REDACTED",
        "ANONYMIZE_RECORD": "ANONYMIZED",
    },
    "VERIFICATION": {
        "VERIFY_RECORD_ABSENT": "ABSENT",
        "VERIFY_RECORD_PRESENT": "PRESENT",
        "VERIFY_RECORD_REDACTED": "REDACTED",
        "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
        "VERIFY_RESTORE_BLOCKED": "BLOCKED",
    },
}

REQUIRED_STEP_KEYS = {
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
}


def load_valid_evidence_ids() -> Set[str]:
    manifest_path = os.path.join(DATASET_DIR, "evidence_files.csv")
    valid = set()
    if os.path.exists(manifest_path):
        with open(manifest_path, "r", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                valid.add(r["file_id"])
    return valid


def validate_output_file(output_path: str, expected_cases_file: str = "deletion_requests.csv") -> Tuple[bool, List[str]]:
    """Validate output.csv against all challenge specifications."""
    errors = []

    if not os.path.exists(output_path):
        return False, [f"File not found: {output_path}"]

    valid_evidence_ids = load_valid_evidence_ids()

    # Load expected case IDs
    expected_path = os.path.join(DATASET_DIR, expected_cases_file)
    with open(expected_path, "r", encoding="utf-8") as f:
        expected_case_ids = [r["case_id"] for r in csv.DictReader(f)]

    with open(output_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader, None)

        if header != ["case_id", "deletion_status", "steps_json"]:
            errors.append(f"Invalid header: {header}. Expected: ['case_id', 'deletion_status', 'steps_json']")

        rows = list(reader)

    if len(rows) != len(expected_case_ids):
        errors.append(f"Row count mismatch: got {len(rows)}, expected {len(expected_case_ids)}")

    observed_case_ids = [r[0] for r in rows if r]
    if observed_case_ids != sorted(observed_case_ids):
        errors.append("Rows are not sorted by case_id")

    if observed_case_ids != expected_case_ids:
        missing = set(expected_case_ids) - set(observed_case_ids)
        extra = set(observed_case_ids) - set(expected_case_ids)
        if missing:
            errors.append(f"Missing case IDs: {list(missing)[:5]}")
        if extra:
            errors.append(f"Extra case IDs: {list(extra)[:5]}")

    for idx, row in enumerate(rows, start=1):
        if len(row) != 3:
            errors.append(f"Row {idx} has {len(row)} columns, expected 3")
            continue

        cid, status, steps_raw = row

        if status not in PERMITTED_STATUSES:
            errors.append(f"Row {idx} ({cid}): invalid deletion_status '{status}'")

        try:
            steps = json.loads(steps_raw)
        except Exception as e:
            errors.append(f"Row {idx} ({cid}): steps_json failed to parse: {e}")
            continue

        if not isinstance(steps, list):
            errors.append(f"Row {idx} ({cid}): steps_json must be a JSON array")
            continue

        if status == "NOT_APPLICABLE":
            if len(steps) != 0:
                errors.append(f"Row {idx} ({cid}): NOT_APPLICABLE must have empty steps_json, got {len(steps)} steps")
            continue

        if status == "COMPLETE":
            for s in steps:
                if s.get("phase") != "VERIFICATION":
                    errors.append(f"Row {idx} ({cid}): COMPLETE cases must contain only VERIFICATION steps, found {s.get('phase')}")
                if not s.get("evidence_id"):
                    errors.append(f"Row {idx} ({cid}): COMPLETE verification step missing evidence_id")

        if status == "INCOMPLETE":
            phases_in_steps = [s.get("phase") for s in steps]
            has_finding = "FINDING" in phases_in_steps
            has_remediation = "REMEDIATION" in phases_in_steps
            has_verification = "VERIFICATION" in phases_in_steps
            if not (has_finding and has_remediation and has_verification):
                errors.append(f"Row {idx} ({cid}): INCOMPLETE must contain FINDING, REMEDIATION, and VERIFICATION phases")

        prev_phase_rank = 0
        phase_ranks = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}

        for s_idx, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                errors.append(f"Row {idx} ({cid}) step {s_idx}: step must be an object")
                continue

            if set(step.keys()) != REQUIRED_STEP_KEYS:
                errors.append(f"Row {idx} ({cid}) step {s_idx}: keys mismatch. Got {set(step.keys())}, expected {REQUIRED_STEP_KEYS}")

            if step.get("step_no") != s_idx:
                errors.append(f"Row {idx} ({cid}) step {s_idx}: step_no must be {s_idx}, got {step.get('step_no')}")

            phase = step.get("phase")
            op = step.get("operation")
            st = step.get("state")
            evi = step.get("evidence_id")

            if phase not in PERMITTED_OPERATIONS:
                errors.append(f"Row {idx} ({cid}) step {s_idx}: invalid phase '{phase}'")
                continue

            # Phase order check
            curr_rank = phase_ranks.get(phase, 99)
            if curr_rank < prev_phase_rank:
                errors.append(f"Row {idx} ({cid}) step {s_idx}: phase out of order ({phase} after higher phase)")
            prev_phase_rank = curr_rank

            allowed_ops = PERMITTED_OPERATIONS[phase]
            if op not in allowed_ops:
                errors.append(f"Row {idx} ({cid}) step {s_idx}: invalid operation '{op}' for phase '{phase}'")
            elif allowed_ops[op] != st:
                errors.append(f"Row {idx} ({cid}) step {s_idx}: operation '{op}' requires state '{allowed_ops[op]}', got '{st}'")

            # Evidence ID checks
            if phase == "FINDING":
                if not evi or evi not in valid_evidence_ids:
                    errors.append(f"Row {idx} ({cid}) step {s_idx}: finding requires valid participant-visible evidence_id, got '{evi}'")
            elif phase == "REMEDIATION":
                if evi != "":
                    errors.append(f"Row {idx} ({cid}) step {s_idx}: remediation evidence_id must be empty string, got '{evi}'")
            elif phase == "VERIFICATION":
                if status == "INCOMPLETE" and evi != "":
                    errors.append(f"Row {idx} ({cid}) step {s_idx}: post-remediation verification evidence_id must be empty string, got '{evi}'")
                elif status == "COMPLETE" and (not evi or evi not in valid_evidence_ids):
                    errors.append(f"Row {idx} ({cid}) step {s_idx}: COMPLETE verification requires valid evidence_id, got '{evi}'")

    is_valid = len(errors) == 0
    return is_valid, errors


if __name__ == "__main__":
    out_file = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT_DIR, "output.csv")
    valid, errs = validate_output_file(out_file)
    if valid:
        print(f"VALIDATION PASSED! {out_file} strictly conforms to all challenge contracts.")
    else:
        print(f"VALIDATION FAILED with {len(errs)} errors:")
        for e in errs[:20]:
            print(f"  - {e}")
        sys.exit(1)
