"""
main.py — Primary Entry Point for Ghost Data Still Exists Deletion Audit Agent.

Executes the complete audit pipeline:
1. Ingests and indexes all evidence files and manifests.
2. Resolves current and historical user identities.
3. Classifies request intent (deletion authorization).
4. Reconstructs temporal state at audit cutoff (audit_at).
5. Enforces deletion policy rules.
6. Generates, orders, and formats compliant prediction steps.
7. Serializes output to root output.csv.
8. Validates output strictly against challenge contracts.

Usage:
    python code/main.py
"""

import csv
import json
import os
import sys
import time
from typing import Optional

# Ensure code directory is on sys.path
CODE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CODE_DIR)
sys.path.insert(0, CODE_DIR)
sys.path.insert(0, ROOT_DIR)

from ingest import parse_all_evidence, EvidenceCatalog
from identity import IdentityResolver
from policy import PolicyEngine
from audit import AuditEngine
from validate import validate_output_file
from ai_review import AIReviewer


def run_full_pipeline(input_filename: str = "deletion_requests.csv", output_path: Optional[str] = None) -> str:
    start_time = time.time()
    print("=" * 80)
    print("GHOST DATA STILL EXISTS — DELETION AUDIT AGENT")
    print("=" * 80)

    dataset_dir = os.path.join(ROOT_DIR, "dataset")
    input_path = os.path.join(dataset_dir, input_filename)

    if not output_path:
        output_path = os.path.join(ROOT_DIR, "output.csv")

    print(f"Reading target evaluation requests from: {input_path}")
    print(f"Final prediction target: {output_path}")

    # 1. Ingestion & Evidence Parsing
    t0 = time.time()
    catalog = parse_all_evidence(use_cache=True)
    print(f"Evidence catalog ready in {time.time() - t0:.2f}s ({len(catalog.observations)} observations).")

    # 2. Identity Resolution
    t0 = time.time()
    resolver = IdentityResolver()
    print(f"Identity resolver ready in {time.time() - t0:.2f}s ({len(resolver.by_user_id)} subjects resolved).")

    # 3. Policy Engine
    policy = PolicyEngine()
    print(f"Policy engine loaded {len(policy.rules)} policy categories.")

    # 4. Audit Engine
    engine = AuditEngine(catalog, resolver, policy)
    reviewer = AIReviewer()
    if reviewer.enabled:
        print(f"Optional AI review enabled: {reviewer.provider}")

    # 5. Process Requests
    with open(input_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        requests = list(reader)

    print(f"\nProcessing {len(requests)} deletion audit cases...")
    predictions = []
    status_counts = {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0}

    for idx, req in enumerate(requests, start=1):
        cid = req.get("case_id", "")
        status, steps = engine.audit_case(req)
        status, steps = reviewer.review(req, status, steps, [])

        status_counts[status] = status_counts.get(status, 0) + 1
        steps_json = json.dumps(steps, separators=(",", ":"))

        predictions.append({
            "case_id": cid,
            "deletion_status": status,
            "steps_json": steps_json,
        })

        if idx % 100 == 0 or idx == len(requests):
            print(f"  Processed {idx}/{len(requests)} cases...")

    # Sort strictly by case_id
    predictions.sort(key=lambda x: x["case_id"])

    # 6. Write output.csv
    print(f"\nWriting {len(predictions)} prediction rows to: {output_path}")
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        for p in predictions:
            writer.writerow([p["case_id"], p["deletion_status"], p["steps_json"]])

    # 7. Validate output.csv
    print("\nRunning strict output validation...")
    is_valid, errors = validate_output_file(output_path, expected_cases_file=input_filename)
    if is_valid:
        print(">>> SUCCESS: Output file passed all contract validation checks! <<<")
    else:
        print(f">>> ERROR: Validation failed with {len(errors)} errors: <<<")
        for err in errors[:10]:
            print(f"  - {err}")
        sys.exit(1)

    elapsed = time.time() - start_time
    print("\n" + "=" * 80)
    print("PIPELINE EXECUTION SUMMARY")
    print("=" * 80)
    print(f"Total Cases Processed: {len(predictions)}")
    print(f"Status Distribution:   {status_counts}")
    print(f"Output File Location:  {output_path}")
    print(f"Total Execution Time:  {elapsed:.2f} seconds")
    if reviewer.enabled:
        print(f"AI review calls:       {reviewer.calls} (fallbacks: {reviewer.failures})")
    print("=" * 80)

    return output_path


if __name__ == "__main__":
    run_full_pipeline()
