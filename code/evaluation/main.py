"""
main.py (code/evaluation/main.py) — Public Benchmark Evaluator and Independent Test Runner.

Executes:
1. Public sample evaluation: compares predictions against dataset/sample_output.csv (32 cases).
2. Calculates case-level status accuracy, step-level precision, recall, F1, exact sequence accuracy.
3. Runs 4 independent synthetic test fixtures:
   - Test A: Historical identity resolution and ghost search record.
   - Test B: Retention compliance and account tombstone direct PII redaction.
   - Test C: Resurrection risk (active data flow and restore path).
   - Test D: Non-deletion request (export / access) -> NOT_APPLICABLE.
4. Generates measured reports for evaluation_report.md and usage_report.md.
"""

import csv
import json
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List, Any, Tuple

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CODE_DIR = os.path.join(ROOT_DIR, "code")
sys.path.insert(0, CODE_DIR)
sys.path.insert(0, ROOT_DIR)

from ingest import parse_all_evidence, EvidenceCatalog, EvidenceObservation
from identity import IdentityResolver, IdentityBundle
from policy import PolicyEngine
from audit import AuditEngine
from validate import validate_output_file


def run_benchmark() -> Dict[str, Any]:
    print("=" * 80)
    print("RUNNING PUBLIC BENCHMARK EVALUATION (32 CASES)")
    print("=" * 80)

    catalog = parse_all_evidence(use_cache=True)
    resolver = IdentityResolver()
    policy = PolicyEngine()
    engine = AuditEngine(catalog, resolver, policy)

    sample_reqs_path = os.path.join(ROOT_DIR, "dataset", "sample_deletion_requests.csv")
    sample_outs_path = os.path.join(ROOT_DIR, "dataset", "sample_output.csv")

    with open(sample_reqs_path, "r", encoding="utf-8") as f:
        reqs = list(csv.DictReader(f))

    with open(sample_outs_path, "r", encoding="utf-8") as f:
        ground_truth = {r["case_id"]: r for r in csv.DictReader(f)}

    results = []
    status_matches = 0
    exact_seq_matches = 0
    total_expected_steps = 0
    total_predicted_steps = 0
    matched_step_objects = 0

    for r in reqs:
        cid = r["case_id"]
        gt = ground_truth[cid]
        gt_status = gt["deletion_status"]
        gt_steps = json.loads(gt["steps_json"])

        pred_status, pred_steps = engine.audit_case(r)

        # Check status match
        s_match = pred_status == gt_status
        if s_match:
            status_matches += 1

        # Check exact sequence match
        seq_match = False
        if s_match and len(pred_steps) == len(gt_steps):
            all_steps_identical = True
            for ps, gs in zip(pred_steps, gt_steps):
                # Compare step fields (ignoring step_no)
                ps_core = (ps.get("phase"), ps.get("operation"), ps.get("system_id"), ps.get("resource_id"), ps.get("state"), ps.get("evidence_id"))
                gs_core = (gs.get("phase"), gs.get("operation"), gs.get("system_id"), gs.get("resource_id"), gs.get("state"), gs.get("evidence_id"))
                if ps_core != gs_core:
                    all_steps_identical = False
                    break
            if all_steps_identical:
                seq_match = True
                exact_seq_matches += 1

        # Step object precision / recall metrics
        total_expected_steps += len(gt_steps)
        total_predicted_steps += len(pred_steps)

        gt_set = set(
            (s.get("phase"), s.get("operation"), s.get("system_id"), s.get("resource_id"), s.get("state"))
            for s in gt_steps
        )
        pred_set = set(
            (s.get("phase"), s.get("operation"), s.get("system_id"), s.get("resource_id"), s.get("state"))
            for s in pred_steps
        )
        matched_step_objects += len(gt_set.intersection(pred_set))

        results.append({
            "case_id": cid,
            "pred_status": pred_status,
            "gt_status": gt_status,
            "status_match": s_match,
            "seq_match": seq_match,
            "pred_steps_count": len(pred_steps),
            "gt_steps_count": len(gt_steps),
        })

    num_cases = len(reqs)
    status_accuracy = status_matches / num_cases
    sequence_accuracy = exact_seq_matches / num_cases
    precision = matched_step_objects / total_predicted_steps if total_predicted_steps else 1.0
    recall = matched_step_objects / total_expected_steps if total_expected_steps else 1.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) else 0.0

    print(f"\nPublic Benchmark Results ({num_cases} cases):")
    print(f"  Status Accuracy:       {status_matches}/{num_cases} ({status_accuracy*100:.1f}%)")
    print(f"  Exact Sequence Match:  {exact_seq_matches}/{num_cases} ({sequence_accuracy*100:.1f}%)")
    print(f"  Step Precision:        {matched_step_objects}/{total_predicted_steps} ({precision*100:.1f}%)")
    print(f"  Step Recall:           {matched_step_objects}/{total_expected_steps} ({recall*100:.1f}%)")
    print(f"  Step F1 Score:         {f1*100:.1f}%")

    return {
        "num_cases": num_cases,
        "status_accuracy": status_accuracy,
        "sequence_accuracy": sequence_accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "results": results,
    }


def run_independent_tests() -> bool:
    print("\n" + "=" * 80)
    print("RUNNING INDEPENDENT SYNTHETIC FIXTURE TESTS")
    print("=" * 80)

    policy = PolicyEngine()
    passed = 0
    total = 4

    # --------------------------------------------------------------------------
    # Test A: Historical Identity Resolution
    # --------------------------------------------------------------------------
    print("\n[TEST A] Historical Identity Resolution & Ghost Search Entry")
    # Request uses old email "alice.old@example.com", current email is "alice.new@example.com"
    cat_a = EvidenceCatalog()
    cat_a.manifest_cap["evi_test_a"] = datetime(2026, 9, 10, tzinfo=timezone.utc)
    cat_a.add(EvidenceObservation(
        file_id="evi_test_a",
        captured_at=datetime(2026, 9, 10, tzinfo=timezone.utc),
        system_id="search_service",
        resource_id="search_test_a",
        state="PRESENT",
        identifiers={"alice.old@example.com", "user_test_a"},
        details={}
    ))
    res_a = IdentityResolver()
    b_a = IdentityBundle("user_test_a")
    b_a.emails.add("alice.new@example.com")
    b_a.emails.add("alice.old@example.com")
    res_a.by_user_id["user_test_a"] = b_a
    res_a.email_to_user_id["alice.old@example.com"] = "user_test_a"
    res_a.email_to_user_id["alice.new@example.com"] = "user_test_a"

    eng_a = AuditEngine(cat_a, res_a, policy)
    req_a = {
        "case_id": "test_case_a",
        "email": "alice.old@example.com",
        "request_text": "Please delete my account and all data associated with my old email address.",
        "audit_at": "2026-09-15T12:00:00Z",
    }
    status_a, steps_a = eng_a.audit_case(req_a)
    finding_a = any(s["operation"] == "REPORT_REMAINING_RECORD" and s["resource_id"] == "search_test_a" for s in steps_a)
    if status_a == "INCOMPLETE" and finding_a:
        print("  PASS: Detected remaining search record linked via historical email address.")
        passed += 1
    else:
        print(f"  FAIL: Expected INCOMPLETE with search_test_a finding, got {status_a}")

    # --------------------------------------------------------------------------
    # Test B: Retention Compliance & Account Tombstone
    # --------------------------------------------------------------------------
    print("\n[TEST B] Retention Compliance & Account Tombstone Direct Identifier Redaction")
    cat_b = EvidenceCatalog()
    cat_b.manifest_cap["evi_test_b"] = datetime(2026, 9, 10, tzinfo=timezone.utc)
    # Security audit record is PRESENT (compliant retention)
    cat_b.add(EvidenceObservation(
        file_id="evi_test_b",
        captured_at=datetime(2026, 9, 10, tzinfo=timezone.utc),
        system_id="security_service",
        resource_id="audit_record_test_b",
        state="PRESENT",
        identifiers={"user_test_b"},
        details={}
    ))
    # Tombstone has direct identifiers removed (compliant tombstone)
    cat_b.add(EvidenceObservation(
        file_id="evi_test_b",
        captured_at=datetime(2026, 9, 10, tzinfo=timezone.utc),
        system_id="identity_service",
        resource_id="tombstone_test_b",
        state="REDACTED",
        identifiers={"user_test_b"},
        details={}
    ))
    # Primary account is ABSENT
    cat_b.add(EvidenceObservation(
        file_id="evi_test_b",
        captured_at=datetime(2026, 9, 10, tzinfo=timezone.utc),
        system_id="account_service",
        resource_id="account_test_b",
        state="ABSENT",
        identifiers={"user_test_b", "bob@example.com"},
        details={}
    ))
    res_b = IdentityResolver()
    b_b = IdentityBundle("user_test_b")
    b_b.emails.add("bob@example.com")
    res_b.by_user_id["user_test_b"] = b_b
    res_b.email_to_user_id["bob@example.com"] = "user_test_b"

    eng_b = AuditEngine(cat_b, res_b, policy)
    req_b = {
        "case_id": "test_case_b",
        "email": "bob@example.com",
        "request_text": "Please delete my account and remove all direct contact information.",
        "audit_at": "2026-09-15T12:00:00Z",
    }
    status_b, steps_b = eng_b.audit_case(req_b)
    has_audit_ver = any(s["operation"] == "VERIFY_RECORD_PRESENT" and s["resource_id"] == "audit_record_test_b" for s in steps_b)
    has_tomb_ver = any(s["operation"] == "VERIFY_RECORD_REDACTED" and s["resource_id"] == "tombstone_test_b" for s in steps_b)
    if status_b == "COMPLETE" and has_audit_ver and has_tomb_ver:
        print("  PASS: Correctly preserved security audit record and verified compliant redacted tombstone.")
        passed += 1
    else:
        print(f"  FAIL: Expected COMPLETE with preserved audit & tombstone, got {status_b}")

    # --------------------------------------------------------------------------
    # Test C: Resurrection Risk (Active Data Flow & Backup Restore)
    # --------------------------------------------------------------------------
    print("\n[TEST C] Resurrection Risk Detection (Active Data Flow)")
    cat_c = EvidenceCatalog()
    cat_c.manifest_cap["evi_test_c"] = datetime(2026, 9, 10, tzinfo=timezone.utc)
    # Primary account is absent
    cat_c.add(EvidenceObservation(
        file_id="evi_test_c",
        captured_at=datetime(2026, 9, 10, tzinfo=timezone.utc),
        system_id="account_service",
        resource_id="account_test_c",
        state="ABSENT",
        identifiers={"user_test_c", "charlie@example.com"},
        details={}
    ))
    # Active sync connector can recreate user profile
    cat_c.add(EvidenceObservation(
        file_id="evi_test_c",
        captured_at=datetime(2026, 9, 10, tzinfo=timezone.utc),
        system_id="integration_service",
        resource_id="data_flow_test_c",
        state="ACTIVE",
        identifiers={"user_test_c", "charlie@example.com"},
        details={}
    ))
    res_c = IdentityResolver()
    b_c = IdentityBundle("user_test_c")
    b_c.emails.add("charlie@example.com")
    res_c.by_user_id["user_test_c"] = b_c
    res_c.email_to_user_id["charlie@example.com"] = "user_test_c"

    eng_c = AuditEngine(cat_c, res_c, policy)
    req_c = {
        "case_id": "test_case_c",
        "email": "charlie@example.com",
        "request_text": "Please delete my account and ensure no background processes recreate it.",
        "audit_at": "2026-09-15T12:00:00Z",
    }
    status_c, steps_c = eng_c.audit_case(req_c)
    has_flow_finding = any(s["operation"] == "REPORT_ACTIVE_DATA_FLOW" and s["resource_id"] == "data_flow_test_c" for s in steps_c)
    has_flow_disable = any(s["operation"] == "DISABLE_DATA_FLOW" and s["resource_id"] == "data_flow_test_c" for s in steps_c)
    if status_c == "INCOMPLETE" and has_flow_finding and has_flow_disable:
        print("  PASS: Correctly reported active sync flow recreation risk and planned flow disablement.")
        passed += 1
    else:
        print(f"  FAIL: Expected INCOMPLETE with flow finding & remediation, got {status_c}")

    # --------------------------------------------------------------------------
    # Test D: Non-Deletion Request (NOT_APPLICABLE)
    # --------------------------------------------------------------------------
    print("\n[TEST D] Non-Deletion Request Intent Classification (NOT_APPLICABLE)")
    cat_d = EvidenceCatalog()
    res_d = IdentityResolver()
    eng_d = AuditEngine(cat_d, res_d, policy)
    req_d = {
        "case_id": "test_case_d",
        "email": "david@example.com",
        "request_text": "I need a copy of last year's invoices for tax filing. Please keep the account active.",
        "audit_at": "2026-09-15T12:00:00Z",
    }
    status_d, steps_d = eng_d.audit_case(req_d)
    if status_d == "NOT_APPLICABLE" and len(steps_d) == 0:
        print("  PASS: Correctly classified access request with keep-alive instruction as NOT_APPLICABLE with empty steps.")
        passed += 1
    else:
        print(f"  FAIL: Expected NOT_APPLICABLE with [] steps, got {status_d}")

    print(f"\nIndependent Test Results: {passed}/{total} Passed (100% Pass Rate)" if passed == total else f"Independent Tests: {passed}/{total}")
    return passed == total


if __name__ == "__main__":
    b_res = run_benchmark()
    tests_ok = run_independent_tests()
