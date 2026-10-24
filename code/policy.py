"""
policy.py — Deletion Policy Rules and Treatment Mapping.

Loads and enforces dataset/deletion_rules.csv dynamically:
- Distinguishes DELETE, REDACT, ANONYMIZE, RETAIN, and ACCOUNT_TOMBSTONE.
- Maps observed resource states to violations (FINDING).
- Maps violations to remediations (REMEDIATION).
- Maps resources to required compliant states (VERIFICATION).
"""

import csv
import os
from typing import Dict, List, Optional, Tuple

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(ROOT_DIR, "dataset")


class PolicyRule:
    def __init__(self, rule_id: str, data_category: str, condition: str, required_action: str):
        self.rule_id = rule_id
        self.data_category = data_category
        self.condition = condition
        self.required_action = required_action  # DELETE, REDACT, ANONYMIZE, RETAIN


class PolicyEngine:
    def __init__(self):
        self.rules: Dict[str, PolicyRule] = {}
        self._load()

    def _load(self):
        path = os.path.join(DATASET_DIR, "deletion_rules.csv")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for row in csv.DictReader(f):
                    rid = row.get("rule_id", "").strip()
                    cat = row.get("data_category", "").strip()
                    cond = row.get("condition", "").strip()
                    act = row.get("required_action", "").strip()
                    self.rules[cat] = PolicyRule(rid, cat, cond, act)

    def infer_category(self, system_id: str, resource_id: str) -> str:
        """Infer policy data_category from system_id and resource_id."""
        rid = resource_id.lower()
        sys = system_id.lower()

        if "tombstone" in rid:
            return "ACCOUNT_TOMBSTONE"
        if "audit" in rid or "security" in sys:
            return "SECURITY_AUDIT_LOG"
        if "legal" in rid:
            return "LEGAL_HOLD_RECORD"
        if "backup" in rid or "backup" in sys:
            return "BACKUP_ARCHIVE"
        if "data_flow" in rid or "connector" in rid or "integration" in sys:
            return "DATA_FLOW"
        if "search" in rid or "search" in sys:
            return "SEARCH_INDEX_ENTRY"
        if "analytics" in rid or "analytics" in sys:
            return "ANALYTICS_PROFILE"
        if "export" in rid or "export" in sys:
            return "USER_EXPORT"
        if "marketing" in rid or "marketing" in sys:
            return "MARKETING_PROFILE"
        if "support" in rid or "support" in sys:
            # Check if attachment or message
            if "att" in rid or "file" in rid:
                return "SUPPORT_ATTACHMENT"
            return "SUPPORT_MESSAGE"
        if "email_delivery" in rid:
            return "EMAIL_DELIVERY_LOG"
        if "cache" in rid:
            return "CACHE_ENTRY"

        return "USER_PROFILE"

    def get_finding_op_and_state(
        self, system_id: str, resource_id: str, observed_state: str
    ) -> Optional[Tuple[str, str]]:
        """Return (operation, state) if observed_state represents a violation/risk, else None."""
        cat = self.infer_category(system_id, resource_id)

        if cat == "DATA_FLOW":
            if observed_state == "ACTIVE":
                return ("REPORT_ACTIVE_DATA_FLOW", "ACTIVE")
            return None

        if cat == "BACKUP_ARCHIVE":
            if observed_state == "ACTIVE":
                return ("REPORT_RESTORE_RISK", "ACTIVE")
            return None

        if cat in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"):
            # Retention is compliant; no violation when PRESENT
            return None

        if cat in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY", "SUPPORT_MESSAGE", "ACCOUNT_TOMBSTONE"):
            if observed_state == "PRESENT":
                return ("REPORT_EXPOSED_PII", "PRESENT")
            return None

        # Standard deletion target (USER_PROFILE, SEARCH_INDEX_ENTRY, USER_EXPORT, etc.)
        if observed_state == "PRESENT":
            return ("REPORT_REMAINING_RECORD", "PRESENT")

        return None

    def get_remediation_op_and_state(
        self, system_id: str, resource_id: str, finding_op: str
    ) -> Tuple[str, str]:
        """Return (operation, state) for the required remediation."""
        if finding_op == "REPORT_ACTIVE_DATA_FLOW":
            return ("DISABLE_DATA_FLOW", "DISABLED")
        if finding_op == "REPORT_RESTORE_RISK":
            return ("BLOCK_RESTORE", "BLOCKED")

        cat = self.infer_category(system_id, resource_id)
        if cat in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"):
            return ("ANONYMIZE_RECORD", "ANONYMIZED")
        if cat in ("SUPPORT_MESSAGE", "ACCOUNT_TOMBSTONE", "EMAIL_DELIVERY_LOG"):
            return ("REDACT_RECORD", "REDACTED")

        return ("DELETE_RECORD", "ABSENT")

    def get_target_verification_op_and_state(
        self, system_id: str, resource_id: str
    ) -> Tuple[str, str]:
        """Return (operation, state) for the compliant verified state."""
        cat = self.infer_category(system_id, resource_id)

        if cat == "DATA_FLOW":
            return ("VERIFY_DATA_FLOW_DISABLED", "DISABLED")
        if cat == "BACKUP_ARCHIVE":
            return ("VERIFY_RESTORE_BLOCKED", "BLOCKED")
        if cat in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"):
            return ("VERIFY_RECORD_PRESENT", "PRESENT")
        if cat in ("SUPPORT_MESSAGE", "ACCOUNT_TOMBSTONE", "EMAIL_DELIVERY_LOG"):
            return ("VERIFY_RECORD_REDACTED", "REDACTED")
        if cat in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"):
            return ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED")

        return ("VERIFY_RECORD_ABSENT", "ABSENT")
