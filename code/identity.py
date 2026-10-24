"""
identity.py — Identity Resolution and Historical Identifier Reconstruction.

Resolves subject identities across:
- Current identity snapshots in dataset/user_identities.csv
- Historical identity changes in dataset/user_audit_log.csv
- Reconstructs stable user_id, current and historical emails, phone numbers,
  email hashes, and full names.
- Precomputes indexed identity bundles for high performance.
"""

import csv
import os
import re
from typing import Dict, List, Optional, Set

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(ROOT_DIR, "dataset")


def normalize_phone(phone: Optional[str]) -> str:
    """Normalize phone number to digits and leading +."""
    if not phone:
        return ""
    return re.sub(r"[^\d+]", "", phone.strip())


class IdentityBundle:
    """Represents a person's current and historical identity profile."""

    def __init__(self, user_id: str):
        self.user_id = user_id
        self.emails: Set[str] = set()
        self.phones: Set[str] = set()
        self.email_hashes: Set[str] = set()
        self.names: Set[str] = set()

    @property
    def all_search_keys(self) -> Set[str]:
        """All searchable identifier tokens for this subject."""
        keys = set()
        if self.user_id:
            keys.add(self.user_id.lower())
        for e in self.emails:
            if e:
                keys.add(e.lower())
        for p in self.phones:
            if p:
                keys.add(p.lower())
                keys.add(normalize_phone(p).lower())
        for h in self.email_hashes:
            if h:
                keys.add(h.lower())
        return keys

    def __repr__(self):
        return f"IdentityBundle(user_id={self.user_id}, emails={self.emails})"


class IdentityResolver:
    """Precomputed identity resolver mapping any historical or current identifier to subject."""

    def __init__(self):
        self.by_user_id: Dict[str, IdentityBundle] = {}
        self.email_to_user_id: Dict[str, str] = {}
        self.phone_to_user_id: Dict[str, str] = {}
        self.hash_to_user_id: Dict[str, str] = {}
        self._load()

    def _load(self):
        identities_path = os.path.join(DATASET_DIR, "user_identities.csv")
        audit_path = os.path.join(DATASET_DIR, "user_audit_log.csv")

        # 1. Load current identity snapshot
        if os.path.exists(identities_path):
            with open(identities_path, "r", encoding="utf-8", errors="replace") as f:
                for row in csv.DictReader(f):
                    uid = row.get("user_id", "").strip()
                    if not uid:
                        continue
                    bundle = self.by_user_id.setdefault(uid, IdentityBundle(uid))
                    email = row.get("email", "").strip().lower()
                    if email:
                        bundle.emails.add(email)
                        self.email_to_user_id[email] = uid
                    phone = row.get("phone", "").strip()
                    if phone:
                        bundle.phones.add(phone)
                        self.phone_to_user_id[phone] = uid
                        self.phone_to_user_id[normalize_phone(phone)] = uid
                    eh = row.get("email_hash", "").strip().lower()
                    if eh:
                        bundle.email_hashes.add(eh)
                        self.hash_to_user_id[eh] = uid
                    name = row.get("full_name", "").strip()
                    if name:
                        bundle.names.add(name)

        # 2. Reconstruct historical changes from audit log
        if os.path.exists(audit_path):
            with open(audit_path, "r", encoding="utf-8", errors="replace") as f:
                for row in csv.DictReader(f):
                    uid = row.get("user_id", "").strip()
                    if not uid:
                        continue
                    bundle = self.by_user_id.setdefault(uid, IdentityBundle(uid))
                    fn = row.get("field_name", "").strip().lower()
                    ov = row.get("old_value", "").strip()
                    nv = row.get("new_value", "").strip()

                    if fn == "email":
                        if ov:
                            ov_l = ov.lower()
                            bundle.emails.add(ov_l)
                            self.email_to_user_id.setdefault(ov_l, uid)
                        if nv:
                            nv_l = nv.lower()
                            bundle.emails.add(nv_l)
                            self.email_to_user_id.setdefault(nv_l, uid)

                    elif fn == "phone":
                        if ov:
                            bundle.phones.add(ov)
                            self.phone_to_user_id.setdefault(ov, uid)
                            self.phone_to_user_id.setdefault(normalize_phone(ov), uid)
                        if nv:
                            bundle.phones.add(nv)
                            self.phone_to_user_id.setdefault(nv, uid)
                            self.phone_to_user_id.setdefault(normalize_phone(nv), uid)

                    elif fn == "email_hash":
                        if ov:
                            bundle.email_hashes.add(ov.lower())
                            self.hash_to_user_id.setdefault(ov.lower(), uid)
                        if nv:
                            bundle.email_hashes.add(nv.lower())
                            self.hash_to_user_id.setdefault(nv.lower(), uid)

                    elif fn in ("name", "full_name"):
                        if ov:
                            bundle.names.add(ov)
                        if nv:
                            bundle.names.add(nv)

    def resolve(self, email: str) -> Optional[IdentityBundle]:
        """Resolve a request email to its complete IdentityBundle."""
        norm_email = email.strip().lower()
        uid = self.email_to_user_id.get(norm_email)
        if uid and uid in self.by_user_id:
            return self.by_user_id[uid]

        # If user_id not found in records, construct a minimal bundle
        fallback = IdentityBundle(user_id="")
        fallback.emails.add(norm_email)
        return fallback
