"""
ingest.py — Evidence Ingestion and Cataloging for Ghost Data Still Exists.

Parses all participant-facing dataset files and evidence formats:
- CSV manifests and identity files
- JSON snapshot bundles, service resource exports, and record dumps
- SQL relational snapshots via SQLite in-memory execution, including JSON record columns
- Structured log streams with trace_id correlation
- Plain-text shift handover records
- PDF compliance documents and customer statements via PyMuPDF
- UI screenshots via native Windows OCR (winocr) with graceful fallback
- Automatic serialization caching to evidence_cache.pkl for fast execution
"""

import csv
import json
import os
import pickle
import re
import sqlite3
import tempfile
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Set, Tuple

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None

try:
    from PIL import Image
    import winocr
except ImportError:
    winocr = None

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(ROOT_DIR, "dataset")
CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence_cache.pkl")
CACHE_VERSION = 7


def parse_iso(ts: Optional[str]) -> Optional[datetime]:
    """Parse ISO-8601 timestamp string into timezone-aware datetime."""
    if not ts:
        return None
    ts = ts.strip()
    try:
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def normalize_phone(phone: Optional[str]) -> str:
    """Normalize phone number to digits and leading +."""
    if not phone:
        return ""
    return re.sub(r"[^\d+]", "", phone.strip())


class EvidenceObservation:
    """A single factual observation about a resource grounded in an evidence file."""

    def __init__(
        self,
        file_id: str,
        captured_at: Optional[datetime],
        system_id: str,
        resource_id: str,
        state: str,  # PRESENT, ABSENT, REDACTED, ANONYMIZED, ACTIVE, DISABLED, BLOCKED
        identifiers: Set[str],
        details: Dict[str, Any],
    ):
        self.file_id = file_id
        self.captured_at = captured_at
        self.system_id = system_id
        self.resource_id = resource_id
        self.state = state
        self.identifiers = set(i.lower().strip() for i in identifiers if i)
        self.details = details

    def __repr__(self):
        return (
            f"Obs({self.file_id}, {self.system_id}, {self.resource_id}, "
            f"{self.state}, ids={len(self.identifiers)})"
        )


class EvidenceCatalog:
    """Indexed catalog of all parsed evidence observations."""

    def __init__(self):
        self.cache_version = CACHE_VERSION
        self.observations: List[EvidenceObservation] = []
        self.by_resource_id: Dict[str, List[EvidenceObservation]] = {}
        self.by_identifier: Dict[str, List[EvidenceObservation]] = {}
        self.manifest: List[Dict[str, Any]] = []
        self.manifest_cap: Dict[str, Optional[datetime]] = {}

    def add(self, obs: EvidenceObservation):
        self.observations.append(obs)
        self.by_resource_id.setdefault(obs.resource_id, []).append(obs)
        for ident in obs.identifiers:
            self.by_identifier.setdefault(ident.lower(), []).append(obs)

    def find_by_identifiers(
        self, idents: Set[str], audit_at: Optional[datetime] = None
    ) -> List[EvidenceObservation]:
        """Find observations matching any identifier, filtered to file captured_at <= audit_at."""
        results = []
        seen = set()
        matched_resource_ids = set()
        for ident in idents:
            norm = ident.lower().strip()
            for obs in self.by_identifier.get(norm, []):
                file_cap = self.manifest_cap.get(obs.file_id)
                if file_cap and audit_at and file_cap > audit_at:
                    continue
                if obs.captured_at and audit_at and obs.captured_at > audit_at:
                    continue
                obs_id = id(obs)
                if obs_id not in seen:
                    seen.add(obs_id)
                    results.append(obs)
                matched_resource_ids.add(obs.resource_id)

        # A resource's compliant/absent snapshot often has no direct identifier.
        # Once one observation links it to the subject, include its other snapshots.
        for resource_id in matched_resource_ids:
            for obs in self.by_resource_id.get(resource_id, []):
                file_cap = self.manifest_cap.get(obs.file_id)
                if file_cap and audit_at and file_cap > audit_at:
                    continue
                if obs.captured_at and audit_at and obs.captured_at > audit_at:
                    continue
                obs_id = id(obs)
                if obs_id not in seen:
                    seen.add(obs_id)
                    results.append(obs)
        return results

    def find_by_resource(
        self, resource_id: str, audit_at: Optional[datetime] = None
    ) -> List[EvidenceObservation]:
        """Find observations for a resource, filtered to file captured_at <= audit_at."""
        results = []
        for obs in self.by_resource_id.get(resource_id, []):
            file_cap = self.manifest_cap.get(obs.file_id)
            if file_cap and audit_at and file_cap > audit_at:
                continue
            if obs.captured_at and audit_at and obs.captured_at > audit_at:
                continue
            results.append(obs)
        return results


def load_evidence_manifest() -> List[Dict[str, Any]]:
    path = os.path.join(DATASET_DIR, "evidence_files.csv")
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return list(csv.DictReader(f))


def parse_all_evidence(use_cache: bool = True) -> EvidenceCatalog:
    """Parse all evidence files and build the indexed EvidenceCatalog."""
    if use_cache and os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "rb") as fp:
                catalog = pickle.load(fp)
            if getattr(catalog, "cache_version", None) == CACHE_VERSION:
                print(f"Loaded evidence catalog from cache: {len(catalog.observations)} observations.")
                return catalog
            print("Evidence cache is from an older parser version. Rebuilding...")
        except Exception as e:
            print(f"Failed to load cache: {e}. Rebuilding...")

    catalog = EvidenceCatalog()
    catalog.manifest = load_evidence_manifest()
    for m in catalog.manifest:
        catalog.manifest_cap[m["file_id"]] = parse_iso(m.get("captured_at"))

    print(f"Parsing evidence files from {DATASET_DIR}...")

    for m in catalog.manifest:
        file_id = m["file_id"]
        rel_path = m["file_path"]
        cap_at = catalog.manifest_cap.get(file_id)
        full_path = os.path.join(DATASET_DIR, rel_path)

        if not os.path.exists(full_path):
            continue

        ext = os.path.splitext(full_path)[1].lower()

        # 1. TEXT HANDOVER
        if ext == ".txt":
            _parse_txt(full_path, file_id, cap_at, catalog)

        # 2. JSON EXPORTS & SNAPSHOTS
        elif ext == ".json":
            _parse_json(full_path, file_id, cap_at, catalog)

        # 3. SQL RELATIONAL SNAPSHOTS
        elif ext == ".sql":
            _parse_sql(full_path, file_id, cap_at, catalog)

        # 4. STRUCTURED LOG STREAMS
        elif ext == ".log":
            _parse_log(full_path, file_id, cap_at, catalog)

        # 5. PDF DOCUMENTS
        elif ext == ".pdf":
            _parse_pdf(full_path, file_id, cap_at, catalog)

        # 6. UI SCREENSHOTS
        elif ext == ".png":
            _parse_image(full_path, file_id, cap_at, catalog)

    print(f"Parsed {len(catalog.observations)} total observations across all evidence files.")

    # Save cache
    try:
        with open(CACHE_FILE, "wb") as fp:
            pickle.dump(catalog, fp, protocol=pickle.HIGHEST_PROTOCOL)
        print("Evidence catalog cached successfully.")
    except Exception as e:
        print(f"Could not write cache file: {e}")

    return catalog


def _parse_txt(fpath: str, fid: str, cap_at: Optional[datetime], catalog: EvidenceCatalog):
    state_map = {
        "NOT_FOUND": "ABSENT",
        "FOUND": "PRESENT",
        "IDENTIFIABLE": "PRESENT",
        "ACTIVE": "ACTIVE",
        "DISABLED": "DISABLED",
        "BLOCKED": "BLOCKED",
        "REDACTED": "REDACTED",
        "ANONYMIZED": "ANONYMIZED",
    }
    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line.startswith("- "):
                continue
            parts = [p.strip() for p in line[2:].split("|")]
            if len(parts) >= 6:
                ts_str, sys_id, res_id, cat, status, ident = parts[:6]
                t_cap = parse_iso(ts_str) or cap_at
                st = state_map.get(status, "PRESENT")
                ids = set()
                if ident and ident != "no direct identifier":
                    ids.add(ident.lower())
                catalog.add(
                    EvidenceObservation(
                        fid, t_cap, sys_id, res_id, st, ids, {"category": cat, "ident": ident}
                    )
                )


def _parse_json(fpath: str, fid: str, cap_at: Optional[datetime], catalog: EvidenceCatalog):
    try:
        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except Exception:
        return

    # Service resource exports
    if "service_exports" in data:
        exp_time = parse_iso(data.get("exported_at")) or cap_at
        se = data["service_exports"]

        # account_service
        for rec in se.get("account_service", {}).get("profile_lookups", []):
            rid = rec.get("resource_id")
            st = "ABSENT" if rec.get("status_code") == 404 else "PRESENT"
            ids = set()
            prof = rec.get("profile") or {}
            for k in ["customer_reference", "email", "phone", "email_hash"]:
                v = prof.get(k)
                if v:
                    ids.add(str(v).lower())
            obs_time = parse_iso(rec.get("observed_at")) or exp_time
            catalog.add(EvidenceObservation(fid, obs_time, "account_service", rid, st, ids, rec))

        # analytics_platform
        for rec in se.get("analytics_platform", {}).get("profiles", []):
            rid = rec.get("resource_id")
            ids = set()
            for k in ["customer_reference", "email", "phone", "email_hash"]:
                v = rec.get(k)
                if v:
                    ids.add(str(v).lower())
            st = "ANONYMIZED" if not ids else "PRESENT"
            obs_time = parse_iso(rec.get("observed_at")) or exp_time
            catalog.add(EvidenceObservation(fid, obs_time, "analytics_platform", rid, st, ids, rec))

        # backup_service
        for rec in se.get("backup_service", {}).get("restore_entries", []):
            rid = rec.get("resource_id")
            ids = set()
            for k in ["customer_reference", "customer_email"]:
                v = rec.get(k)
                if v:
                    ids.add(str(v).lower())
            st = "ACTIVE" if rec.get("restore_allowed") else "BLOCKED"
            obs_time = parse_iso(rec.get("observed_at")) or exp_time
            catalog.add(EvidenceObservation(fid, obs_time, "backup_service", rid, st, ids, rec))

        # export_service
        for rec in se.get("export_service", {}).get("exports", []):
            rid = rec.get("resource_id")
            ids = set()
            for k in ["customer_reference", "owner_email", "owner_phone"]:
                v = rec.get(k)
                if v:
                    ids.add(str(v).lower())
            obs_time = parse_iso(rec.get("observed_at")) or exp_time
            catalog.add(EvidenceObservation(fid, obs_time, "export_service", rid, "PRESENT", ids, rec))

        # integration_service
        for rec in se.get("integration_service", {}).get("connectors", []):
            rid = rec.get("resource_id")
            ids = set()
            for k in ["customer_reference", "customer_email"]:
                v = rec.get(k)
                if v:
                    ids.add(str(v).lower())
            st = "ACTIVE" if rec.get("enabled") else "DISABLED"
            obs_time = parse_iso(rec.get("observed_at")) or exp_time
            catalog.add(EvidenceObservation(fid, obs_time, "integration_service", rid, st, ids, rec))

        # search_service
        for rec in se.get("search_service", {}).get("index_queries", []):
            rid = rec.get("resource_id")
            hits = rec.get("hits", {})
            total = hits.get("total", 0)
            st = "PRESENT" if total > 0 else "ABSENT"
            ids = set()
            if rec.get("query"):
                ids.add(rec["query"].lower())
            for doc in hits.get("documents", []):
                for k in ["customer_reference", "email", "phone"]:
                    v = doc.get(k)
                    if v:
                        ids.add(str(v).lower())
            obs_time = parse_iso(rec.get("observed_at")) or exp_time
            catalog.add(EvidenceObservation(fid, obs_time, "search_service", rid, st, ids, rec))

        # security_service
        for rec in se.get("security_service", {}).get("audit_records", []):
            rid = rec.get("resource_id")
            ids = set()
            v = rec.get("subject_reference")
            if v:
                ids.add(str(v).lower())
            obs_time = parse_iso(rec.get("observed_at")) or exp_time
            catalog.add(EvidenceObservation(fid, obs_time, "security_service", rid, "PRESENT", ids, rec))

        # support_platform
        for rec in se.get("support_platform", {}).get("tickets", []):
            rid = rec.get("resource_id")
            ids = set()
            for k in ["customer_reference", "requester_email", "requester_phone", "requester_name"]:
                v = rec.get(k)
                if v:
                    ids.add(str(v).lower())
            direct_pii = [
                rec.get(k)
                for k in ["requester_email", "requester_phone", "requester_name"]
                if rec.get(k)
            ]
            st = "PRESENT" if direct_pii else "REDACTED"
            obs_time = parse_iso(rec.get("observed_at")) or exp_time
            catalog.add(EvidenceObservation(fid, obs_time, "support_platform", rid, st, ids, rec))

    # Snapshot bundles
    elif "snapshots" in data:
        exp_time = parse_iso(data.get("exported_at")) or cap_at
        for snap in data["snapshots"]:
            ds = snap.get("data_store", "")
            coll = snap.get("collection", "")
            t_snap = parse_iso(snap.get("captured_at")) or exp_time
            for rec in snap.get("records", []):
                rid = rec.get("resource_id")
                ids = set()
                for k in [
                    "user_id",
                    "customer_reference",
                    "subject_reference",
                    "owner_user_id",
                    "email",
                    "phone",
                    "email_hash",
                    "name",
                    "full_name",
                ]:
                    v = rec.get(k)
                    if v:
                        ids.add(str(v).lower())
                if "identity_service" in ds or "tombstone" in rid:
                    direct_pii = [
                        rec.get(k) for k in ["email", "phone", "email_hash", "name"] if rec.get(k)
                    ]
                    st = "PRESENT" if direct_pii else "REDACTED"
                    sys_id = "identity_service"
                elif "security_service" in ds or "audit" in rid:
                    st = "PRESENT"
                    sys_id = "security_service"
                elif "analytics" in ds or "analytics" in rid:
                    direct_pii = [
                        rec.get(k) for k in ["email", "phone", "email_hash"] if rec.get(k)
                    ]
                    st = "PRESENT" if direct_pii else "ANONYMIZED"
                    sys_id = "analytics_platform"
                elif "account_service" in ds or "account_" in rid:
                    st = "PRESENT"
                    sys_id = "account_service"
                else:
                    st = "PRESENT"
                    sys_id = ds
                catalog.add(EvidenceObservation(fid, t_snap, sys_id, rid, st, ids, rec))

    # Flat records list
    elif "records" in data:
        coll = data.get("collection", "")
        t_cap = parse_iso(data.get("captured_at") or data.get("exported_at")) or cap_at
        for rec in data["records"]:
            rid = rec.get("resource_id") or rec.get("record_id")
            if not rid:
                continue
            ids = set()
            for k in [
                "user_id",
                "customer_reference",
                "subject_reference",
                "email",
                "phone",
                "owner_email",
                "owner_phone",
            ]:
                v = rec.get(k)
                if v:
                    ids.add(str(v).lower())
            if "analytics" in coll or "analytics" in rid:
                direct_pii = [rec.get(k) for k in ["email", "phone", "email_hash"] if rec.get(k)]
                st = "PRESENT" if direct_pii else "ANONYMIZED"
                sys_id = "analytics_platform"
            elif "export" in coll or "export" in rid:
                st = "PRESENT"
                sys_id = "export_service"
            elif "connector" in coll or "data_flow" in rid:
                st = (
                    "ACTIVE"
                    if rec.get("status") == "active" or rec.get("enabled")
                    else "DISABLED"
                )
                sys_id = "integration_service"
            elif "audit" in coll or "audit" in rid:
                st = "PRESENT"
                sys_id = "security_service"
            else:
                st = "PRESENT"
                sys_id = "unknown"
            catalog.add(EvidenceObservation(fid, t_cap, sys_id, rid, st, ids, rec))


def _parse_sql(fpath: str, fid: str, cap_at: Optional[datetime], catalog: EvidenceCatalog):
    try:
        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
            sql_content = f.read()

        cap_match = re.search(r"--\s*Captured at:\s*(\S+)", sql_content)
        if cap_match:
            sql_cap = parse_iso(cap_match.group(1))
            if sql_cap:
                cap_at = sql_cap

        conn = sqlite3.connect(":memory:")
        conn.executescript(sql_content)
        cur = conn.cursor()
        tables = [
            r[0]
            for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        ]

        for tbl in tables:
            cur.execute(f'SELECT * FROM "{tbl}"')
            cols = [d[0] for d in cur.description]
            rows = cur.fetchall()

            has_record_json = "record_json" in cols

            for r in rows:
                rd = dict(zip(cols, r))

                # Handle tables with record_json column
                if has_record_json and rd.get("record_json"):
                    try:
                        inner = json.loads(rd["record_json"])
                        rid = rd.get("resource_id") or inner.get("resource_id")
                        ids = set()
                        for k in [
                            "user_id",
                            "customer_reference",
                            "subject_reference",
                            "email",
                            "phone",
                            "email_hash",
                        ]:
                            v = inner.get(k)
                            if v:
                                ids.add(str(v).lower())
                        document = inner.get("document")
                        if isinstance(document, dict):
                            for k in [
                                "user_id",
                                "customer_reference",
                                "subject_reference",
                                "email",
                                "phone",
                                "email_hash",
                            ]:
                                v = document.get(k)
                                if v:
                                    ids.add(str(v).lower())
                        coll = rd.get("collection_name", "")
                        if "profile" in coll:
                            sys_id = "account_service"
                            st = "PRESENT"
                        elif "search" in coll:
                            sys_id = "search_service"
                            st = "PRESENT"
                        elif "analytics" in coll:
                            sys_id = "analytics_platform"
                            direct_pii = [
                                inner.get(k)
                                for k in ["email", "phone", "email_hash"]
                                if inner.get(k)
                            ]
                            st = "PRESENT" if direct_pii else "ANONYMIZED"
                        elif "support" in coll:
                            sys_id = "support_platform"
                            direct_pii = [
                                inner.get(k)
                                for k in ["requester_email", "requester_phone"]
                                if inner.get(k)
                            ]
                            st = "PRESENT" if direct_pii else "REDACTED"
                        else:
                            sys_id = "account_service"
                            st = "PRESENT"
                        catalog.add(
                            EvidenceObservation(fid, cap_at, sys_id, rid, st, ids, inner)
                        )
                        continue
                    except Exception:
                        pass

                rid = rd.get("resource_id") or rd.get("record_id")
                if not rid:
                    continue
                ids = set()
                for k in [
                    "user_id",
                    "email",
                    "phone",
                    "customer_reference",
                    "subject_reference",
                    "owner_email",
                    "requester_email",
                    "customer_email",
                ]:
                    v = rd.get(k)
                    if v:
                        ids.add(str(v).lower())

                tbl_l = tbl.lower()
                if "tombstone" in tbl_l or "tombstone" in rid:
                    sys_id = "identity_service"
                    direct_pii = [
                        rd.get(k) for k in ["name", "email", "phone", "email_hash"] if rd.get(k)
                    ]
                    st = "PRESENT" if direct_pii else "REDACTED"
                elif "search" in tbl_l or "search" in rid:
                    sys_id = "search_service"
                    st = "PRESENT"
                elif "support" in tbl_l or "support" in rid:
                    sys_id = "support_platform"
                    direct_pii = [
                        rd.get(k)
                        for k in ["requester_name", "requester_email", "requester_phone"]
                        if rd.get(k)
                    ]
                    st = "PRESENT" if direct_pii else "REDACTED"
                elif "analytics" in tbl_l or "analytics" in rid:
                    sys_id = "analytics_platform"
                    direct_pii = [
                        rd.get(k) for k in ["email", "phone", "email_hash"] if rd.get(k)
                    ]
                    st = "PRESENT" if direct_pii else "ANONYMIZED"
                elif "backup" in tbl_l or "backup" in rid:
                    sys_id = "backup_service"
                    allowed = rd.get("restore_allowed") or rd.get("restore_enabled")
                    st = "ACTIVE" if allowed in (1, "1", True, "true") else "BLOCKED"
                elif "connector" in tbl_l or "data_flow" in rid:
                    sys_id = "integration_service"
                    enabled = rd.get("enabled")
                    st = "ACTIVE" if enabled in (1, "1", True, "true") else "DISABLED"
                elif "security" in tbl_l or "audit" in rid:
                    sys_id = "security_service"
                    st = "PRESENT"
                elif "export" in tbl_l or "export" in rid:
                    sys_id = "export_service"
                    st = "PRESENT"
                else:
                    sys_id = "account_service"
                    st = "PRESENT"

                catalog.add(EvidenceObservation(fid, cap_at, sys_id, rid, st, ids, rd))

        conn.close()
    except Exception as e:
        pass


def _parse_log(fpath: str, fid: str, cap_at: Optional[datetime], catalog: EvidenceCatalog):
    """Parse log stream, correlating events by trace_id."""
    service_aliases = {
        "support_replica": "support_platform",
        "support_service": "support_platform",
        "analytics_service": "analytics_platform",
    }
    try:
        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception:
        return

    # Pass 1: Parse lines and group by trace_id
    traces: Dict[str, Dict[str, Any]] = {}  # trace_id -> {identifiers: set(), items: []}
    parsed_lines = []

    for line in lines:
        line = line.strip()
        if not line:
            continue
        m_ts = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?)\s+(.*)", line)
        if m_ts:
            ts = parse_iso(m_ts.group(1)) or cap_at
            rest = m_ts.group(2)
        else:
            ts = cap_at
            rest = line

        parts = {}
        try:
            json_parts = json.loads(rest)
            if isinstance(json_parts, dict):
                parts.update(json_parts)
        except (json.JSONDecodeError, TypeError):
            pass
        if not parts:
            for km in re.finditer(r'(\w+)=(?:"([^"]*?)"|(\S+))', rest):
                k = km.group(1)
                v = km.group(2) if km.group(2) is not None else km.group(3)
                parts[k] = v

        trace_id = parts.get("trace_id")
        ids = set()
        for k in [
            "lookup_key",
            "customer_reference",
            "subject_reference",
            "subject_ref",
            "subject_key",
            "correlation_key",
            "email",
            "phone",
            "customer_email",
            "matched_value",
        ]:
            v = parts.get(k)
            if v and v != "null":
                ids.add(str(v).lower())

        if trace_id:
            traces.setdefault(trace_id, {"identifiers": set(), "lines": []})
            traces[trace_id]["identifiers"].update(ids)
            traces[trace_id]["lines"].append((ts, parts))
        else:
            parsed_lines.append((ts, parts, ids))

    # Pass 2: Add trace-correlated observations
    for trace_id, tr_data in traces.items():
        tr_ids = tr_data["identifiers"]
        for ts, parts in tr_data["lines"]:
            rid = parts.get("resource_id")
            if not rid:
                continue
            sys_id = service_aliases.get(parts.get("service", ""), parts.get("service") or "unknown")
            event = parts.get("event", "")

            # Combine trace-level identifiers
            line_ids = set(tr_ids)
            for k in [
                "lookup_key",
                "customer_reference",
                "subject_reference",
                "subject_ref",
                "subject_key",
                "correlation_key",
                "email",
                "phone",
                "customer_email",
                "matched_value",
            ]:
                v = parts.get(k)
                if v and v != "null":
                    line_ids.add(str(v).lower())

            # Determine state
            if (
                parts.get("http_status") == "404"
                or parts.get("rows") == "0"
                or parts.get("result") == "miss"
            ):
                st = "ABSENT"
            elif sys_id == "integration_service" or "connector" in event or "data_flow" in rid:
                st = "ACTIVE" if parts.get("enabled") == "true" else "DISABLED"
            elif sys_id == "backup_service" or "restore" in event or "backup" in rid:
                st = (
                    "ACTIVE"
                    if (
                        parts.get("restore_allowed") == "true"
                        or (
                            parts.get("eligible") == "true"
                            and parts.get("deletion_block") != "true"
                        )
                    )
                    else "BLOCKED"
                )
            elif sys_id == "analytics_platform" or "analytics" in rid:
                st = (
                    "ANONYMIZED"
                    if (
                        any(token in event.lower() for token in ("anonym", "redact"))
                        or (
                            "profile_read_completed" in event
                            and all(parts.get(k) in (None, "null") for k in ("email", "phone", "email_hash"))
                        )
                    )
                    else "PRESENT"
                )
            elif sys_id == "support_platform" or "support" in rid:
                st = (
                    "REDACTED"
                    if any(token in event.lower() for token in ("redact", "scrub"))
                    else "PRESENT"
                )
            else:
                st = "PRESENT"

            catalog.add(EvidenceObservation(fid, ts, sys_id, rid, st, line_ids, parts))

    # Add standalone log lines
    for ts, parts, ids in parsed_lines:
        rid = parts.get("resource_id")
        if not rid:
            continue
        sys_id = service_aliases.get(parts.get("service", ""), parts.get("service") or "unknown")
        event = parts.get("event", "")
        if (
            parts.get("http_status") == "404"
            or parts.get("rows") == "0"
            or parts.get("result") == "miss"
        ):
            st = "ABSENT"
        elif sys_id == "integration_service" or "connector" in event or "data_flow" in rid:
            st = "ACTIVE" if parts.get("enabled") == "true" else "DISABLED"
        elif sys_id == "backup_service" or "restore" in event or "backup" in rid:
            st = "ACTIVE" if parts.get("restore_allowed") == "true" else "BLOCKED"
        else:
            st = "PRESENT"
        catalog.add(EvidenceObservation(fid, ts, sys_id, rid, st, ids, parts))


def _parse_pdf(fpath: str, fid: str, cap_at: Optional[datetime], catalog: EvidenceCatalog):
    if not fitz:
        return
    try:
        doc = fitz.open(fpath)
        full_text = "\n".join([page.get_text() for page in doc])
        res_matches = re.findall(
            r"\b(account_\w+|support_\w+|audit_record_\w+|analytics_\w+|backup_\w+|data_flow_\w+|search_\w+|export_\w+)\b",
            full_text,
        )
        user_matches = re.findall(r"\b(user_\d+)\b", full_text)
        email_matches = re.findall(
            r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b", full_text
        )

        ids = set(u.lower() for u in user_matches) | set(e.lower() for e in email_matches)
        for rid in set(res_matches):
            if rid.startswith("account_"):
                sys_id = "account_service"
            elif rid.startswith("support_"):
                sys_id = "support_platform"
            elif rid.startswith("audit_record_"):
                sys_id = "security_service"
            elif rid.startswith("analytics_"):
                sys_id = "analytics_platform"
            elif rid.startswith("backup_"):
                sys_id = "backup_service"
            elif rid.startswith("data_flow_"):
                sys_id = "integration_service"
            else:
                sys_id = "document_service"
            catalog.add(
                EvidenceObservation(
                    fid, cap_at, sys_id, rid, "PRESENT", ids, {"text_snippet": full_text[:200]}
                )
            )
    except Exception:
        pass


def _parse_image(fpath: str, fid: str, cap_at: Optional[datetime], catalog: EvidenceCatalog):
    try:
        txt_path = os.path.splitext(fpath)[0] + ".txt"
        if os.path.exists(txt_path):
            with open(txt_path, "r", encoding="utf-8", errors="replace") as f:
                ocr_text = f.read()
        elif winocr:
            ocr_res = winocr.recognize_pil_sync(Image.open(fpath))
            ocr_text = ocr_res.get("text", "")
        else:
            return

        res_matches = re.findall(
            r"\b(account_\w+|support_\w+|audit_record_\w+|analytics_\w+|backup_\w+|data_flow_\w+|search_\w+|export_\w+|tombstone_\w+)\b",
            ocr_text,
        )
        user_matches = re.findall(r"\b(user_\d+)\b", ocr_text)
        email_matches = re.findall(
            r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b", ocr_text
        )
        ids = set(u.lower() for u in user_matches) | set(e.lower() for e in email_matches)
        for rid in set(res_matches):
            if rid.startswith("account_"):
                sys_id = "account_service"
            elif rid.startswith("tombstone_"):
                sys_id = "identity_service"
            elif rid.startswith("support_"):
                sys_id = "support_platform"
            elif rid.startswith("search_"):
                sys_id = "search_service"
            else:
                sys_id = "image_service"
            catalog.add(
                EvidenceObservation(
                    fid, cap_at, sys_id, rid, "PRESENT", ids, {"ocr_snippet": ocr_text[:200]}
                )
            )
    except Exception:
        pass
