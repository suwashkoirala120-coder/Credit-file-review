#!/usr/bin/env python3
"""Local credit proposal review system. Python standard library only."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import sys
import time
import uuid
from datetime import datetime, timezone
from email.parser import BytesParser
from email.policy import default
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse
from urllib.parse import quote as urlquote

BASE = Path(__file__).resolve().parent
DB_PATH = BASE / "credit_review.db"
UPLOAD_DIR = BASE / "uploads"
MAX_BODY = 15 * 1024 * 1024
SESSION_SECONDS = 8 * 60 * 60
PBKDF2_ROUNDS = 240_000

MODULE_FIELDS = {
    "KYC & customer": ["Customer identity", "Citizenship & national ID", "Address & contacts", "PEP declaration"],
    "Facility & vehicle": ["Facility amount & tenure", "Rate, EMI & purpose", "Vehicle identity", "Quotation & down payment"],
    "Documents": ["Document upload", "OCR extracted values", "Verification result", "Security documents"],
    "CIC": ["CIC identity data", "Probability of default", "Overdue history", "Blacklisting & accounts"],
    "Repayment": ["Declared income", "Tax & bank evidence", "Income analysis", "Existing obligations"],
    "Security & valuation": ["Collateral details", "FMV / DV", "Site & boundary risks", "Group limit & outstanding"],
    "Guarantor": ["Guarantor identity", "Date of birth & age", "Income & occupation", "PEP declaration"],
    "Workflow": ["Initiate / submit", "Forward file", "Return file", "Return remarks"],
    "Credit decision": ["Recommendation", "Approval authority", "Decision rationale", "Conditions"],
    "Reporting": ["Branch reports", "Portfolio reports", "Export data", "Sensitive fields"],
    "Users & roles": ["User assignment", "Role definitions", "Module permissions", "Field permissions"],
}
CHECKLIST_PATH = BASE / "rules" / "automobile_loan_checklist.json"
with CHECKLIST_PATH.open("r", encoding="utf-8") as checklist_file:
    CHECKLIST_DOCUMENT = json.load(checklist_file)
CAD_CHECKLIST_SECTIONS = [section for section in CHECKLIST_DOCUMENT["sections"] if section["id"] in {"documents", "security_docs"}]
CAD_CHECKLIST_ITEMS = [(f"{section['id']}--{index}", section["title"], item) for section in CAD_CHECKLIST_SECTIONS for index, item in enumerate(section["items"])]
DATA_FIELDS = {
    "KYC & customer": set("name gender marital_status dob nationality profession father_name mother_name spouse_name father_in_law grandfather_name citizenship citizenship_issue_date issued_district national_id license_no license_expiry passport_no passport_issue_date passport_expiry pan pan_issue_date tax_office permanent_address current_address phone mobile alternate_mobile email alternate_email pep experience_years other_bank_loans".split()),
    "Facility & vehicle": set("type vehicle_type route brand model year dealer dealer_phone dealer_email quotation down_payment amount tenure_months rate emi_frequency purpose existing_exposure vehicles".split()),
    "Documents": set("document_status extracted_value verification_result".split()),
    "CIC": set("cir_number report_date name dob citizenship citizenship_issue_date father_name grandfather_name probability_default active_overdue last_six_overdue max_overdue_days min_overdue_days recent_overdue_amount recent_overdue_date blacklist_active blacklist_history active_accounts institutions total_emi sanctioned_amount outstanding overdue_lt30 overdue_31_60 overdue_61_90 overdue_gt90 account_category guaranteed_category".split()),
    "Repayment": set("declared_income industry_average tax_income bank_average agreement_income other_emi assessment".split()),
    "Security & valuation": set("security_type property_details valuation_date area_valuated fmv dv market_rate government_rate frontage road row boundary_north boundary_south boundary_east boundary_west site_risks group_name group_limit group_outstanding review_notes".split()),
    "Guarantor": set("name dob relationship citizenship address profession income pep additional_guarantors".split()),
    "Credit decision": set("recommendation authority rationale conditions".split()),
}
ROLES = ["RO", "Branch Manager", "Cluster Head", "Risk Reviewer", "Approver", "CAD", "Superadmin"]
STAGES = ["RO Review", "Branch Manager Review", "Cluster Head Review", "Risk Review", "Approval", "CAD", "Completed", "Declined"]
STAGE_OWNER = {"RO Review": "RO", "Branch Manager Review": "Branch Manager", "Cluster Head Review": "Cluster Head", "Risk Review": "Risk Reviewer", "Approval": "Approver", "CAD": "CAD", "Completed": "CAD", "Declined": "Approver"}
NEXT_STAGE = {"RO Review": "Branch Manager Review", "Branch Manager Review": "Cluster Head Review", "Cluster Head Review": "Risk Review", "Risk Review": "Approval", "Approval": "CAD", "CAD": "Completed"}
PREVIOUS_STAGE = {"Branch Manager Review": "RO Review", "Cluster Head Review": "Branch Manager Review", "Risk Review": "Cluster Head Review", "Approval": "Risk Review", "CAD": "Approval"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc, tb):
        try: return super().__exit__(exc_type, exc, tb)
        finally: self.close()


def connect() -> sqlite3.Connection:
    db = sqlite3.connect(DB_PATH, factory=ClosingConnection)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return f"{salt.hex()}:{derived.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        salt_hex, expected = encoded.split(":", 1)
        actual = hash_password(password, bytes.fromhex(salt_hex)).split(":", 1)[1]
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def permission_defaults(role: str) -> dict:
    readable = {
        "RO": ["KYC & customer", "Facility & vehicle", "Documents", "CIC", "Repayment", "Security & valuation", "Guarantor", "Workflow"],
        "Branch Manager": ["KYC & customer", "Facility & vehicle", "Documents", "CIC", "Repayment", "Security & valuation", "Guarantor", "Workflow"],
        "Cluster Head": ["KYC & customer", "Facility & vehicle", "Documents", "CIC", "Repayment", "Security & valuation", "Guarantor", "Workflow", "Reporting"],
        "Risk Reviewer": ["KYC & customer", "Facility & vehicle", "Documents", "CIC", "Repayment", "Security & valuation", "Guarantor", "Workflow"],
        "Approver": ["KYC & customer", "Facility & vehicle", "Documents", "CIC", "Repayment", "Security & valuation", "Guarantor", "Workflow", "Credit decision", "Reporting"],
        "CAD": ["Facility & vehicle", "Documents", "Security & valuation", "Workflow", "Credit decision"],
    }
    if role == "Superadmin":
        return {m: {"__module": {"C": True, "R": True, "U": True, "D": True}, **{f: {"C": True, "R": True, "U": True, "D": True} for f in fields}} for m, fields in MODULE_FIELDS.items()}
    result = {}
    for module, fields in MODULE_FIELDS.items():
        allowed = module in readable.get(role, [])
        create = role == "RO" and module in ["KYC & customer", "Facility & vehicle", "Documents", "Guarantor"] or role == "CAD" and module in ["Documents", "Security & valuation"]
        delete = role == "RO" and module == "Documents"
        update = (role == "RO" and module in ["KYC & customer", "Facility & vehicle", "Documents", "Repayment", "Security & valuation", "Guarantor", "Workflow"]
                  or role in ["Branch Manager", "Cluster Head"] and module == "Workflow"
                  or role == "Risk Reviewer" and module in ["CIC", "Repayment", "Security & valuation", "Workflow"]
                  or role == "Approver" and module in ["Credit decision", "Workflow"]
                  or role == "CAD" and module in ["Documents", "Security & valuation", "Workflow"])
        parent = {"C": bool(create), "R": bool(allowed), "U": bool(update), "D": bool(delete)}
        result[module] = {"__module": parent}
        for field in fields:
            result[module][field] = {"C": bool(create), "R": bool(allowed), "U": bool(update), "D": False}
    return result


def init_db() -> None:
    UPLOAD_DIR.mkdir(exist_ok=True)
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS roles(name TEXT PRIMARY KEY, permissions TEXT NOT NULL, built_in INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL, email TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL, scope TEXT NOT NULL, branch TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, csrf TEXT NOT NULL, expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS applications(id TEXT PRIMARY KEY, customer_name TEXT NOT NULL, branch TEXT NOT NULL, stage TEXT NOT NULL, amount INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'In review', created_by INTEGER NOT NULL REFERENCES users(id), data TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY AUTOINCREMENT, application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE, action TEXT NOT NULL, from_stage TEXT NOT NULL, to_stage TEXT NOT NULL, actor_id INTEGER NOT NULL REFERENCES users(id), actor_role TEXT NOT NULL, remarks TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS documents(id TEXT PRIMARY KEY, application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE, original_name TEXT NOT NULL, stored_name TEXT NOT NULL, content_type TEXT NOT NULL, size INTEGER NOT NULL, document_type TEXT NOT NULL, uploaded_by INTEGER NOT NULL REFERENCES users(id), status TEXT NOT NULL DEFAULT 'Pending verification', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS checklist_reviews(application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE, item_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Pending', document_id TEXT REFERENCES documents(id) ON DELETE SET NULL, remarks TEXT NOT NULL DEFAULT '', updated_by INTEGER REFERENCES users(id), updated_at TEXT NOT NULL, PRIMARY KEY(application_id,item_id));
        CREATE TABLE IF NOT EXISTS admin_history(id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER NOT NULL REFERENCES users(id), action TEXT NOT NULL, target TEXT NOT NULL, details TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_apps_stage ON applications(stage);
        CREATE INDEX IF NOT EXISTS idx_apps_branch ON applications(branch);
        CREATE INDEX IF NOT EXISTS idx_history_app ON history(application_id, id);
        """)
        for role in ROLES:
            db.execute("INSERT OR IGNORE INTO roles(name,permissions,built_in,created_at) VALUES(?,?,1,?)", (role, json.dumps(permission_defaults(role)), now_iso()))
            role_row = db.execute("SELECT permissions FROM roles WHERE name=?", (role,)).fetchone()
            permissions = json.loads(role_row["permissions"])
            defaults = permission_defaults(role)
            changed = False
            for module, fields in MODULE_FIELDS.items():
                permissions.setdefault(module, {"__module": defaults[module]["__module"]})
                permissions[module].setdefault("__module", defaults[module]["__module"])
                for field in fields:
                    if field not in permissions[module]:
                        permissions[module][field] = defaults[module][field]
                        changed = True
            if changed:
                db.execute("UPDATE roles SET permissions=? WHERE name=?", (json.dumps(permissions), role))
        seeds = [
            ("ro.alex", "Alex Shrestha", "alex@northstar.test", "RO", ["Lalitpur"], "Lalitpur"),
            ("bm.mina", "Mina Karki", "mina@northstar.test", "Branch Manager", ["Lalitpur"], "Lalitpur"),
            ("ch.rabin", "Rabin Joshi", "rabin@northstar.test", "Cluster Head", ["Lalitpur", "Kathmandu", "Bhaktapur", "Patan", "Kirtipur"], "Central Cluster"),
            ("risk.nirmala", "Nirmala Rai", "risk@northstar.test", "Risk Reviewer", ["All"], "Risk"),
            ("approver.sanjay", "Sanjay Basnet", "approver@northstar.test", "Approver", ["All"], "Credit"),
            ("cad.bikash", "Bikash Thapa", "cad@northstar.test", "CAD", ["All"], "CAD"),
            ("admin", "System Administrator", "admin@northstar.test", "Superadmin", ["All"], "All branches"),
        ]
        for username, display, email, role, scope, branch in seeds:
            existing = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
            if not existing:
                db.execute("INSERT INTO users(username,display_name,email,password_hash,role,scope,branch,created_at) VALUES(?,?,?,?,?,?,?,?)",
                           (username, display, email, hash_password("Demo123!"), role, json.dumps(scope), branch, now_iso()))
        examples = [
            ("AL-2026-04821", "Ramesh Kumar", "Lalitpur", "RO Review", 3200000, "ro.alex", {"kyc": {"name": "Ramesh Kumar", "dob": "1990-08-14", "citizenship": "42-01-75-00824", "pep": "No"}, "facility": {"type": "Automobile Loan", "vehicle": "Hyundai Creta SX", "year": 2025, "quotation": 5000000, "amount": 3200000, "tenure_months": 60, "rate": 10.5}, "guarantor": {"name": "Sita Kumar", "dob": "1985-02-08"}}),
            ("AL-2026-04820", "Mina Gurung", "Kathmandu", "Branch Manager Review", 2450000, "ro.alex", {"kyc": {"name": "Mina Gurung"}, "facility": {"amount": 2450000}}),
            ("AL-2026-04819", "Prakash Thapa", "Bhaktapur", "Cluster Head Review", 4100000, "ro.alex", {"kyc": {"name": "Prakash Thapa"}, "facility": {"amount": 4100000}}),
            ("AL-2026-04818", "Sushila Rai", "Patan", "Approval", 2850000, "ro.alex", {"kyc": {"name": "Sushila Rai"}, "facility": {"amount": 2850000}}),
            ("AL-2026-04817", "Bikash Adhikari", "Kirtipur", "CAD", 3600000, "ro.alex", {"kyc": {"name": "Bikash Adhikari"}, "facility": {"amount": 3600000}}),
            ("AL-2026-04816", "Anita Shahi", "Kathmandu", "CAD", 1950000, "ro.alex", {"kyc": {"name": "Anita Shahi"}, "facility": {"amount": 1950000}}),
            ("AL-2026-04815", "Sanjay Bista", "Lalitpur", "Risk Review", 5200000, "ro.alex", {"kyc": {"name": "Sanjay Bista"}, "facility": {"amount": 5200000}}),
            ("AL-2026-04814", "Nisha Tamang", "Bhaktapur", "RO Review", 1750000, "ro.alex", {"kyc": {"name": "Nisha Tamang"}, "facility": {"amount": 1750000}}),
            ("AL-2026-04813", "Dinesh Karki", "Patan", "Approval", 3000000, "ro.alex", {"kyc": {"name": "Dinesh Karki"}, "facility": {"amount": 3000000}}),
            ("AL-2026-04812", "Kabita KC", "Kirtipur", "CAD", 2750000, "ro.alex", {"kyc": {"name": "Kabita KC"}, "facility": {"amount": 2750000}}),
            ("AL-2026-04811", "Hari Poudel", "Kathmandu", "Risk Review", 4600000, "ro.alex", {"kyc": {"name": "Hari Poudel"}, "facility": {"amount": 4600000}}),
        ]
        users = {r["username"]: r["id"] for r in db.execute("SELECT id,username FROM users")}
        for app_id, name, branch, stage, amount, creator, data in examples:
            db.execute("INSERT OR IGNORE INTO applications(id,customer_name,branch,stage,amount,created_by,data,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                       (app_id, name, branch, stage, amount, users[creator], json.dumps(data), now_iso(), now_iso()))


def field_group(module: str, key: str) -> str | None:
    k = key.lower().replace("_", " ")
    if module == "KYC & customer":
        if "pep" in k: return "PEP declaration"
        if any(x in k for x in ["citizenship", "national id", "issue date", "passport", "license", "pan"]): return "Citizenship & national ID"
        if any(x in k for x in ["address", "phone", "mobile", "email", "ward", "district", "province"]): return "Address & contacts"
        return "Customer identity"
    if module == "Facility & vehicle":
        if any(x in k for x in ["quotation", "down payment"]): return "Quotation & down payment"
        if any(x in k for x in ["vehicle", "year", "make", "model"]): return "Vehicle identity"
        if any(x in k for x in ["rate", "emi", "purpose", "frequency"]): return "Rate, EMI & purpose"
        return "Facility amount & tenure"
    if module == "CIC":
        if any(x in k for x in ["probability", "default"]): return "Probability of default"
        if any(x in k for x in ["overdue", "installment"]): return "Overdue history"
        if "blacklist" in k: return "Blacklisting & accounts"
        if any(x in k for x in ["account", "facility", "institution"]): return "Blacklisting & accounts"
        return "CIC identity data"
    if module == "Repayment":
        if any(x in k for x in ["income", "industry average"]): return "Declared income"
        if any(x in k for x in ["tax", "bank", "proof", "statement"]): return "Tax & bank evidence"
        if any(x in k for x in ["emi", "obligation"]): return "Existing obligations"
        return "Income analysis"
    if module == "Security & valuation":
        if any(x in k for x in ["fmv", "dv", "valuation", "market rate"]): return "FMV / DV"
        if any(x in k for x in ["boundary", "frontage", "road", "row", "risk"]): return "Site & boundary risks"
        if any(x in k for x in ["group", "limit", "outstanding"]): return "Group limit & outstanding"
        return "Collateral details"
    if module == "Guarantor":
        if "pep" in k: return "PEP declaration"
        if any(x in k for x in ["dob", "birth", "age"]): return "Date of birth & age"
        if any(x in k for x in ["income", "occupation", "profession"]): return "Income & occupation"
        return "Guarantor identity"
    if module == "Documents":
        if any(x in k for x in ["security", "execution"]): return "Security documents"
        if any(x in k for x in ["ocr", "extracted"]): return "OCR extracted values"
        if any(x in k for x in ["verification", "status"]): return "Verification result"
        return "Document upload"
    if module == "Credit decision":
        if "rationale" in k: return "Decision rationale"
        if "authority" in k or "approver" in k: return "Approval authority"
        if "condition" in k: return "Conditions"
        return "Recommendation"
    if module == "Workflow":
        if "remark" in k or "note" in k: return "Return remarks"
        if "return" in k: return "Return file"
        if "initiat" in k or "submit" in k: return "Initiate / submit"
        return "Forward file"
    if module == "Reporting":
        if "export" in k: return "Export data"
        if "branch" in k: return "Branch reports"
        if "sensitive" in k: return "Sensitive fields"
        return "Portfolio reports"
    return None


class CreditHandler(BaseHTTPRequestHandler):
    server_version = "CreditReview/1.0"

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {self.address_string()} {fmt % args}")

    def send_json(self, status: int, obj: dict, headers: dict | None = None):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
        for key, value in (headers or {}).items(): self.send_header(key, value)
        self.end_headers(); self.wfile.write(body)

    def body_bytes(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_BODY: raise ValueError("Request body is too large")
        return self.rfile.read(length)

    def body_json(self) -> dict:
        raw = self.body_bytes()
        if not raw: return {}
        try: return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError): raise ValueError("Request must contain valid JSON")

    def session_user(self):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get("cr_session")
        if not morsel: return None, None
        token = morsel.value
        with connect() as db:
            row = db.execute("SELECT s.csrf,s.expires_at,u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
            if not row or row["expires_at"] < time.time() or not row["active"]:
                return None, None
            user = dict(row); user["scope"] = json.loads(user["scope"])
            return user, row["csrf"]

    def has_permission(self, role: str, module: str, operation: str, field: str | None = None) -> bool:
        if role == "Superadmin": return True
        with connect() as db:
            row = db.execute("SELECT permissions FROM roles WHERE name=?", (role,)).fetchone()
        if not row: return False
        perms = json.loads(row["permissions"])
        module_perm = perms.get(module, {}).get("__module", {})
        if not module_perm.get("R", False): return False
        if not module_perm.get(operation, False): return False
        if field:
            field_perm = perms.get(module, {}).get(field, {})
            if not field_perm.get("R", False) or not field_perm.get(operation, False): return False
        return True

    def require_auth(self, csrf=False):
        user, token = self.session_user()
        if not user:
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Sign in required"}); return None
        if csrf and not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), token or ""):
            self.send_json(HTTPStatus.FORBIDDEN, {"error": "Invalid CSRF token"}); return None
        return user

    def can_see_app(self, user: dict, app: sqlite3.Row) -> bool:
        role = user["role"]
        if role == "Superadmin": return True
        if role == "RO": return app["created_by"] == user["id"]
        return "All" in user["scope"] or app["branch"] in user["scope"]

    def app_dict(self, app: sqlite3.Row, user: dict, detail=False) -> dict:
        data = json.loads(app["data"])
        cleaned = {}
        for module, module_name in [("kyc", "KYC & customer"), ("facility", "Facility & vehicle"), ("documents", "Documents"), ("cic", "CIC"), ("repayment", "Repayment"), ("security", "Security & valuation"), ("guarantor", "Guarantor"), ("decision", "Credit decision")]:
            if not self.has_permission(user["role"], module_name, "R"):
                continue
            section = data.get(module)
            if not isinstance(section, dict): continue
            visible = {}
            for key, value in section.items():
                group = field_group(module_name, key)
                if group and key in DATA_FIELDS.get(module_name, set()) and self.has_permission(user["role"], module_name, "R", group): visible[key] = value
            cleaned[module] = visible
        customer_visible = self.has_permission(user["role"], "KYC & customer", "R", "Customer identity")
        amount_visible = self.has_permission(user["role"], "Facility & vehicle", "R", "Facility amount & tenure")
        result = {"id": app["id"], "customer_name": app["customer_name"] if customer_visible else "Restricted customer", "branch": app["branch"], "stage": app["stage"], "amount": app["amount"] if amount_visible else None, "status": app["status"], "created_at": app["created_at"], "updated_at": app["updated_at"], "version": app["version"], "data": cleaned}
        if detail:
            with connect() as db:
                docs = db.execute("SELECT id,original_name,content_type,size,document_type,status,created_at FROM documents WHERE application_id=? ORDER BY created_at", (app["id"],)).fetchall()
                hist = db.execute("SELECT h.action,h.from_stage,h.to_stage,h.actor_role,u.display_name,h.remarks,h.created_at FROM history h JOIN users u ON u.id=h.actor_id WHERE application_id=? ORDER BY h.id DESC", (app["id"],)).fetchall()
            if self.has_permission(user["role"], "Documents", "R"):
                result["documents"] = [dict(x) for x in docs]
                result["cad_checklist"] = {"title": CHECKLIST_DOCUMENT["title"], "version": CHECKLIST_DOCUMENT["version"], "notice": CHECKLIST_DOCUMENT["notice"], "sections": CAD_CHECKLIST_SECTIONS}
                with connect() as review_db:
                    reviews = review_db.execute("SELECT item_id,status,document_id,remarks,updated_by,updated_at FROM checklist_reviews WHERE application_id=?", (app["id"],)).fetchall()
                result["checklist_reviews"] = {row["item_id"]: dict(row) for row in reviews}
            if self.has_permission(user["role"], "Workflow", "R"):
                result["history"] = [dict(x) for x in hist]
                result["return_remarks"] = self.last_return_remarks(app["id"])
        return result

    def audit(self, db, app_id, action, from_stage, to_stage, user, remarks=""):
        db.execute("INSERT INTO history(application_id,action,from_stage,to_stage,actor_id,actor_role,remarks,created_at) VALUES(?,?,?,?,?,?,?,?)",
                   (app_id, action, from_stage, to_stage, user["id"], user["role"], remarks, now_iso()))

    def do_GET(self):
        parsed = urlparse(self.path); path = unquote(parsed.path)
        if path == "/" or path == "/system": return self.serve_file(BASE / "system.html")
        if path == "/prototype": return self.serve_file(BASE / "index.html")
        if path in ["/system.css", "/system.js", "/role-switch.css", "/cad-review.css"]: return self.serve_file(BASE / path.lstrip("/"))
        if path == "/api/health": return self.send_json(200, {"status": "ok", "service": "Credit Review System"})
        user, _ = self.session_user()
        if not user: return self.send_json(401, {"error": "Sign in required"})
        if path == "/api/me":
            _, csrf = self.session_user()
            return self.send_json(200, {"user": {"id": user["id"], "username": user["username"], "display_name": user["display_name"], "email": user["email"], "role": user["role"], "branch": user["branch"], "scope": user["scope"]}, "csrf": csrf, "modules": MODULE_FIELDS, "permissions": self.role_permissions(user["role"])})
        if path == "/api/applications": return self.list_applications(user, parse_qs(parsed.query))
        if path.startswith("/api/applications/"):
            app_id = path.split("/")[-1]
            with connect() as db: app = db.execute("SELECT * FROM applications WHERE id=?", (app_id,)).fetchone()
            if not app: return self.send_json(404, {"error": "Application not found"})
            if not self.can_see_app(user, app): return self.send_json(403, {"error": "Application outside your scope"})
            if not self.has_permission(user["role"], "Workflow", "R"): return self.send_json(403, {"error": "Workflow read access required"})
            return self.send_json(200, {"application": self.app_dict(app, user, detail=True), "permissions": self.role_permissions(user["role"])})
        if path == "/api/reports": return self.reports(user, parse_qs(parsed.query))
        if path == "/api/admin/access":
            if user["role"] != "Superadmin": return self.send_json(403, {"error": "Superadmin only"})
            return self.admin_access()
        if path.startswith("/api/documents/") and path.endswith("/download"):
            doc_id = path.split("/")[-2]
            return self.download_document(user, doc_id)
        return self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path); path = unquote(parsed.path)
        if path == "/api/login": return self.login()
        user = self.require_auth(csrf=True)
        if not user: return
        if path == "/api/logout":
            cookie = SimpleCookie(self.headers.get("Cookie", "")); token = cookie.get("cr_session")
            if token:
                with connect() as db: db.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.value.encode()).hexdigest(),))
            return self.send_json(200, {"ok": True}, {"Set-Cookie": "cr_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"})
        if path == "/api/applications": return self.create_application(user)
        if path.startswith("/api/applications/") and path.endswith("/transition"):
            return self.transition_application(user, path.split("/")[-2])
        if path.startswith("/api/applications/") and path.endswith("/documents"):
            return self.upload_document(user, path.split("/")[-2])
        if path == "/api/admin/roles": return self.create_role(user)
        if path == "/api/admin/users": return self.create_user(user)
        if path == "/api/admin/audit": return self.admin_audit(user)
        return self.send_json(404, {"error": "Not found"})

    def do_PATCH(self):
        user = self.require_auth(csrf=True)
        if not user: return
        path = unquote(urlparse(self.path).path)
        if path.startswith("/api/applications/"):
            return self.update_application(user, path.split("/")[-1])
        if path.startswith("/api/admin/users/"):
            return self.update_user_role(user, path.split("/")[-1])
        if path.startswith("/api/documents/"):
            return self.update_document_status(user, path.split("/")[-1])
        return self.send_json(404, {"error": "Not found"})

    def do_PUT(self):
        user = self.require_auth(csrf=True)
        if not user: return
        path = unquote(urlparse(self.path).path)
        checklist_match = re.fullmatch(r"/api/applications/([^/]+)/checklist/([^/]+)", path)
        if checklist_match: return self.update_checklist_review(user, checklist_match.group(1), checklist_match.group(2))
        match = re.fullmatch(r"/api/admin/roles/([^/]+)/permissions", path)
        if match: return self.update_role_permissions(user, match.group(1))
        return self.send_json(404, {"error": "Not found"})

    def do_DELETE(self):
        user = self.require_auth(csrf=True)
        if not user: return
        path = unquote(urlparse(self.path).path)
        match = re.fullmatch(r"/api/admin/roles/([^/]+)", path)
        if match: return self.delete_role(user, match.group(1))
        return self.send_json(404, {"error": "Not found"})

    def serve_file(self, path: Path):
        if not path.is_file(): return self.send_error(404)
        body = path.read_bytes(); kind = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        self.send_response(200); self.send_header("Content-Type", kind); self.send_header("Content-Length", str(len(body))); self.send_header("X-Content-Type-Options", "nosniff"); self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"); self.end_headers(); self.wfile.write(body)

    def login(self):
        try: data = self.body_json()
        except ValueError as e: return self.send_json(400, {"error": str(e)})
        username, password = str(data.get("username", "")).strip(), str(data.get("password", ""))
        with connect() as db: user = db.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
        if not user or not verify_password(password, user["password_hash"]): return self.send_json(401, {"error": "Username or password is incorrect"})
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        with connect() as db:
            db.execute("INSERT INTO sessions(token_hash,user_id,csrf,expires_at) VALUES(?,?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), user["id"], csrf, int(time.time())+SESSION_SECONDS))
        return self.send_json(200, {"user": {"id": user["id"], "display_name": user["display_name"], "role": user["role"], "branch": user["branch"]}, "csrf": csrf}, {"Set-Cookie": f"cr_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}"})

    def role_permissions(self, role):
        with connect() as db: row = db.execute("SELECT permissions FROM roles WHERE name=?", (role,)).fetchone()
        return json.loads(row["permissions"]) if row else {}

    def list_applications(self, user, query):
        if not self.has_permission(user["role"], "Workflow", "R"): return self.send_json(403, {"error": "Application queue read access required"})
        with connect() as db:
            apps = db.execute("SELECT * FROM applications ORDER BY updated_at DESC").fetchall()
        rows = []
        stage_filter = query.get("stage", [""])[0]; branch_filter = query.get("branch", [""])[0]; search = query.get("q", [""])[0].lower()
        for app in apps:
            if not self.can_see_app(user, app): continue
            role = user["role"]
            if role not in ["Superadmin", "RO", "Branch Manager", "Cluster Head"] and app["stage"] != "Completed" and STAGE_OWNER.get(app["stage"]) != role: continue
            if role in ["Risk Reviewer", "Approver", "CAD"] and app["stage"] in ["Declined", "Completed"]: continue
            if stage_filter and app["stage"] != stage_filter: continue
            if branch_filter and app["branch"] != branch_filter: continue
            if search and search not in app["id"].lower() and (not self.has_permission(user["role"], "KYC & customer", "R", "Customer identity") or search not in app["customer_name"].lower()): continue
            row = self.app_dict(app, user)
            row["return_remarks"] = self.last_return_remarks(app["id"]) if self.has_permission(role, "Workflow", "R", "Return remarks") else ""
            rows.append(row)
        return self.send_json(200, {"applications": rows, "stages": STAGES})

    def last_return_remarks(self, app_id):
        with connect() as db: row = db.execute("SELECT action,remarks FROM history WHERE application_id=? ORDER BY id DESC LIMIT 1", (app_id,)).fetchone()
        return row["remarks"] if row and row["action"] == "Returned for changes" else ""

    def create_application(self, user):
        if user["role"] != "RO" or not self.has_permission(user["role"], "Workflow", "C") or not self.has_permission(user["role"], "KYC & customer", "C"):
            return self.send_json(403, {"error": "RO create access required"})
        try: data = self.body_json()
        except ValueError as e: return self.send_json(400, {"error": str(e)})
        customer = str(data.get("customer_name", "")).strip()
        facility = data.get("data", {}).get("facility", {})
        if not customer: return self.send_json(400, {"error": "Customer name is required"})
        try: amount = max(0, int(facility.get("amount", 0)))
        except (ValueError, TypeError): return self.send_json(400, {"error": "Loan amount must be numeric"})
        branch = user["branch"]
        app_id = "CR-" + datetime.now().strftime("%Y%m%d") + "-" + secrets.token_hex(3).upper()
        payload = data.get("data", {})
        if not isinstance(payload, dict): return self.send_json(400, {"error": "Application data must be an object"})
        module_keys = {"kyc":"KYC & customer","facility":"Facility & vehicle","guarantor":"Guarantor"}
        for section, fields in payload.items():
            module = module_keys.get(section)
            if not module or not isinstance(fields, dict): return self.send_json(400, {"error": "Unsupported application section"})
            for key in fields:
                group = field_group(module, key)
                if key not in DATA_FIELDS[module] or not group or not self.has_permission(user["role"], module, "C", group): return self.send_json(403, {"error": f"No create permission for {module} / {group or key}"})
        with connect() as db:
            db.execute("INSERT INTO applications(id,customer_name,branch,stage,amount,created_by,data,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)", (app_id, customer, branch, "RO Review", amount, user["id"], json.dumps(payload), now_iso(), now_iso()))
            self.audit(db, app_id, "Application created", "", "RO Review", user, "Draft created by RO")
        return self.send_json(201, {"id": app_id, "stage": "RO Review", "version": 1})

    def update_application(self, user, app_id):
        try: patch = self.body_json()
        except ValueError as e: return self.send_json(400, {"error": str(e)})
        with connect() as db:
            app = db.execute("SELECT * FROM applications WHERE id=?", (app_id,)).fetchone()
            if not app: return self.send_json(404, {"error": "Application not found"})
            if not self.can_see_app(user, app): return self.send_json(403, {"error": "Application outside your scope"})
            if user["role"] != "Superadmin" and STAGE_OWNER.get(app["stage"]) != user["role"]: return self.send_json(403, {"error": "Only the assigned stage role can edit this application"})
            expected_version = patch.get("version")
            if expected_version is not None and int(expected_version) != app["version"]: return self.send_json(409, {"error": "Application changed since it was opened. Reload before saving."})
            data = json.loads(app["data"]); changed = False
            for key, fields in patch.get("data", {}).items():
                module = {"kyc": "KYC & customer", "facility": "Facility & vehicle", "documents": "Documents", "cic": "CIC", "repayment": "Repayment", "security": "Security & valuation", "guarantor": "Guarantor", "decision": "Credit decision"}.get(key)
                if not module: continue
                if not isinstance(fields, dict): return self.send_json(400, {"error": "Each module must be an object"})
                for field, value in fields.items():
                    group = field_group(module, field)
                    if field not in DATA_FIELDS.get(module, set()) or not group: return self.send_json(400, {"error": f"Unsupported field: {module} / {field}"})
                    if not self.has_permission(user["role"], module, "U", group): return self.send_json(403, {"error": f"No update permission for {module} / {group}"})
                    data.setdefault(key, {})[field] = value; changed = True
            if not changed: return self.send_json(400, {"error": "No permitted fields to update"})
            customer = str(data.get("kyc", {}).get("name", app["customer_name"]))
            try: amount = int(data.get("facility", {}).get("amount", app["amount"]) or 0)
            except (ValueError, TypeError): return self.send_json(400, {"error": "Loan amount must be numeric"})
            db.execute("UPDATE applications SET customer_name=?,amount=?,data=?,updated_at=?,version=version+1 WHERE id=?", (customer, max(0, amount), json.dumps(data), now_iso(), app_id))
        return self.send_json(200, {"ok": True, "version": app["version"]+1})

    def transition_application(self, user, app_id):
        try: request = self.body_json()
        except ValueError as e: return self.send_json(400, {"error": str(e)})
        action = request.get("action"); remarks = str(request.get("remarks", "")).strip()
        with connect() as db:
            app = db.execute("SELECT * FROM applications WHERE id=?", (app_id,)).fetchone()
            if not app: return self.send_json(404, {"error": "Application not found"})
            if not self.can_see_app(user, app): return self.send_json(403, {"error": "Application outside your scope"})
            stage = app["stage"]
            expected_version = request.get("version")
            if expected_version is not None and int(expected_version) != app["version"]: return self.send_json(409, {"error": "Application changed since it was opened. Reload before acting."})
            if user["role"] != "Superadmin" and STAGE_OWNER.get(stage) != user["role"]: return self.send_json(403, {"error": "Only the assigned stage role can move this file"})
            if action == "return":
                if not remarks: return self.send_json(400, {"error": "Return remarks are required"})
                target = PREVIOUS_STAGE.get(stage)
                if not target: return self.send_json(409, {"error": "This stage has no previous reviewer"})
                for permission_field in ["Return file", "Return remarks"]:
                    if not self.has_permission(user["role"], "Workflow", "U", permission_field): return self.send_json(403, {"error": "Role lacks return permission"})
                db.execute("UPDATE applications SET stage=?,status='Returned for changes',updated_at=?,version=version+1 WHERE id=?", (target, now_iso(), app_id))
                self.audit(db, app_id, "Returned for changes", stage, target, user, remarks)
            elif action == "forward":
                permission_field = "Initiate / submit" if stage == "RO Review" else "Forward file"
                if not self.has_permission(user["role"], "Workflow", "U", permission_field): return self.send_json(403, {"error": "Role lacks forward permission"})
                if stage == "RO Review":
                    with connect() as docs_db: present = {r["document_type"].strip().lower() for r in docs_db.execute("SELECT document_type FROM documents WHERE application_id=?", (app_id,)).fetchall()}
                    required = ["citizenship", "vehicle quotation", "income document", "guarantor citizenship"]
                    missing = [name for name in required if name not in present]
                    if missing: return self.send_json(409, {"error": "Upload required documents before initiation: " + ", ".join(missing)})
                    application_data = json.loads(app["data"])
                    if not application_data.get("kyc", {}).get("name") or not application_data.get("kyc", {}).get("citizenship"):
                        return self.send_json(409, {"error": "Borrower name and citizenship number are required before initiation"})
                    if not application_data.get("facility", {}).get("quotation") or not application_data.get("facility", {}).get("amount"):
                        return self.send_json(409, {"error": "Quotation amount and proposed loan amount are required before initiation"})
                    if not application_data.get("guarantor", {}).get("name") or not application_data.get("guarantor", {}).get("citizenship"):
                        return self.send_json(409, {"error": "Guarantor name and citizenship number are required before initiation"})
                if stage == "Approval":
                    decision = request.get("decision", {})
                    recommendation = str(decision.get("recommendation", ""))
                    rationale = str(decision.get("rationale", "")).strip()
                    if not recommendation or not rationale: return self.send_json(400, {"error": "Recommendation and decision rationale are required"})
                    if recommendation == "Return for clarification": return self.send_json(400, {"error": "Use Return to Risk Reviewer and provide return remarks"})
                    if not self.has_permission(user["role"], "Credit decision", "U", "Recommendation") or not self.has_permission(user["role"], "Credit decision", "U", "Decision rationale"):
                        return self.send_json(403, {"error": "Decision field permission is required"})
                    target = "Declined" if recommendation == "Recommend decline" else "CAD"
                    data = json.loads(app["data"]); data["decision"] = {"recommendation": recommendation, "rationale": rationale, "authority": decision.get("authority", ""), "by": user["display_name"], "at": now_iso()}
                    db.execute("UPDATE applications SET stage=?,status=?,data=?,updated_at=?,version=version+1 WHERE id=?", (target, "Declined" if target == "Declined" else "Approved", json.dumps(data), now_iso(), app_id))
                    self.audit(db, app_id, f"Decision · {recommendation}", stage, target, user, rationale)
                else:
                    if stage == "CAD":
                        with connect() as review_db:
                            reviews = {row["item_id"]: row["status"] for row in review_db.execute("SELECT item_id,status FROM checklist_reviews WHERE application_id=?", (app_id,)).fetchall()}
                        pending = [item_id for item_id, _, _ in CAD_CHECKLIST_ITEMS if reviews.get(item_id, "Pending") not in ["Verified", "Not Applicable"]]
                        if pending:
                            return self.send_json(409, {"error": f"CAD review has {len(pending)} checklist item(s) pending or discrepant. Resolve them or return the file with remarks before completion."})
                    target = NEXT_STAGE.get(stage)
                    if not target: return self.send_json(409, {"error": "This stage cannot be forwarded"})
                    status = "Completed" if target == "Completed" else "In review"
                    db.execute("UPDATE applications SET stage=?,status=?,updated_at=?,version=version+1 WHERE id=?", (target, status, now_iso(), app_id))
                    self.audit(db, app_id, "CAD completed" if target == "Completed" else "Forwarded", stage, target, user, remarks)
            else: return self.send_json(400, {"error": "Action must be forward or return"})
            new = db.execute("SELECT * FROM applications WHERE id=?", (app_id,)).fetchone()
        return self.send_json(200, {"application": self.app_dict(new, user, detail=True)})

    def role_record(self, role):
        with connect() as db: return db.execute("SELECT permissions FROM roles WHERE name=?", (role,)).fetchone()

    def admin_access(self):
        with connect() as db:
            users = db.execute("SELECT id,username,display_name,email,role,scope,branch,active,created_at FROM users ORDER BY role,display_name").fetchall()
            roles = db.execute("SELECT name,permissions,built_in,created_at FROM roles ORDER BY built_in DESC,name").fetchall()
        return self.send_json(200, {"users": [{**dict(u), "scope": json.loads(u["scope"])} for u in users], "roles": [{**dict(r), "permissions": json.loads(r["permissions"])} for r in roles], "modules": MODULE_FIELDS})

    def admin_log(self, db, actor, action, target, details=""):
        db.execute("INSERT INTO admin_history(actor_id,action,target,details,created_at) VALUES(?,?,?,?,?)", (actor["id"], action, target, details, now_iso()))

    def admin_audit(self, user):
        if user["role"] != "Superadmin": return self.send_json(403, {"error": "Superadmin only"})
        with connect() as db: rows = db.execute("SELECT a.action,a.target,a.details,a.created_at,u.display_name FROM admin_history a JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 200").fetchall()
        return self.send_json(200, {"events": [dict(r) for r in rows]})

    def create_user(self, user):
        if user["role"] != "Superadmin": return self.send_json(403, {"error": "Superadmin only"})
        try: data = self.body_json()
        except ValueError as e: return self.send_json(400, {"error": str(e)})
        username = str(data.get("username", "")).strip(); display = str(data.get("display_name", "")).strip()
        email = str(data.get("email", "")).strip(); password = str(data.get("password", ""))
        role = str(data.get("role", "")); branch = str(data.get("branch", "")).strip(); scope = data.get("scope", [branch])
        if not re.fullmatch(r"[A-Za-z0-9._-]{3,50}", username): return self.send_json(400, {"error": "Username must be 3–50 letters, numbers, dots, underscores, or hyphens"})
        if not display or len(display) > 100 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email): return self.send_json(400, {"error": "Valid name and email are required"})
        if len(password) < 12: return self.send_json(400, {"error": "Initial password must be at least 12 characters"})
        if not branch or not isinstance(scope, list) or any(not isinstance(x, str) for x in scope): return self.send_json(400, {"error": "Branch and scope are required"})
        with connect() as db:
            if not db.execute("SELECT name FROM roles WHERE name=?", (role,)).fetchone(): return self.send_json(400, {"error": "Role is not available"})
            try:
                cur = db.execute("INSERT INTO users(username,display_name,email,password_hash,role,scope,branch,created_at) VALUES(?,?,?,?,?,?,?,?)", (username,display,email,hash_password(password),role,json.dumps(scope),branch,now_iso()))
            except sqlite3.IntegrityError: return self.send_json(409, {"error": "Username already exists"})
            self.admin_log(db,user,"User created and role assigned",username,f"role={role}; branch={branch}")
        return self.send_json(201,{"id":cur.lastrowid,"username":username,"role":role})

    def create_role(self, user):
        if user["role"] != "Superadmin": return self.send_json(403, {"error": "Superadmin only"})
        try: data = self.body_json()
        except ValueError as e: return self.send_json(400, {"error": str(e)})
        name = str(data.get("name", "")).strip()
        if not name or name in ROLES or len(name) > 50: return self.send_json(400, {"error": "Provide a unique custom role name (max 50 characters)"})
        permissions = {module: {"__module": {"C": False, "R": False, "U": False, "D": False}, **{field: {"C": False, "R": False, "U": False, "D": False} for field in fields}} for module, fields in MODULE_FIELDS.items()}
        try:
            with connect() as db: db.execute("INSERT INTO roles(name,permissions,built_in,created_at) VALUES(?,?,0,?)", (name, json.dumps(permissions), now_iso()))
        except sqlite3.IntegrityError: return self.send_json(409, {"error": "Role already exists"})
        with connect() as db: self.admin_log(db,user,"Custom role created",name)
        return self.send_json(201, {"name": name, "permissions": permissions})

    def update_role_permissions(self, user, role):
        if user["role"] != "Superadmin": return self.send_json(403, {"error": "Superadmin only"})
        if role == "Superadmin": return self.send_json(403, {"error": "Superadmin permissions are fixed at full access"})
        try: incoming = self.body_json().get("permissions", {})
        except ValueError as e: return self.send_json(400, {"error": str(e)})
        normalized = {}
        for module, fields in MODULE_FIELDS.items():
            source = incoming.get(module, {}) if isinstance(incoming, dict) else {}
            normalized[module] = {}
            for field in ["__module", *fields]:
                rights = source.get(field, {}) if isinstance(source, dict) else {}
                normalized[module][field] = {op: bool(rights.get(op, False)) for op in "CRUD"}
        with connect() as db:
            existing = db.execute("SELECT name FROM roles WHERE name=?", (role,)).fetchone()
            if not existing: return self.send_json(404, {"error": "Role not found"})
            db.execute("UPDATE roles SET permissions=? WHERE name=?", (json.dumps(normalized), role))
            self.admin_log(db,user,"Role permissions updated",role,"Module and field CRUD matrix saved")
        return self.send_json(200, {"ok": True, "role": role})

    def update_user_role(self, user, user_id):
        if user["role"] != "Superadmin": return self.send_json(403, {"error": "Superadmin only"})
        try: data = self.body_json()
        except ValueError as e: return self.send_json(400, {"error": str(e)})
        with connect() as db:
            target = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            if not target: return self.send_json(404, {"error": "User not found"})
            if target["role"] == "Superadmin" and user["id"] == target["id"]: return self.send_json(403, {"error": "Cannot change your own Superadmin assignment"})
            role = str(data.get("role", target["role"]))
            exists = db.execute("SELECT name FROM roles WHERE name=?", (role,)).fetchone()
            if not exists: return self.send_json(400, {"error": "Role is not available"})
            scope = data.get("scope", json.loads(target["scope"]))
            branch = str(data.get("branch", target["branch"]))
            if not isinstance(scope, list) or any(not isinstance(x, str) for x in scope): return self.send_json(400, {"error": "Scope must be a list of branches"})
            db.execute("UPDATE users SET role=?,scope=?,branch=? WHERE id=?", (role, json.dumps(scope), branch, user_id))
            self.admin_log(db,user,"User assignment updated",target["username"],f"role={role}; branch={branch}; scope={json.dumps(scope)}")
        return self.send_json(200, {"ok": True})

    def delete_role(self, user, role):
        if user["role"] != "Superadmin": return self.send_json(403, {"error": "Superadmin only"})
        with connect() as db:
            row = db.execute("SELECT built_in FROM roles WHERE name=?", (role,)).fetchone()
            if not row: return self.send_json(404, {"error": "Role not found"})
            if row["built_in"]: return self.send_json(403, {"error": "Built-in roles cannot be deleted"})
            if db.execute("SELECT 1 FROM users WHERE role=? LIMIT 1", (role,)).fetchone(): return self.send_json(409, {"error": "Reassign users before deleting this role"})
            db.execute("DELETE FROM roles WHERE name=?", (role,))
            self.admin_log(db,user,"Custom role deleted",role)
        return self.send_json(200, {"ok": True})

    def reports(self, user, query):
        if not self.has_permission(user["role"], "Reporting", "R", "Portfolio reports"): return self.send_json(403, {"error": "Reporting access is not assigned to this role"})
        if query.get("export", [""])[0] == "1" and not self.has_permission(user["role"], "Reporting", "R", "Export data"): return self.send_json(403, {"error": "Report export access is not assigned to this role"})
        with connect() as db: apps = db.execute("SELECT * FROM applications ORDER BY created_at DESC").fetchall()
        branch, stage, from_date, to_date = (query.get(k, [""])[0] for k in ["branch", "stage", "from", "to"])
        rows = []
        for app in apps:
            if not self.can_see_app(user, app): continue
            date = app["created_at"][:10]
            if branch and app["branch"] != branch or stage and app["stage"] != stage or from_date and date < from_date or to_date and date > to_date: continue
            rows.append({"id": app["id"], "customer_name": app["customer_name"], "branch": app["branch"], "stage": app["stage"], "amount": app["amount"], "status": app["status"], "created_at": app["created_at"]})
        amount_visible = self.has_permission(user["role"], "Facility & vehicle", "R", "Facility amount & tenure")
        name_visible = self.has_permission(user["role"], "KYC & customer", "R", "Customer identity") and self.has_permission(user["role"], "Reporting", "R", "Sensitive fields")
        for row in rows:
            if not amount_visible: row["amount"] = None
            if not name_visible: row["customer_name"] = "Restricted customer"
        total = sum(row["amount"] or 0 for row in rows)
        counts = {}
        for row in rows: counts[row["stage"]] = counts.get(row["stage"], 0) + 1
        return self.send_json(200, {"applications": rows, "summary": {"count": len(rows), "requested_exposure": total, "by_stage": counts}, "branches": sorted({row["branch"] for row in rows}), "allow_export": self.has_permission(user["role"], "Reporting", "R", "Export data")})

    def upload_document(self, user, app_id):
        if not self.has_permission(user["role"], "Documents", "C", "Document upload"): return self.send_json(403, {"error": "Document upload permission required"})
        with connect() as db: app = db.execute("SELECT * FROM applications WHERE id=?", (app_id,)).fetchone()
        if not app: return self.send_json(404, {"error": "Application not found"})
        if not self.can_see_app(user, app): return self.send_json(403, {"error": "Application outside your scope"})
        if user["role"] != "Superadmin" and STAGE_OWNER.get(app["stage"]) != user["role"]: return self.send_json(403, {"error": "Only the assigned stage role can upload files"})
        raw = self.body_bytes(); content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type: return self.send_json(400, {"error": "Expected multipart file upload"})
        message = BytesParser(policy=default).parsebytes((f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n").encode()+raw)
        file_part = next((p for p in message.iter_parts() if p.get_filename()), None)
        if not file_part: return self.send_json(400, {"error": "Select a file"})
        payload = file_part.get_payload(decode=True) or b""
        if not payload or len(payload) > 10*1024*1024: return self.send_json(400, {"error": "File must be between 1 byte and 10 MB"})
        original = Path(file_part.get_filename()).name[:180]
        ext = Path(original).suffix.lower()
        if ext not in [".pdf", ".png", ".jpg", ".jpeg", ".webp"]: return self.send_json(400, {"error": "Allowed file types: PDF, PNG, JPG, JPEG, WEBP"})
        stored = uuid.uuid4().hex + ext; (UPLOAD_DIR/stored).write_bytes(payload)
        doc_id = uuid.uuid4().hex
        doc_type = str(parse_qs(parsed_query(self.path)).get("type", ["Supporting document"])[0])[:80]
        with connect() as db: db.execute("INSERT INTO documents(id,application_id,original_name,stored_name,content_type,size,document_type,uploaded_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)", (doc_id,app_id,original,stored,file_part.get_content_type() or "application/octet-stream",len(payload),doc_type,user["id"],now_iso()))
        return self.send_json(201, {"id": doc_id, "filename": original, "status": "Pending verification", "ocr_status": "Not configured"})

    def update_document_status(self, user, doc_id):
        try: data = self.body_json()
        except ValueError as e: return self.send_json(400, {"error": str(e)})
        status = str(data.get("status", ""))
        if status not in ["Pending verification", "Verified", "Mismatch found", "Needs clarification"]: return self.send_json(400, {"error": "Invalid document status"})
        if not self.has_permission(user["role"], "Documents", "U", "Verification result"): return self.send_json(403, {"error": "Document verification permission required"})
        with connect() as db:
            doc = db.execute("SELECT d.application_id,a.* FROM documents d JOIN applications a ON a.id=d.application_id WHERE d.id=?", (doc_id,)).fetchone()
            if not doc: return self.send_json(404, {"error": "Document not found"})
            if not self.can_see_app(user, doc): return self.send_json(403, {"error": "Application outside your scope"})
            if user["role"] != "Superadmin" and STAGE_OWNER.get(doc["stage"]) != user["role"]: return self.send_json(403, {"error": "Only the assigned stage role can verify documents"})
            db.execute("UPDATE documents SET status=? WHERE id=?", (status, doc_id))
            self.audit(db, doc["application_id"], "Document status updated", doc["stage"], doc["stage"], user, status)
        return self.send_json(200, {"ok": True, "status": status})

    def update_checklist_review(self, user, app_id, item_id):
        try: data = self.body_json()
        except ValueError as e: return self.send_json(400, {"error": str(e)})
        item = next((entry for entry in CAD_CHECKLIST_ITEMS if entry[0] == item_id), None)
        if not item: return self.send_json(404, {"error": "Checklist item not found"})
        status = str(data.get("status", "Pending"))
        remarks = str(data.get("remarks", "")).strip()
        document_id = str(data.get("document_id", "")).strip() or None
        if status not in ["Pending", "Verified", "Discrepancy", "Not Applicable"]: return self.send_json(400, {"error": "Invalid checklist status"})
        if status in ["Discrepancy", "Not Applicable"] and len(remarks) < 5: return self.send_json(400, {"error": "Add specific remarks for a discrepancy or not-applicable item"})
        if status == "Verified" and item_id.startswith("documents--") and not document_id: return self.send_json(400, {"error": "Link the supporting uploaded document before marking this item verified"})
        if not self.has_permission(user["role"], "Documents", "U", "Verification result"): return self.send_json(403, {"error": "Document checklist review permission required"})
        with connect() as db:
            app = db.execute("SELECT * FROM applications WHERE id=?", (app_id,)).fetchone()
            if not app: return self.send_json(404, {"error": "Application not found"})
            if not self.can_see_app(user, app): return self.send_json(403, {"error": "Application outside your scope"})
            if user["role"] != "Superadmin" and (user["role"] != "CAD" or app["stage"] != "CAD"): return self.send_json(403, {"error": "Only CAD can review the document checklist at CAD stage"})
            if document_id:
                linked = db.execute("SELECT id FROM documents WHERE id=? AND application_id=?", (document_id, app_id)).fetchone()
                if not linked: return self.send_json(400, {"error": "Linked document must belong to this application"})
            db.execute("INSERT INTO checklist_reviews(application_id,item_id,status,document_id,remarks,updated_by,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(application_id,item_id) DO UPDATE SET status=excluded.status,document_id=excluded.document_id,remarks=excluded.remarks,updated_by=excluded.updated_by,updated_at=excluded.updated_at",
                       (app_id, item_id, status, document_id, remarks, user["id"], now_iso()))
            from_stage = app["stage"]
            audit_text = f"{status} · {item[2]}" + (f" · {remarks}" if remarks else "")
            self.audit(db, app_id, "CAD checklist review", from_stage, from_stage, user, audit_text)
        return self.send_json(200, {"ok": True, "item_id": item_id, "status": status})

    def download_document(self, user, doc_id):
        if not self.has_permission(user["role"], "Documents", "R", "Document upload"): return self.send_json(403, {"error": "Document read access required"})
        with connect() as db:
            row = db.execute("SELECT d.*,a.created_by,a.branch FROM documents d JOIN applications a ON a.id=d.application_id WHERE d.id=?", (doc_id,)).fetchone()
        if not row: return self.send_json(404, {"error": "Document not found"})
        app = {"created_by": row["created_by"], "branch": row["branch"]}
        if not self.can_see_app(user, app): return self.send_json(403, {"error": "Application outside your scope"})
        file_path = UPLOAD_DIR / row["stored_name"]
        if not file_path.is_file(): return self.send_json(404, {"error": "Stored file is missing"})
        data = file_path.read_bytes(); self.send_response(200); self.send_header("Content-Type", row["content_type"]); self.send_header("Content-Length", str(len(data))); self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{urlquote(row['original_name'])}"); self.send_header("X-Content-Type-Options", "nosniff"); self.end_headers(); self.wfile.write(data)


def parsed_query(path: str) -> str:
    return urlparse(path).query


def main():
    init_db()
    host = os.environ.get("CREDIT_HOST", "127.0.0.1")
    port = int(os.environ.get("CREDIT_PORT", "8000"))
    server = ThreadingHTTPServer((host, port), CreditHandler)
    print(f"Credit Review System running at http://{host}:{port}")
    print("Demo sign-ins: ro.alex / bm.mina / ch.rabin / risk.nirmala / approver.sanjay / cad.bikash / admin")
    print("Demo password for all seeded accounts: Demo123!")
    try: server.serve_forever()
    except KeyboardInterrupt: print("\nStopping Credit Review System")
    finally: server.server_close()


if __name__ == "__main__": main()

