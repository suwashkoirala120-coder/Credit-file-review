import importlib.util
import json
from pathlib import Path

APP_PATH = Path(__file__).resolve().parents[1] / "app.py"
RULES_PATH = Path(__file__).resolve().parents[1] / "rules" / "automobile_loan_rules.json"


def load_rules():
    return json.loads(RULES_PATH.read_text(encoding="utf-8"))


def test_rules_json_is_valid():
    rules = load_rules()
    assert rules["product_name"]
    assert "loan_application" in rules["document_types"]


def test_required_documents_are_configured():
    rules = load_rules()
    assert rules["required_document_types"]
    assert all(item in rules["document_types"] for item in rules["required_document_types"])


def test_rule_severities_are_known():
    rules = load_rules()
    assert all(rule["severity"] in {"info", "low", "medium", "high"} for rule in rules["text_checks"])
