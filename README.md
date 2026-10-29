# AI-Assisted Credit File Review MVP

A local prototype for reviewing **automobile loan** credit-file documents. It combines document text extraction, configurable checklist rules, simple cross-document comparisons, and a downloadable findings report.

## Important limitations

- This is a prototype for synthetic or properly anonymized test documents only.
- It is not approved for production banking use and is not connected to Nabil Bank systems.
- It does not make credit decisions or authorize disbursement.
- Text extraction and rule checks can miss issues or produce false positives. CAD must verify every finding against source documents and current approved policy.
- Do not upload real customer information until the bank has approved the hosting, data handling, security, and AI arrangements.

## Run locally

Requires Python 3.10 or later.

1. Create and activate a virtual environment.
2. Install dependencies: `pip install -r requirements.txt`
3. Start the app: `streamlit run app.py`
4. Upload sample PDF, DOCX, or TXT documents. Scanned PDFs may require OCR; this MVP will warn when little or no text can be extracted.

## Current features

- PDF, DOCX, and TXT uploads.
- Basic document type classification using filename and text cues.
- Rule-based checks for document presence, key fields, and selected automobile-loan checklist items.
- Simple comparison of extracted borrower names and facility amounts across documents.
- Findings categorized as information, review required, or high priority.
- Downloadable JSON review report.

## Repository structure

- `app.py`: Streamlit user interface and review workflow.
- `rules/automobile_loan_rules.json`: editable prototype rules and document checklist.
- `tests/test_review.py`: basic tests for deterministic rule helpers.
- `docs/security_controls.md`: security and governance considerations.

## Next steps before a pilot

1. Confirm the product checklist and rule wording with CAD, Credit Risk, Legal, Compliance, and IT.
2. Add approved, versioned policy sources and page/paragraph citations.
3. Validate extraction and rule performance against a representative set of anonymized files.
4. Add authentication, role-based access, audit logging, encrypted approved storage, and secure deployment.
5. Complete bank security, privacy, model-risk, and regulatory approvals.
