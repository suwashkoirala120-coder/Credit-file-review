# Security and Governance Notes

## Prototype data policy

Use synthetic or properly anonymized documents only. Do not commit customer credit files, identity documents, CIC reports, account statements, loan deeds, credentials, tokens, or secrets to GitHub.

## Before any real-data pilot

- Obtain written approval from the bank's information security, privacy, IT, compliance, legal, and relevant business owners.
- Confirm approved deployment location, data residency, retention, deletion, backup, and incident response arrangements.
- Use encryption in transit and at rest and a bank-approved identity provider.
- Implement least-privilege role-based access, segregation of duties, session controls, and auditable access logs.
- Restrict file types and sizes; scan uploads for malware; protect against malicious documents and parser vulnerabilities.
- Keep original documents immutable and maintain provenance for extracted fields and findings.
- Record rule version, policy source, effective date, model/version if applicable, user corrections, and final human disposition.
- Do not allow the system to approve credit, waive conditions, or authorize disbursement.
- Validate false-positive and false-negative rates, especially for high-risk findings.
- Ensure any future LLM is approved for confidential banking data and has acceptable retention/training terms. Never send customer documents to an unapproved external service.

## Known prototype limitations

The application currently performs local text extraction and deterministic checks. It does not provide enterprise authentication, secure document storage, OCR for scanned pages, official policy retrieval, production audit logging, or an LLM. It is not production-ready.
