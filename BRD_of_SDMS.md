# Development of Vault File & Credit File Management System

As per regulatory requirement on credit risk management, record keeping, internal control and audit readiness, banks are required to maintain secure, retrievable and traceable records of security documents of loan clients.

Currently, security documents are physically handled and stored at branch offices using manual registers and cabinets/vaults which exposes the bank to:
- Risk of document misplacement or loss.
- Weak audit trail of document movement.
- Inconsistent filing and indexing practices across branches.

In line with CAD operational strategy and digital transformation initiatives of bank, a system for proper indexing, filing of Credit related Documents along with tracking of its movement is required.

## Objectives of the Proposed System

The proposed system aims to:
- Ensure regulatory compliance with NRB.
- Strengthen security and control over loan security documents.
- Enable systematic digital filing and indexing.
- Establish file movement tracking.
- Improve operational efficiency, audit readiness and risk mitigation.

## Functional Requirements

### Unique Indexing Number – Credit & Vault Files
- Each loan customer shall be assigned a unique indexing number of Credit & Vault file.
- One loan customer shall have two files with unique indexing number:
  - Credit File (Credit approval, renewal, review documents)
  - Vault File (Original legal/security documents)
- The indexing number must be:
  - System-generated
  - Unique across the bank
  - Traceable

### Systematic Registration of Indexing Number
- Indexing number shall be registered in the proposed system after disbursement of facilities & completion of entire security documents.
- Mandatory data fields may include:
  - CIF / Customer ID
  - Borrower Name
  - SOL ID
  - Constitution Type (Retail or Business)

### Coding of Fireproof Cabinets / Vaults
- All physical storage units (fireproof cabinets/vaults) shall be:
  - Assigned unique cabinet/vault codes
  - Mapped in the proposed system
- Each security file record shall be linked to:
  - Branch Code
  - Cabinet/Vault Code
  - Rack / Shelf / Slot Number (if applicable)

### Workflow Management & File Movement Tracking
The system shall be able to support movement of the file and track every movement history for audit purpose.

#### File Movement Recording shall record:
- Approval memo ID (Quick memo or any other platform)
- Staff name and related unit: to whom the file is handed over
- Handover date (system captured)
- Purpose of file movement
- Expected return date (considering the security risk, the file is expected to be returned on the same day)

#### Upon return of the file:
- File return date (system captured)
- Receiving staff name
- Every movement history to be recorded

#### Status Tracking
- In custody
- In transit

## Control, Security & Compliance Requirements
- Role-based access control (Add-Edit-Update option to the users at the Branch/CAD, View option only to Audit, NPA, Legal and others)
- Complete audit trail/logs
- Compliance with:
  - NRB directives
  - Internal audit requirements

## Reporting & MIS
The system should generate standard and ad-hoc reports such as:
- Search option to locate the file status and location through CIF or Customer Name.
- Security document holding position by branch

## Expected Benefits
- Strong control over original security documents & reduced dependency on individual staff knowledge.
- Improved audit and inspection readiness
- Reduced operational and legal risk
- Standardized document handling across the bank
- Foundation for future digital vault and paperless initiatives.
