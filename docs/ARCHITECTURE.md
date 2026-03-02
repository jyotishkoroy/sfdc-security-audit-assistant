# Architecture

## Components
- **SecurityAuditController (Apex)**
  - `listObjects()` returns objects the UI can scan
  - `listFields(objectApiName)` returns fields for selection
  - `runScan(request)` returns findings with severity + recommendation
  - `getSensitiveConfig(objectApiName)` loads CMDT for “sensitive” labels

- **securityAuditAssistant (LWC)**
  - Object picker + field multi-select
  - Executes scan + renders datatable
  - Client-side CSV export

## Finding model
Apex returns:
- `category` (CRUD/FLS/Sharing)
- `severity` (Low/Medium/High)
- `objectApiName`
- `fieldApiName` (optional)
- `message`
- `recommendation`

## Risk heuristics (current version)
- If an object is marked sensitive and:
  - Create/Edit/Delete is allowed -> flag Medium/High
  - Sharing model is ReadWrite or ReadWriteTransfer -> flag High
- If a field is marked sensitive and editable -> flag High

Heuristics are intentionally explicit and documented in ADRs.
