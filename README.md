# Security Audit Assistant (Salesforce) — CRUD/FLS + Sharing Sanity Checks

A Lightning Experience admin tool that scans selected objects/fields for common access risks and produces a report.

## What it audits
### CRUD + FLS (current-user lens)
- Object-level: read/create/edit/delete
- Field-level: readable/editable
- Flags “too-permissive” access for sensitive objects/fields (configurable)

### Sharing sanity checks (metadata lens)
- OWD sharing model (`Private`, `Read`, `ReadWrite`, etc.)
- Flags overly-open sharing models for objects marked sensitive

> **Note on scope:** Salesforce doesn’t expose full Profile/PermSet permission graphs directly to Apex without Tooling/Metadata API usage.
> This implementation focuses on **effective access for the running user** + **object sharing model**. The patterns and report format are designed so you can extend it later to a deeper profile/permset scanner via Tooling API.

---

## UI (what a reviewer will see)
- Pick an object
- Optionally choose fields (multi-select)
- Run scan
- Get a datatable with:
  - Category (CRUD / FLS / Sharing)
  - Severity (Low/Medium/High)
  - Object / Field
  - Finding + recommendation
- Export CSV from the UI

---

## Repo structure
- `force-app/` Salesforce metadata (Apex + LWC + CMDT config)
- `docs/` architecture + ADRs + sample report
- `.github/workflows/` CI (lint + Jest)

---

## Configuration
Uses Custom Metadata Type:
- `Security_Audit_Sensitive_Field__mdt`
  - Object API Name
  - Field API Name (optional; blank = whole object sensitive)
  - Severity (Low/Medium/High)
  - Notes

This keeps “what is sensitive” out of the code.

---

## Extensibility
Planned follow-ups (documented in ADRs):
- Tooling API-based permission graph scan for Profiles/Permission Sets
- Permission Set Group coverage
- Baseline comparisons (diff new risk vs previous run)
