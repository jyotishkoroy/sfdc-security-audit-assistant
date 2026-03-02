# ADR 0001: Scan scope — effective access vs permission graph

## Context
A full audit across Profiles/PermSets typically requires Tooling/Metadata API access and parsing permission metadata.

## Decision
Ship an MVP that:
1) computes **effective access for the running user** via `Schema.Describe*` (CRUD/FLS), and
2) checks **sharing model** via `DescribeSObjectResult.getSharingModel()`.

## Consequences
- Useful as an admin “what do I currently have access to?” risk detector
- Not a full enterprise permission graph scanner
- The report schema is designed to accept future permission-graph findings
