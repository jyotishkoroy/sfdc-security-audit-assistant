# ADR 0002: Sharing heuristics

## Context
OWD being too open on sensitive objects is a common root cause for data exposure.

## Decision
If an object is marked sensitive:
- `ReadWrite` or `ReadWriteTransfer` => High severity
- `Read` => Medium severity
- `Private` / `ControlledByParent` => Low (informational)

## Consequences
- Simple and explainable rules
- Can be tuned per object via CMDT in future
