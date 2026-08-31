# Architecture and technical decisions

## Overview

```
CLI (Typer)
   │
   ▼
Orchestrator (core/)
   │
   ├──► Module: subdomain_enum
   ├──► Module: port_scan
   ├──► Module: cve_match
   │        (parallelized execution via asyncio)
   ▼
Results aggregation
   │
   ▼
Report generator (report/) ──► Markdown / JSON / HTML
```

## Design decisions (short ADRs)

### ADR-001: Typer over argparse
**Context**: need a CLI with subcommands, type validation, auto-generated help.
**Decision**: Typer (built on Python type hints).
**Consequence**: one extra external dependency, but more readable code with less boilerplate
than `argparse`, and auto-generated help — useful for a tool meant to be demoed in interviews.

### ADR-002: asyncio for scan parallelization
**Context**: subdomain enumeration and port scanning involve heavy wait-bound network I/O.
**Decision**: `asyncio` + `httpx.AsyncClient` rather than classic threading.
**Consequence**: better scalability across many targets/ports, but higher code complexity —
requires solid test coverage on this part.

### ADR-003: core / modules / report separation
**Context**: wanting to easily add new scan modules without touching the orchestrator.
**Decision**: each technique (subdomain_enum, port_scan, cve_match...) is an isolated module
implementing a common interface (`run(target) -> Result`).
**Consequence**: easy to extend and test independently, but requires interface discipline from
the start.

*(Keep adding to this as the project grows — any moderately structural technical decision deserves
5 lines here. This kind of document is what lets you explain the "why", not just the "what",
in an interview.)*
