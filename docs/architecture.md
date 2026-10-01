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
   ├──► Module: cve  (package: base + registry + one submodule per CVE)
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
**Decision**: each technique (subdomain_enum, port_scan, cve...) is an isolated module
implementing a common interface (`run(target) -> Result`).
**Consequence**: easy to extend and test independently, but requires interface discipline from
the start.

### ADR-004: one package, one submodule per CVE
**Context**: a CVE needs a URL target, a handcrafted HTTP payload, a signature and advisory
metadata — a different shape from a port scan, and unrelated products share none of it.
**Decision**: `modules/cve/` is a package: `base.py` holds the contract (`CveInfo`, `CveResult`,
`CveScanner`) and the shared client, `scanning.py` does the batching, `registry.py` maps CLI ids to
classes, and each CVE is one self-contained file implementing `probe(url, client)`.
**Consequence**: adding a CVE is a new file plus one registry line, and the new file carries no
client, concurrency or reporting code.

### ADR-005: detection probes are side-channel, never exploit
**Context**: most high-severity web CVEs are RCE, and a scanner that proves a finding by running
code on the target is unusable against production systems.
**Decision**: a CVE submodule confirms a flaw through a *side effect* — a crash, an error digest, a
reflected marker — never by executing attacker-controlled code. The React2Shell probe sends an
incomplete Flight payload and matches the resulting `E{"digest"...}` row.
**Consequence**: findings are safe against live targets, and a positive means "this build mishandles
the payload" rather than proof of compromise. Edge mitigations must be encoded too, since Vercel
and Netlify return the same crash signature and would otherwise read as false positives.

*(Keep adding to this as the project grows — any moderately structural technical decision deserves
5 lines here. This kind of document is what lets you explain the "why", not just the "what",
in an interview.)*
