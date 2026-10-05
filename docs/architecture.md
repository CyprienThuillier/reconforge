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

### ADR-004: Scan technique abstraction (generic engine + injected probes)
**Context**: port scanning was hardwired to the TCP connect technique: orchestration
(semaphore, gather, progress callback) and the probe itself lived in the same function. Adding
SYN, FIN, NULL, XMAS or UDP scans would have meant duplicating the orchestration.
**Decision**: split `modules/port_scanning/` into `models.py` (shared types), `engine.py`
(a generic `scan_ports(probe, ...)`), one module per technique (`connect.py`, ...) and
`registry.py` (a `ScanType -> probe` mapping). A probe is a plain async function matching
`PortProbe = Callable[[str, int, float], Awaitable[PortResult]]`. The engine receives the probe
as an argument instead of importing it.
**Consequence**: adding a technique means writing one probe function and adding one line to
the registry; the engine and the CLI stay untouched. Tests inject fake probes instead of
monkeypatching module paths. Functions were preferred over classes because no technique needs
state yet; if one does (e.g. a scapy socket), the `PortProbe` contract can be swapped for a
class-based interface without changing the engine. Known but unimplemented scan types raise
`UnsupportedScanTypeError`.

### ADR-005: Subdomain enumeration follows the port-scanning layout (async, injected probe)
**Context**: the first subdomain enumeration prototype was a single synchronous script (config
class, resolver helpers, wordlist reader, scan loop and ad-hoc tests in one file). It resolved
names one by one, so a large wordlist was slow, and it could not report progress or share any
orchestration with the port scanner.
**Decision**: split `modules/subdomain_enum/` the same way as `modules/port_scanning/` (ADR-004):
`models.py` (shared types, `DnsStatus`, `SubdomainResult`), `wordlist.py` (label validation and
name building), `resolver.py` (dnspython resolution with retry, wrapped in a
`make_dns_probe(...)` factory returning a `SubdomainProbe`) and `engine.py` (generic
`enumerate_subdomains(probe, names, ...)` with a semaphore and a progress callback). DNS I/O uses
`dns.asyncresolver`, consistent with ADR-002. Console rendering lives in
`report/enum_console.py` and reuses `create_progress` from `report/console.py`.
**Consequence**: tests inject fake probes or a scripted fake resolver instead of hitting the
network; the CLI gets a progress bar and live "[+]" output like `pscan`. Adds `dnspython` as a
dependency. Shared rendering helpers (progress bar, summary grid) could later move to a common
`report/` module if a third command needs them.### ADR-005: Subdomain enumeration follows the port-scanning layout (async, injected probe)
**Context**: the first subdomain enumeration prototype was a single synchronous script (config
class, resolver helpers, wordlist reader, scan loop and ad-hoc tests in one file). It resolved
names one by one, so a large wordlist was slow, and it could not report progress or share any
orchestration with the port scanner.
**Decision**: split `modules/subdomain_enum/` the same way as `modules/port_scanning/` (ADR-004):
`models.py` (shared types, `DnsStatus`, `SubdomainResult`), `wordlist.py` (label validation and
name building), `resolver.py` (dnspython resolution with retry, wrapped in a
`make_dns_probe(...)` factory returning a `SubdomainProbe`) and `engine.py` (generic
`enumerate_subdomains(probe, names, ...)` with a semaphore and a progress callback). DNS I/O uses
`dns.asyncresolver`, consistent with ADR-002. Console rendering lives in
`report/enum_console.py` and reuses `create_progress` from `report/console.py`.
**Consequence**: tests inject fake probes or a scripted fake resolver instead of hitting the
network; the CLI gets a progress bar and live "[+]" output like `pscan`. Adds `dnspython` as a
dependency. Shared rendering helpers (progress bar, summary grid) could later move to a common
`report/` module if a third command needs them.
