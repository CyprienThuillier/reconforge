# ReconForge

> CLI automation tool for reconnaissance and vulnerability scanning against authorized web targets.

[![CI](https://github.com/CyprienThuillier/reconforge/actions/workflows/ci.yml/badge.svg)](https://github.com/CyprienThuillier/reconforge/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/CyprienThuillier/reconforge/branch/main/graph/badge.svg)](https://codecov.io/gh/CyprienThuillier/reconforge)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()

## Table of contents

- [About](#about)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Responsible use](#responsible-use)
- [Authors](#authors)
- [License](#license)

## About

ReconForge is a command-line tool written in Python that automates the reconnaissance and
vulnerability-scanning phases against web targets (within an authorized scope: CTFs, labs,
contracted pentests). Built by two cybersecurity students as part of their technical portfolio.

## Features

- [ ] Subdomain enumeration
- [ ] Port scanning and service fingerprinting
- [ ] Known vulnerability (CVE) detection on identified services
- [ ] Report generation (Markdown / HTML / JSON)
- [ ] Parallelized execution (asyncio)

## Architecture

```
reconforge/
├── src/reconforge/
│   ├── core/          # Orchestrator, scan engine
│   ├── modules/        # One module per technique (subdomain_enum, port_scan, cve_match...)
│   ├── report/          # Report generation
│   └── cli.py            # CLI entry point (Typer/Click)
├── tests/
└── docs/
    └── architecture.md   # Technical decisions (ADRs)
```

See [docs/architecture.md](docs/architecture.md) for the detailed design decisions.

## Installation

```bash
git clone https://github.com/CyprienThuillier/reconforge.git
cd reconforge
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
reconforge scan --target example.com --modules subdomains,ports,cve --output report.md
```

## Roadmap

See the [Projects](https://github.com/CyprienThuillier/reconforge/projects) tab and the
[Issues](https://github.com/CyprienThuillier/reconforge/issues) of this repo.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Responsible use

This tool is intended solely for testing against targets you are explicitly authorized to test
(lab environments, CTFs, contractual pentest scope). See [SECURITY.md](SECURITY.md).

## Authors

- Cyprien Thuillier — [GitHub](https://github.com/CyprienThuillier) — cybersecurity student
- Raphael Blanc — [GitHub](https://github.com/RaphaelBlanc) — cybersecurity student

## License

Distributed under the MIT License — see [LICENSE](LICENSE).
