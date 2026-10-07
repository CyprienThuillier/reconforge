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
- [Release](#release)
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

- [x] Subdomain enumeration
- [x] Port scanning and service fingerprinting
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

## Release

> ⚠️ **Alpha version**: ReconForge is still under active development. `v0.1.0` is a pre-release: expect bugs and interface changes.

The latest release provides a standalone executable for Linux (x86_64), requiring neither a repository clone nor a Python installation.

| Version | Platform | Download |
|---------|----------|----------|
| `v0.1.0` (alpha) | Linux x86_64 | [reconforge-linux-x86_64](https://github.com/CyprienThuillier/reconforge/releases/download/v0.1.0/reconforge-linux-x86_64) |

### Installing from the release

```bash
# 1. Download the executable
wget https://github.com/CyprienThuillier/reconforge/releases/download/v0.1.0/reconforge-linux-x86_64

# 2. Make it executable
chmod +x reconforge-linux-x86_64

# 3. Install it into your PATH
sudo mv reconforge-linux-x86_64 /usr/local/bin/reconforge
```

Then check that the installation works:

```bash
reconforge --help
```

### Release or install from source?

- **Release (binary)**: to quickly try the tool without setting up a Python environment.
- **Source**: to contribute, or to follow the latest changes on the `main` branch (see [Installation](#installation)).

Full release notes are available on the [releases page](https://github.com/CyprienThuillier/reconforge/releases).

## Installation

```bash
git clone https://github.com/CyprienThuillier/reconforge.git
cd reconforge
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# (Optional) To run reconforge with sudo without specifying the full virtual environment path:
sudo ln -sf "$(pwd)/.venv/bin/reconforge" /usr/local/bin/reconforge
```

## Usage

### Port Scanning
Run a TCP SYN scan (requires root privileges):
```bash
sudo reconforge pscan example.com -t syn -p 1-1000
```
Run a standard TCP connect scan:
```bash
reconforge pscan example.com -t connect -p 80,443
```

### Subdomain Enumeration
Run subdomain enumeration with a wordlist:
```bash
reconforge enum example.com -m subdomain -w wordlists/subdomains.txt
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

- Cyprien Thuillier - [GitHub](https://github.com/CyprienThuillier) - cybersecurity student
- Raphael Blanc - [GitHub](https://github.com/RaphaelBlanc) - cybersecurity student
- Hugo Cassabois - [GitHub](https://github.com/endelf) - cybersecurity student

## License

Distributed under the MIT License — see [LICENSE](LICENSE).
