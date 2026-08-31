# Security policy and responsible use

## Authorized scope

ReconForge is an educational project built as part of a cybersecurity curriculum. It is intended
exclusively for use on:

- personal lab environments or platforms designed for training (CTF, TryHackMe, HackTheBox, etc.);
- targets for which the user holds explicit written authorization (pentest contract, defined scope);
- systems owned by the user themselves.

Using this tool against third-party systems without authorization is illegal (in France: articles
323-1 et seq. of the Penal Code) and is solely the responsibility of the person doing so. The
project maintainers disclaim any liability for use outside this scope.

## Reporting a vulnerability in the project itself

If you find a security flaw in ReconForge's own code (not a scan result), please do not open a
public issue. Instead, contact us directly with the details of the vulnerability.

## Security practices built into the project

- No target data is sent to a third-party service without explicit user consent.
- Generated reports remain local by default.
- Configurable rate-limiting to avoid aggressive scans by default.
