from dataclasses import dataclass
from enum import Enum

import httpx

DEFAULT_REQUEST_TIMEOUT = 10.0
DEFAULT_CONCURRENCY = 10
DEFAULT_VERIFY_SSL = False


class CveState(str, Enum):
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass(frozen=True)
class CveInfo:
    id: str
    name: str
    severity: Severity
    cvss: float
    cwe: str
    affected: str
    remediation: str
    references: tuple[str, ...]


@dataclass(frozen=True)
class CveResult:
    cve: CveInfo
    state: CveState
    url: str
    evidence: str = ""


def build_client(
    timeout: float = DEFAULT_REQUEST_TIMEOUT,
    verify_ssl: bool = DEFAULT_VERIFY_SSL,
) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=timeout,
        verify=verify_ssl,
        follow_redirects=False,
        headers={"User-Agent": "ReconForge/0.1"},
        limits=httpx.Limits(
            max_connections=DEFAULT_CONCURRENCY * 5,
            max_keepalive_connections=DEFAULT_CONCURRENCY * 5,
        ),
    )


class CveScanner:
    info: CveInfo

    async def check(self, url: str, client: httpx.AsyncClient) -> CveResult:
        try:
            state, evidence = await self.probe(url, client)
        except httpx.HTTPError as error:
            state, evidence = CveState.UNKNOWN, f"{type(error).__name__}: {error}"

        return CveResult(cve=self.info, state=state, url=url, evidence=evidence)

    async def probe(self, url: str, client: httpx.AsyncClient) -> tuple[CveState, str]:
        raise NotImplementedError
