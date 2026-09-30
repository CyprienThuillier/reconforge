# tests/modules/cve/test_scanning.py
import asyncio

import httpx
import pytest

from reconforge.core.exceptions import InvalidCveError
from reconforge.modules.cve.base import CveInfo, CveResult, CveScanner, CveState, Severity
from reconforge.modules.cve.registry import resolve_scanners
from reconforge.modules.cve.scanning import build_probe_urls, scan_cves

STUB_INFO = CveInfo(
    id="CVE-0000-0000",
    name="stub",
    severity=Severity.INFO,
    cvss=0.0,
    cwe="CWE-000",
    affected="none",
    remediation="none",
    references=(),
)


class _StubScanner(CveScanner):
    info = STUB_INFO

    async def probe(self, url: str, client: httpx.AsyncClient) -> tuple[CveState, str]:
        return CveState.VULNERABLE, f"probe {url}"


# --- build_probe_urls ------------------------------------------------------


def test_build_probe_urls_joins_target_and_paths() -> None:
    assert build_probe_urls("https://example.com/", ["/", "/admin"]) == [
        "https://example.com/",
        "https://example.com/admin",
    ]


# --- resolve_scanners ------------------------------------------------------


def test_resolve_scanners_returns_everything_by_default() -> None:
    every = resolve_scanners()

    assert len(resolve_scanners(None)) == len(every) >= 1
    assert len(resolve_scanners(["all"])) == len(every)
    assert [scanner.info.id for scanner in every] == ["CVE-2025-55182"]


def test_resolve_scanners_keeps_order_and_drops_duplicates() -> None:
    scanners = resolve_scanners(["react2shell", "react2shell", "ALL"])

    assert [scanner.info.id for scanner in scanners] == ["CVE-2025-55182"]


def test_resolve_scanners_rejects_unknown_id() -> None:
    with pytest.raises(InvalidCveError, match="Unknown CVE"):
        resolve_scanners(["nope"])


# --- scan_cves -------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_cves_covers_every_scanner_and_path() -> None:
    results = await scan_cves(
        "https://example.com", [_StubScanner(), _StubScanner()], paths=["/", "/admin"]
    )

    assert len(results) == 4
    assert {result.url for result in results} == {
        "https://example.com/",
        "https://example.com/admin",
    }


@pytest.mark.asyncio
async def test_scan_cves_respects_concurrency_limit() -> None:
    concurrent = 0
    peak = 0
    lock = asyncio.Lock()

    class _SlowScanner(_StubScanner):
        async def probe(self, url: str, client: httpx.AsyncClient) -> tuple[CveState, str]:
            nonlocal concurrent, peak
            async with lock:
                concurrent += 1
                peak = max(peak, concurrent)
            await asyncio.sleep(0.05)
            async with lock:
                concurrent -= 1
            return CveState.NOT_VULNERABLE, "ok"

    results = await scan_cves(
        "https://example.com", [_SlowScanner() for _ in range(10)], concurrency=3
    )

    assert len(results) == 10
    assert 1 < peak <= 3


@pytest.mark.asyncio
async def test_scan_cves_calls_on_result_for_each_probe() -> None:
    seen: list[CveResult] = []

    await scan_cves("https://example.com", [_StubScanner()], on_result=seen.append)

    assert len(seen) == 1
    assert seen[0].evidence == "probe https://example.com/"
