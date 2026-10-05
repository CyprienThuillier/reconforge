# tests/modules/test_subdomain_resolver.py
from typing import Any

import dns.exception
import dns.resolver
import pytest

from reconforge.modules.subdomain_enum import DnsStatus, make_dns_probe
from reconforge.modules.subdomain_enum import resolver as resolver_module


class _Rdata:
    def __init__(self, text: str) -> None:
        self._text = text

    def to_text(self) -> str:
        return self._text


class _FakeResolver:
    """Scripted resolver: each (name, rdtype) maps to a list of outcomes (last one repeats)."""

    def __init__(self, script: dict[tuple[str, str], list[Any]]) -> None:
        self._script = script
        self.calls = 0

    async def resolve(self, name: str, rdtype: str) -> list[_Rdata]:
        self.calls += 1
        outcomes = self._script[(name, rdtype)]
        outcome = outcomes.pop(0) if len(outcomes) > 1 else outcomes[0]
        if isinstance(outcome, Exception):
            raise outcome
        return [_Rdata(value) for value in outcome]


@pytest.fixture(autouse=True)
def _no_retry_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resolver_module.models, "RETRY_DELAY", 0)


NAME = "www.example.com"


@pytest.mark.asyncio
async def test_probe_found() -> None:
    fake = _FakeResolver({(NAME, "A"): [["1.2.3.4"]]})
    result = await make_dns_probe(fake, ["A"], retries=3)(NAME)  # type: ignore[arg-type]

    assert result.status is DnsStatus.FOUND
    assert result.records == {"A": ["1.2.3.4"]}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("exception", "expected"),
    [
        (dns.resolver.NXDOMAIN(), DnsStatus.NOT_FOUND),
        (dns.resolver.NoAnswer(), DnsStatus.NO_DATA),
        (dns.exception.DNSException(), DnsStatus.ERROR),
    ],
)
async def test_probe_maps_exceptions(exception: Exception, expected: DnsStatus) -> None:
    fake = _FakeResolver({(NAME, "A"): [exception]})
    result = await make_dns_probe(fake, ["A"], retries=3)(NAME)  # type: ignore[arg-type]

    assert result.status is expected
    assert result.records == {}


@pytest.mark.asyncio
async def test_probe_retries_then_succeeds() -> None:
    fake = _FakeResolver({(NAME, "A"): [dns.exception.Timeout(), ["1.2.3.4"]]})
    result = await make_dns_probe(fake, ["A"], retries=3)(NAME)  # type: ignore[arg-type]

    assert result.status is DnsStatus.FOUND
    assert fake.calls == 2


@pytest.mark.asyncio
async def test_probe_fails_when_resolver_unreachable() -> None:
    fake = _FakeResolver({(NAME, "A"): [dns.exception.Timeout()]})
    result = await make_dns_probe(fake, ["A"], retries=2)(NAME)  # type: ignore[arg-type]

    assert result.status is DnsStatus.FAILED
    assert fake.calls == 2


@pytest.mark.asyncio
async def test_probe_keeps_only_found_record_types() -> None:
    fake = _FakeResolver({(NAME, "A"): [["1.2.3.4"]], (NAME, "AAAA"): [dns.resolver.NoAnswer()]})
    result = await make_dns_probe(fake, ["A", "AAAA"], retries=1)(NAME)  # type: ignore[arg-type]

    assert result.status is DnsStatus.FOUND
    assert result.records == {"A": ["1.2.3.4"]}


@pytest.mark.asyncio
async def test_probe_found_when_only_secondary_type_exists() -> None:
    fake = _FakeResolver({(NAME, "A"): [dns.resolver.NoAnswer()], (NAME, "AAAA"): [["::1"]]})
    result = await make_dns_probe(fake, ["A", "AAAA"], retries=1)(NAME)  # type: ignore[arg-type]

    assert result.status is DnsStatus.FOUND
    assert result.records == {"AAAA": ["::1"]}


@pytest.mark.asyncio
async def test_probe_skips_secondary_types_when_name_missing() -> None:
    fake = _FakeResolver({(NAME, "A"): [dns.resolver.NXDOMAIN()]})
    result = await make_dns_probe(fake, ["A", "AAAA"], retries=1)(NAME)  # type: ignore[arg-type]

    assert result.status is DnsStatus.NOT_FOUND
    assert fake.calls == 1


@pytest.mark.asyncio
async def test_probe_uppercases_and_deduplicates_record_types() -> None:
    fake = _FakeResolver({(NAME, "A"): [["1.2.3.4"]]})
    result = await make_dns_probe(fake, ["a", "A"], retries=1)(NAME)  # type: ignore[arg-type]

    assert result.records == {"A": ["1.2.3.4"]}
    assert fake.calls == 1


def test_make_dns_probe_rejects_invalid_settings() -> None:
    fake = _FakeResolver({})
    with pytest.raises(ValueError):
        make_dns_probe(fake, ["A"], retries=0)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        make_dns_probe(fake, [], retries=1)  # type: ignore[arg-type]
