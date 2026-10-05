import asyncio
from collections.abc import Sequence

import dns.asyncresolver
import dns.exception
import dns.resolver

from reconforge.modules.subdomain_enum import models
from reconforge.modules.subdomain_enum.models import DnsStatus, SubdomainProbe, SubdomainResult


def create_resolver(
    nameservers: Sequence[str], timeout: float, lifetime: float
) -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = list(nameservers)
    resolver.timeout = timeout
    resolver.lifetime = lifetime
    return resolver


async def resolve_name(
    resolver: dns.asyncresolver.Resolver, name: str, rdtype: str
) -> tuple[DnsStatus, list[str]]:
    try:
        answer = await resolver.resolve(name, rdtype)
    except dns.resolver.NXDOMAIN:
        return DnsStatus.NOT_FOUND, []
    except dns.exception.Timeout:
        return DnsStatus.RETRY, []
    except dns.resolver.NoAnswer:
        return DnsStatus.NO_DATA, []
    except dns.resolver.NoNameservers:
        return DnsStatus.RETRY, []
    except dns.exception.DNSException:
        return DnsStatus.ERROR, []
    return DnsStatus.FOUND, [rdata.to_text() for rdata in answer]


async def resolve_with_retry(
    resolver: dns.asyncresolver.Resolver, name: str, rdtype: str, retries: int
) -> tuple[DnsStatus, list[str]]:
    for attempt in range(retries):
        status, values = await resolve_name(resolver, name, rdtype)
        if status is not DnsStatus.RETRY:
            return status, values
        if attempt < retries - 1:
            await asyncio.sleep(models.RETRY_DELAY)
    return DnsStatus.FAILED, []


async def resolve_record_types(
    resolver: dns.asyncresolver.Resolver,
    name: str,
    rdtypes: Sequence[str],
    retries: int,
) -> SubdomainResult:
    """Resolve the first record type; only if the name exists, query the remaining ones."""
    first = rdtypes[0]
    status, values = await resolve_with_retry(resolver, name, first, retries)
    if status not in (DnsStatus.FOUND, DnsStatus.NO_DATA):
        return SubdomainResult(name=name, status=status)

    records: dict[str, list[str]] = {}
    if status is DnsStatus.FOUND:
        records[first] = values

    for rdtype in rdtypes[1:]:
        status, values = await resolve_with_retry(resolver, name, rdtype, retries)
        if status is DnsStatus.FOUND:
            records[rdtype] = values

    final = DnsStatus.FOUND if records else DnsStatus.NO_DATA
    return SubdomainResult(name=name, status=final, records=records)


def make_dns_probe(
    resolver: dns.asyncresolver.Resolver,
    rdtypes: Sequence[str],
    retries: int,
) -> SubdomainProbe:
    if retries < 1:
        raise ValueError("Retries must be >= 1")
    unique_types = tuple(dict.fromkeys(rdtype.upper() for rdtype in rdtypes))
    if not unique_types:
        raise ValueError("At least one record type is required")

    async def probe(name: str) -> SubdomainResult:
        return await resolve_record_types(resolver, name, unique_types, retries)

    return probe
