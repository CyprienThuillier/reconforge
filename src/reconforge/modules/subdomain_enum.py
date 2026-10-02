import dns.resolver
import dns.exception
import re
import tempfile
import time
from pathlib import Path
from typing import Iterator

EX = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")


class SubdomainEnumData:
    def __init__(self, domain: str, wordlist_path: Path, timeout: float = 2.0, lifetime: float = 4.0, nameservers: list[str] = None, rdtypes: list[str] = None, retries: int = 3):
        if retries < 1:
            raise ValueError("Retries must be >= 1")
        self.domain = domain.strip().lower().rstrip(".")
        self.wordlist_path = Path(wordlist_path)
        self.timeout = timeout
        self.lifetime = lifetime
        self.nameservers = nameservers or ["1.1.1.1", "8.8.8.8"]
        self.rdtypes = list(dict.fromkeys(t.upper() for t in rdtypes)) if rdtypes else ["A"]
        self.retries = retries


def create_resolver(nameservers: list[str], timeout: float, lifetime: float):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = nameservers
    resolver.timeout = timeout
    resolver.lifetime = lifetime
    return resolver


def concatenate(subdomain: str, domain: str) -> str:
    return f"{subdomain}.{domain}"


def resolve_name(resolver, name: str, rdtype: str) -> tuple[str, list[str]]:
    try:
        resolved = resolver.resolve(name, rdtype)
        results = []
        for i in resolved:
            results.append(i.to_text())
        return ("FOUND", results)
    except dns.resolver.NXDOMAIN:
        return ("NOT_FOUND", [])
    except dns.exception.Timeout:
        return ("RETRY", [])
    except dns.resolver.NoAnswer:
        return ("NO_DATA", [])
    except dns.resolver.NoNameservers:
        return ("RETRY", [])
    except dns.exception.DNSException:
        return ("ERROR", [])


def resolve_with_retry(retries: int, resolver, name: str, rdtype: str) -> tuple[str, list[str]]:
    for attempt in range(retries):
        status, values = resolve_name(resolver, name, rdtype)
        if status != "RETRY":
            return (status, values)
        if attempt < retries - 1:
            time.sleep(.2)
    return ("FAILED", [])


def resolve_record_types(retries: int, resolver, name: str, rdtypes: list[str]) -> tuple[str, dict[str, list[str]]]:
    first = rdtypes[0]
    status, values = resolve_with_retry(retries, resolver, name, first)
    if status not in ("FOUND", "NO_DATA"):
        return (status, {})

    records = {}
    if status == "FOUND":
        records[first] = values

    for rdtype in rdtypes[1:]:
        status, values = resolve_with_retry(retries, resolver, name, rdtype)
        if status == "FOUND":
            records[rdtype] = values

    return ("FOUND" if records else "NO_DATA", records)


def is_valid_label(label: str) -> bool:
    return EX.fullmatch(label) is not None


def generate_wordlist(wordlist_path: Path) -> Iterator[str]:
    with open(wordlist_path, 'r', encoding="utf-8", errors="ignore") as file:
        for line in file:
            line = line.strip().lower()
            if line and not line.startswith('#') and is_valid_label(line):
                yield line


def generate_names_list(word_generator: Iterator[str], domain: str) -> Iterator[str]:
    for word in word_generator:
        yield concatenate(word, domain)


def scan(config: SubdomainEnumData) -> tuple[dict[str, int], list[tuple[str, dict[str, list[str]]]]]:
    count = {
        "FOUND": 0,
        "NOT_FOUND": 0,
        "NO_DATA": 0,
        "FAILED": 0,
        "ERROR": 0
    }
    found = []
    resolver = create_resolver(config.nameservers, config.timeout, config.lifetime)
    wordlist = generate_wordlist(config.wordlist_path)
    names = set(generate_names_list(wordlist, config.domain))
    for name in names:
        status, records = resolve_record_types(config.retries, resolver, name, config.rdtypes)
        count[status] += 1
        if status == "FOUND":
            found.append((name, records))
    return (count, found)


def test_unreachable_resolver() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "wordlist_unreachable.txt"
        path.write_text("www\nmail\napi\n", encoding="utf-8")
        config = SubdomainEnumData(
            domain="google.com",
            wordlist_path=path,
            timeout=0.5,
            lifetime=1.0,
            nameservers=["10.255.255.1"],
            rdtypes=["A"],
            retries=2,
        )
        count, found = scan(config)
    print(count)
    assert count["FAILED"] == 3
    assert sum(count.values()) == 3
    assert found == []


if __name__ == '__main__':
    config = SubdomainEnumData(
        domain="google.com",
        wordlist_path=Path("wordlist_test.txt"),
        timeout=2.0,
        lifetime=4.0,
        nameservers=["1.1.1.1", "8.8.8.8"],
        rdtypes=["A", "AAAA"],
        retries=3,
    )
    count, found = scan(config)
    print(count)
    for name, records in found:
        print(name, records)
    assert sum(count.values()) == 12

    test_unreachable_resolver()
    print("OK")