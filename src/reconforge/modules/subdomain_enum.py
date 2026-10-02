# import asyncio
import dns.resolver
import dns.exception
# import aiofiles
from pathlib import Path

class SubdomainEnumData:
    def __init__(self, domain: str, wordlist_path: Path, timeout: float = 2.0, lifetime: float = 4.0, nameservers: list[str] = None, rdtype: list[str] = None, retries: int = 3):
        self.domain = domain
        self.wordlist_path = wordlist_path
        self.timeout = timeout
        self.lifetime = lifetime
        self.nameservers = nameservers if nameservers is not None else ["1.1.1.1", "8.8.8.8"]
        self.rdtype = rdtype if rdtype is not None else ["A"]
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

if __name__ == '__main__':
    domain = "google.com"
    subdomains = ["www", "zzzqqq123", "www", "test"]
    names = []
    for sub in subdomains:
        names.append(concatenate(sub, domain))
    resolver1 = create_resolver(["8.8.8.8"], 0.5, 0.5)
    resolver2 = create_resolver(["10.255.255.1"], 0.5, 0.5)
    a = resolve_name(resolver1, names[0], "A")
    b = resolve_name(resolver1, names[1], "A")
    c = resolve_name(resolver1, names[2], "MX")
    d = resolve_name(resolver2, names[3], "A")
    # print(f"{a[0]}\n{b[0]}\n{c[0]}\n{d[0]}")
    assert a[0] == "FOUND"
    assert b[0] == "NOT_FOUND"
    assert c[0] == "NO_DATA"
    assert d[0] == "RETRY"