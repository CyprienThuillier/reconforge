# import asyncio
import dns.resolver
import dns.exception
# import aiofiles
# from pathlib import Path

# class SubdomainEnumData:
#     def __init__(self, domain: str, wordlist_path: Path, concurrency: int, rate_limit: None, timeout: int, lifetime: int, resolvers: list[str] = None, record_types: list[str] = None, retries: int = 3):
#         self.domain = domain
#         self.wordlist_path = wordlist_path
#         self.concurrency = concurrency
#         self.rate_limit = rate_limit
#         self.timeout = timeout
#         self.lifetime = lifetime
#         self.resolvers = resolvers if resolvers is not None else [] 
#         self.record_types = record_types if record_types is not None else []
#         self.retries = retries
        
# async def wordlist_generator(wordlist_path: Path):
#     async with aiofiles.open(wordlist_path, mode='r', encoding='utf-8', errors='ignore') as f:
#         return await f.read().strip().splitlines()
    
# def validate_wordlist_subdomains(wordlist: list[str], domain: str) -> set[str]:
#     valid_subdomains = []
#     for subdomain in wordlist:
#         if subdomain and subdomain != domain and len(subdomain) < 63 and subdomain[0] != '-' and subdomain[-1] != '-':
#             valid_subdomains.append(subdomain)
#     return set(valid_subdomains)

# def resolve_subdomain(subdomain: str, resolvers: list[str], record_types: list[str], timeout: int, retries: int) -> dict:
#     result = {}
#     for resolver in resolvers:
#         for record_type in record_types:
#             try:
#                 dnspython.asyncresolver.Resolver(configure=False)
#                 answers = dnspython.resolve()
#                 result[subdomain] = [answer.to_text() for answer in answers]
#                 break
#             except Exception as e:
#                 if retries > 0:
#                     retries -= 1
#                     continue
#                 else:
#                     result[subdomain] = []
#     return result

def concatenate(subdomain: str, domain: str) -> str:
    return f"{subdomain}.{domain}"

def test():
    domain = "www.google.com"
    subdomain = "test"
    target = concatenate(subdomain, domain)
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["8.8.8.8"]
    resolver.timeout = 1
    resolver.lifetime = 5
    try:
        resolved = resolver.resolve(target, "A")
        for i in resolved:
            print(i.to_text())
    except dns.exception.NXDOMAIN:
        print("NXDOMAIN")
    except dns.exception.NoAnswer:
        print("No answer")
    except dns.exception.Timeout:
        print("Timeout")
    except dns.exception.NoNameservers:
        print("No nameservers")
        
if __name__ == '__main__':
    test()