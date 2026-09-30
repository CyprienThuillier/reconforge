import secrets
import string

import httpx

from reconforge.modules.cve.base import CveInfo, CveScanner, CveState, Severity

CVE_ID = "CVE-2025-55182"

RSC_BOUNDARY = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
RSC_CONTENT_TYPE = f"multipart/form-data; boundary={RSC_BOUNDARY}"
VULNERABLE_SIGNATURE = 'E{"digest"'
CRASH_STATUS = 500
MITIGATED_SERVERS = ("vercel", "netlify")
NETLIFY_VARY_HEADER = "Netlify-Vary"

INFO = CveInfo(
    id=CVE_ID,
    name="React Server Components unauthenticated RCE (React2Shell)",
    severity=Severity.CRITICAL,
    cvss=10.0,
    cwe="CWE-502",
    affected="react-server-dom-webpack/parcel/turbopack 19.0.0, 19.1.0, 19.1.1, 19.2.0",
    remediation="Upgrade react-server-dom-* to 19.0.1, 19.1.2 or 19.2.1 and Next.js to a patched release",
    references=(
        "https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components",
        "https://github.com/vercel/next.js/security/advisories/GHSA-9qr9-h5gf-34mp",
    ),
)


def build_probe_body() -> str:
    delimiter = f"--{RSC_BOUNDARY}"
    return (
        f"{delimiter}\r\n"
        'Content-Disposition: form-data; name="1"\r\n\r\n'
        "{}\r\n"
        f"{delimiter}\r\n"
        'Content-Disposition: form-data; name="0"\r\n\r\n'
        '["$1:aa:aa"]\r\n'
        f"{delimiter}--"
    )


def random_id(size: int) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(size))


def build_probe_headers() -> dict[str, str]:
    return {
        "Content-Type": RSC_CONTENT_TYPE,
        "Next-Action": "x",
        "X-Nextjs-Request-Id": random_id(8),
        "X-Nextjs-Html-Request-Id": random_id(21),
    }


def is_edge_mitigated(response: httpx.Response) -> bool:
    if NETLIFY_VARY_HEADER in response.headers:
        return True

    servers = {token.strip().lower() for token in response.headers.get("Server", "").split(",")}
    return bool(servers & set(MITIGATED_SERVERS))


def classify(response: httpx.Response) -> tuple[CveState, str]:
    if response.status_code != CRASH_STATUS:
        return CveState.NOT_VULNERABLE, f"HTTP {response.status_code}"

    if VULNERABLE_SIGNATURE not in response.text:
        return CveState.NOT_VULNERABLE, "HTTP 500 without Flight error digest"

    if is_edge_mitigated(response):
        return CveState.NOT_VULNERABLE, "Flight digest present but edge mitigation active"

    return CveState.VULNERABLE, f"HTTP 500 with Flight error digest {VULNERABLE_SIGNATURE}..."


class React2ShellScanner(CveScanner):
    info = INFO

    async def probe(self, url: str, client: httpx.AsyncClient) -> tuple[CveState, str]:
        response = await client.post(url, content=build_probe_body(), headers=build_probe_headers())
        return classify(response)
