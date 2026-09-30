# tests/modules/cve/test_react2shell.py
import asyncio
from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio

from reconforge.modules.cve.react2shell import (
    INFO,
    React2ShellScanner,
    build_probe_body,
    build_probe_headers,
    classify,
)


def _response(
    status_code: int, text: str = "", headers: dict[str, str] | None = None
) -> httpx.Response:
    return httpx.Response(status_code, text=text, headers=headers or {})


@pytest_asyncio.fixture
async def vulnerable_server() -> AsyncIterator[str]:
    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.read(65536)
        writer.write(
            b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/x-component\r\n\r\n"
            b'E{"digest":"deadbeef"}'
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(_handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        yield f"http://127.0.0.1:{port}/"


# --- build_probe_body / build_probe_headers --------------------------------


def test_build_probe_body_carries_both_multipart_parts() -> None:
    body = build_probe_body()

    assert 'name="1"\r\n\r\n{}' in body
    assert 'name="0"\r\n\r\n["$1:aa:aa"]' in body
    assert body.rstrip().endswith("--")


def test_build_probe_headers_are_rsc_shaped_and_unique() -> None:
    first, second = build_probe_headers(), build_probe_headers()

    assert first["Next-Action"] == "x"
    assert first["Content-Type"].startswith("multipart/form-data; boundary=")
    assert len(first["X-Nextjs-Html-Request-Id"]) == 21
    assert first != second


# --- classify --------------------------------------------------------------


def test_classify_flags_flight_crash_as_vulnerable() -> None:
    state, evidence = classify(_response(500, 'E{"digest":"abc"}'))

    assert state.value == "vulnerable"
    assert "digest" in evidence


@pytest.mark.parametrize("status_code", [200, 403, 404])
def test_classify_ignores_non_500_responses(status_code: int) -> None:
    state, _ = classify(_response(status_code, "ok"))

    assert state.value == "not_vulnerable"


def test_classify_ignores_generic_500() -> None:
    state, evidence = classify(_response(500, "Internal Server Error"))

    assert state.value == "not_vulnerable"
    assert "without Flight error digest" in evidence


@pytest.mark.parametrize("headers", [{"Server": "Vercel"}, {"Server": "Netlify"}])
def test_classify_credits_edge_mitigation(headers: dict[str, str]) -> None:
    state, evidence = classify(_response(500, 'E{"digest":"abc"}', headers))

    assert state.value == "not_vulnerable"
    assert "edge mitigation" in evidence


def test_classify_credits_netlify_vary_header() -> None:
    state, _ = classify(_response(500, 'E{"digest":"abc"}', {"Netlify-Vary": "rsc"}))
    assert state.value == "not_vulnerable"


# --- React2ShellScanner ----------------------------------------------------


@pytest.mark.asyncio
async def test_scanner_reports_vulnerable_against_real_socket(vulnerable_server: str) -> None:
    async with httpx.AsyncClient() as client:
        result = await React2ShellScanner().check(vulnerable_server, client)

    assert result.cve.id == INFO.id
    assert result.state.value == "vulnerable"
    assert result.url == vulnerable_server


@pytest.mark.asyncio
async def test_scanner_reports_unknown_on_connection_error() -> None:
    async with httpx.AsyncClient() as client:
        result = await React2ShellScanner().check("http://127.0.0.1:1/", client)

    assert result.state.value == "unknown"
    assert "ConnectError" in result.evidence
