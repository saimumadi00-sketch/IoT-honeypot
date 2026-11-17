"""Fake Telnet service: the shared login shell plus Telnet option handling."""

from __future__ import annotations

from services.fake_shell import TELNET_BANNER, make_handler
from services.tcp_base import TCPDecoyServer


def create_telnet_server(host: str, port: int) -> TCPDecoyServer:
    return TCPDecoyServer(
        "fake_telnet", host, port, make_handler("fake_telnet", TELNET_BANNER, telnet=True)
    )
