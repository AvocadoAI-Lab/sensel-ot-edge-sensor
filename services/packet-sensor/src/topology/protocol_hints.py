"""Passive IT protocol port fingerprints (PRD §5.6)."""

from __future__ import annotations

from typing import Mapping

# Well-known IT service ports → protocol_hint
IT_SERVICE_PORTS: Mapping[int, str] = {
    445: "smb",
    3389: "rdp",
    389: "ldap",
    636: "ldap",
    88: "kerberos",
    135: "msrpc",
    139: "netbios",
    53: "dns",
}

LDAP_SERVER_MIN_CLIENTS = 2
DNS_SERVER_MIN_CLIENTS = 1


def hint_for_port(port: int) -> str | None:
    return IT_SERVICE_PORTS.get(int(port))


def merge_hints(existing: list[str] | None, new_hints: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in list(existing or []) + list(new_hints):
        text = str(item or "").strip().lower()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out
