#!/usr/bin/env python3
"""Lab seed: index CVE rows into wazuh-states-vulnerabilities-* for OT topology CVE gate.

When Wazuh indexer-connector cannot write states (common Lab misconfig: indexer host
0.0.0.0), this script bulk-indexes minimal documents that match CP query fields.

Usage:
  ./scripts/seed-topology-lab-vuln-indexer.sh
  ./scripts/seed-topology-lab-vuln-indexer.sh --agent-id 004 --ssh-host 192.168.1.108
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from typing import Any


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _build_docs(*, agent_id: str, agent_name: str) -> list[dict[str, Any]]:
    now = _utc_now()
    seeds = [
        ("CVE-2024-38063", "critical", 9.8, "AnyDesk", "ad 9.0.12"),
        ("CVE-2023-44487", "high", 7.5, "Microsoft Edge", "131.0.2903.70"),
        ("CVE-2022-3602", "high", 7.4, "OpenSSL", "3.0.7"),
    ]
    docs: list[dict[str, Any]] = []
    for cve, severity, score, pkg_name, pkg_version in seeds:
        docs.append(
            {
                "agent": {"id": agent_id, "name": agent_name},
                "package": {"name": pkg_name, "version": pkg_version},
                "vulnerability": {
                    "id": cve,
                    "severity": severity,
                    "score": {"base": score},
                    "description": f"Lab seed vulnerability {cve} for OT topology CVE gate",
                    "published_at": now,
                    "detected_at": now,
                },
                "wazuh": {"cluster": {"name": "wazuh"}},
            }
        )
    return docs


def _bulk_body(*, index: str, docs: list[dict[str, Any]]) -> bytes:
    lines: list[str] = []
    for i, doc in enumerate(docs):
        doc_id = f"lab-{doc['agent']['id']}-{doc['vulnerability']['id']}-{i}"
        lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}, ensure_ascii=False))
        lines.append(json.dumps(doc, ensure_ascii=False))
    return ("\n".join(lines) + "\n").encode("utf-8")


def _post_bulk_local(*, indexer_url: str, user: str, password: str, body: bytes) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    auth_hdr = urllib.request.HTTPBasicAuthHandler().add_password(
        realm="OpenSearch",
        uri=indexer_url,
        user=user,
        passwd=password,
    )
    del auth_hdr  # unused; build header manually
    import base64

    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    req = urllib.request.Request(
        f"{indexer_url.rstrip('/')}/_bulk",
        data=body,
        headers={
            "Authorization": f"Basic {token}",
            "Content-Type": "application/x-ndjson",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
        return json.loads(resp.read().decode())


def _post_bulk_remote_ssh(
    *,
    ssh_host: str,
    ssh_user: str,
    ssh_pass: str,
    index: str,
    docs: list[dict[str, Any]],
    indexer_user: str,
    indexer_password: str,
) -> dict[str, Any]:
    body = _bulk_body(index=index, docs=docs)
    remote_cmd = (
        "docker exec -i wazuh-indexer curl -sk "
        f"-u {indexer_user}:{indexer_password} "
        '-X POST "https://localhost:9200/_bulk" '
        '-H "Content-Type: application/x-ndjson" '
        "--data-binary @-"
    )
    proc = subprocess.run(
        [
            "sshpass",
            "-p",
            ssh_pass,
            "ssh",
            "-o",
            "StrictHostKeyChecking=accept-new",
            f"{ssh_user}@{ssh_host}",
            remote_cmd,
        ],
        input=body,
        capture_output=True,
        timeout=120,
    )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or b"").decode(errors="replace").strip()
        raise RuntimeError(err or "remote bulk failed")
    return json.loads(proc.stdout.decode())


def _refresh_index(*, ssh_host: str, ssh_user: str, ssh_pass: str, index: str, indexer_user: str, indexer_password: str) -> None:
    remote = (
        f"docker exec wazuh-indexer curl -sk -u {indexer_user}:{indexer_password} "
        f'-X POST "https://localhost:9200/{index}/_refresh"'
    )
    subprocess.run(
        ["sshpass", "-p", ssh_pass, "ssh", "-o", "StrictHostKeyChecking=accept-new", f"{ssh_user}@{ssh_host}", remote],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed Wazuh vulnerability states for OT topology Lab")
    parser.add_argument("--agent-id", default=os.environ.get("CVE_EXPECT_AGENT_ID", "004"))
    parser.add_argument("--agent-name", default=os.environ.get("CVE_SEED_AGENT_NAME", "DESKTOP-423GKH1"))
    parser.add_argument("--index", default=os.environ.get("CVE_SEED_INDEX", "wazuh-states-vulnerabilities-default"))
    parser.add_argument("--ssh-host", default=os.environ.get("M2_LAB_SSH_HOST", "192.168.1.108"))
    parser.add_argument("--ssh-user", default=os.environ.get("M2_LAB_SSH_USER", "ubuntu"))
    parser.add_argument("--indexer-user", default=os.environ.get("WAZUH_INDEXER_USER", "admin"))
    parser.add_argument("--indexer-password", default=os.environ.get("WAZUH_INDEXER_PASSWORD", "admin"))
    parser.add_argument("--local-indexer-url", default=os.environ.get("WAZUH_INDEXER_URL", ""))
    args = parser.parse_args()

    docs = _build_docs(agent_id=args.agent_id, agent_name=args.agent_name)
    print(f"==> Seed {len(docs)} CVE docs → {args.index} agent={args.agent_id}")

    ssh_pass = (os.environ.get("SSHPASS") or "").strip()
    try:
        if args.local_indexer_url:
            result = _post_bulk_local(
                indexer_url=args.local_indexer_url,
                user=args.indexer_user,
                password=args.indexer_password,
                body=_bulk_body(index=args.index, docs=docs),
            )
        else:
            if not ssh_pass:
                print("Set SSHPASS for remote seed (or WAZUH_INDEXER_URL for local)", file=sys.stderr)
                return 1
            result = _post_bulk_remote_ssh(
                ssh_host=args.ssh_host,
                ssh_user=args.ssh_user,
                ssh_pass=ssh_pass,
                index=args.index,
                docs=docs,
                indexer_user=args.indexer_user,
                indexer_password=args.indexer_password,
            )
            _refresh_index(
                ssh_host=args.ssh_host,
                ssh_user=args.ssh_user,
                ssh_pass=ssh_pass,
                index=args.index,
                indexer_user=args.indexer_user,
                indexer_password=args.indexer_password,
            )
    except Exception as exc:
        print(f"FAIL bulk index: {exc}", file=sys.stderr)
        return 1

    if result.get("errors"):
        print(f"FAIL bulk errors: {json.dumps(result, ensure_ascii=False)[:500]}", file=sys.stderr)
        return 1

    indexed = sum(1 for item in (result.get("items") or []) if (item.get("index") or {}).get("result") in ("created", "updated"))
    print(f"OK  indexed={indexed} took={result.get('took')}ms")
    print("==> Next: restart API (clear vuln cache) + ./scripts/verify-topology-cve-context-lab.sh --strict")
    return 0


if __name__ == "__main__":
    sys.exit(main())
