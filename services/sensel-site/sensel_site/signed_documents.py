"""Bounded detached Ed25519 document signing and verification helpers."""

from __future__ import annotations

import base64
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from sensel_site.lineage import canonical_json, sha256_bytes

_KEY_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def read_regular_file(path: str | Path, *, maximum_bytes: int) -> bytes:
    target = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > maximum_bytes
        ):
            raise ValueError(f"signed input size/type is invalid: {target.name}")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise ValueError(f"signed input was truncated: {target.name}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError(f"signed input grew during read: {target.name}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def detached_signature(
    payload: bytes,
    *,
    private_key: Ed25519PrivateKey,
    key_id: str,
) -> dict[str, str]:
    if not _KEY_ID.fullmatch(key_id.strip()):
        raise ValueError("signing key_id is invalid")
    return {
        "algorithm": "Ed25519",
        "key_id": key_id.strip(),
        "signed_sha256": sha256_bytes(payload),
        "signature": base64.b64encode(private_key.sign(payload)).decode("ascii"),
    }


def encode_embedded_signed_document(
    document: Mapping[str, Any],
    *,
    private_key: Ed25519PrivateKey,
    key_id: str,
) -> tuple[bytes, bytes, str]:
    unsigned = dict(document)
    unsigned.pop("signature", None)
    payload = canonical_json(unsigned)
    signature = detached_signature(payload, private_key=private_key, key_id=key_id)
    signed = {
        **unsigned,
        "signature": {
            "algorithm": "Ed25519",
            "key_id": key_id,
            "signed_fields": "canonical-document-without-signature",
        },
    }
    return (
        canonical_json(signed) + b"\n",
        canonical_json(signature) + b"\n",
        sha256_bytes(payload),
    )


def verify_detached_document(
    document_path: str | Path,
    signature_path: str | Path,
    *,
    public_key: Ed25519PublicKey,
    expected_key_id: str,
    maximum_document_bytes: int = 1_048_576,
) -> tuple[dict[str, Any], str]:
    raw = read_regular_file(document_path, maximum_bytes=maximum_document_bytes)
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("signed document is not valid JSON") from exc
    if not isinstance(document, dict):
        raise ValueError("signed document root must be an object")
    payload = canonical_json(document)
    try:
        signature = json.loads(
            read_regular_file(signature_path, maximum_bytes=16_384)
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("detached signature is not valid JSON") from exc
    if not isinstance(signature, Mapping) or signature.get("algorithm") != "Ed25519":
        raise ValueError("detached signature algorithm is invalid")
    if signature.get("key_id") != expected_key_id:
        raise ValueError("detached signature key is not trusted")
    digest = sha256_bytes(payload)
    if signature.get("signed_sha256") != digest:
        raise ValueError("detached signed document digest mismatch")
    try:
        public_key.verify(
            base64.b64decode(str(signature["signature"]), validate=True),
            payload,
        )
    except (InvalidSignature, KeyError, ValueError) as exc:
        raise ValueError("detached document signature verification failed") from exc
    return document, digest


def verify_embedded_signed_document(
    document_path: str | Path,
    signature_path: str | Path,
    *,
    public_key: Ed25519PublicKey,
    expected_key_id: str,
    maximum_document_bytes: int = 1_048_576,
) -> tuple[dict[str, Any], str]:
    raw = read_regular_file(document_path, maximum_bytes=maximum_document_bytes)
    try:
        signed = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("signed document is not valid JSON") from exc
    if not isinstance(signed, dict):
        raise ValueError("signed document root must be an object")
    metadata = signed.pop("signature", None)
    if (
        not isinstance(metadata, Mapping)
        or metadata.get("algorithm") != "Ed25519"
        or metadata.get("key_id") != expected_key_id
        or metadata.get("signed_fields")
        != "canonical-document-without-signature"
    ):
        raise ValueError("embedded document signature metadata is invalid")
    payload = canonical_json(signed)
    try:
        signature = json.loads(
            read_regular_file(signature_path, maximum_bytes=16_384)
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("detached signature is not valid JSON") from exc
    if (
        not isinstance(signature, Mapping)
        or signature.get("algorithm") != "Ed25519"
        or signature.get("key_id") != expected_key_id
        or signature.get("signed_sha256") != sha256_bytes(payload)
    ):
        raise ValueError("detached signature metadata is invalid")
    try:
        public_key.verify(
            base64.b64decode(str(signature["signature"]), validate=True),
            payload,
        )
    except (InvalidSignature, KeyError, ValueError) as exc:
        raise ValueError("signed document verification failed") from exc
    return signed, sha256_bytes(payload)


def write_exclusive(path: Path, payload: bytes, *, mode: int = 0o444) -> None:
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("signed output write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
