"""Minimal session auth for edge console (lab / appliance)."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from pathlib import Path
from typing import Optional

from fastapi import Cookie, HTTPException, Request, Response

_COOKIE = "edge_console_session"
_TTL_SEC = 60 * 60 * 12


def _secret() -> str:
    file_path = os.environ.get("EDGE_CONSOLE_PASSWORD_FILE", "/data/agent/console.password")
    try:
        stored = Path(file_path)
        if stored.is_file():
            text = stored.read_text(encoding="utf-8").strip()
            if text:
                return text
    except OSError:
        pass
    return (
        os.environ.get("EDGE_CONSOLE_SECRET")
        or os.environ.get("EDGE_CONSOLE_PASSWORD")
        or "sensel-edge-console-dev-change-me"
    )


def password_required() -> bool:
    file_path = os.environ.get("EDGE_CONSOLE_PASSWORD_FILE", "/data/agent/console.password")
    if Path(file_path).is_file():
        return True
    return bool((os.environ.get("EDGE_CONSOLE_PASSWORD") or "").strip())


def verify_password(password: str) -> bool:
    expected = _secret()
    env_pw = (os.environ.get("EDGE_CONSOLE_PASSWORD") or "").strip()
    if not env_pw and not Path(os.environ.get("EDGE_CONSOLE_PASSWORD_FILE", "/data/agent/console.password")).is_file():
        return True
    return hmac.compare_digest(password, expected)


def set_password(password: str) -> None:
    text = (password or "").strip()
    if len(text) < 8:
        raise ValueError("Password must be at least 8 characters")
    file_path = Path(os.environ.get("EDGE_CONSOLE_PASSWORD_FILE", "/data/agent/console.password"))
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(text, encoding="utf-8")
    try:
        os.chmod(file_path, 0o600)
    except OSError:
        pass


def _sign(payload: str) -> str:
    return hmac.new(_secret().encode(), payload.encode(), hashlib.sha256).hexdigest()


def create_session(response: Response) -> None:
    nonce = secrets.token_hex(8)
    exp = int(time.time()) + _TTL_SEC
    payload = f"{exp}.{nonce}"
    token = f"{payload}.{_sign(payload)}"
    response.set_cookie(
        _COOKIE,
        token,
        httponly=True,
        samesite="lax",
        max_age=_TTL_SEC,
        path="/",
    )


def clear_session(response: Response) -> None:
    response.delete_cookie(_COOKIE, path="/")


def _valid_token(token: Optional[str]) -> bool:
    if not token:
        return False
    parts = token.split(".")
    if len(parts) != 3:
        return False
    exp_str, nonce, sig = parts
    payload = f"{exp_str}.{nonce}"
    if not hmac.compare_digest(sig, _sign(payload)):
        return False
    try:
        exp = int(exp_str)
    except ValueError:
        return False
    return exp >= int(time.time())


def require_session(
    request: Request,
    edge_console_session: Optional[str] = Cookie(None, alias=_COOKIE),
) -> None:
    if not password_required():
        return
    if _valid_token(edge_console_session):
        return
    raise HTTPException(status_code=401, detail="Login required")
