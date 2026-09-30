from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml

from .schema import assert_detector_fields_unchanged, detector_owned_snapshot


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SLM_CONFIG = ROOT / "config" / "slm.yaml"


def load_slm_config(path: Path | None = None) -> dict[str, Any]:
    return yaml.safe_load((path or DEFAULT_SLM_CONFIG).read_text(encoding="utf-8")) or {}


def build_slm_input(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "evidence-0.1",
        "detector_outputs": event.get("detection", {}),
        "evidence": event.get("evidence", []),
        "asset_context": {
            "device_id": (event.get("asset") or {}).get("device_id"),
            "device_type": (event.get("asset") or {}).get("device_type"),
            "operating_state": (event.get("asset") or {}).get("operating_state"),
            "criticality": (event.get("asset") or {}).get("criticality", "unknown"),
        },
        "assessment_context": {
            "verdict": (event.get("assessment") or {}).get("verdict"),
            "severity": (event.get("assessment") or {}).get("severity"),
            "taxonomy": (event.get("assessment") or {}).get("taxonomy"),
        },
    }


_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_PROHIBITED_ACTION_RE = re.compile(
    r"\b(isolate|block|shutdown|firewall|exploit|credential|sudo|rm -rf)\b",
    re.IGNORECASE,
)


def _event_grounding_corpus(event: dict[str, Any]) -> str:
    """Flatten detector-owned and assessment fields for unsupported-claim checks."""
    chunks: list[str] = []
    for key in ("asset", "detection", "assessment", "evidence"):
        try:
            chunks.append(json.dumps(event.get(key), sort_keys=True, default=str))
        except TypeError:
            chunks.append(str(event.get(key)))
    return "\n".join(chunks)


def template_slm_output(event: dict[str, Any], config: dict[str, Any] | None = None) -> dict[str, Any]:
    config = config or load_slm_config()
    evidence_ids = [
        item.get("evidence_id")
        for item in event.get("evidence", [])
        if item.get("evidence_id")
    ]
    detection = event.get("detection") or {}
    assessment = event.get("assessment") or {}
    disagreement = bool(detection.get("disagreement"))
    status = "ok"
    taxonomy = assessment.get("taxonomy", "unknown")
    intents = ["asset_context", "playbook_lookup"]

    if detection.get("status") == "partial_detection":
        status = "insufficient_evidence"
        taxonomy = "insufficient_evidence"
        intents = ["asset_context", "behavior_baseline"]
    if disagreement:
        status = "conflict"
        taxonomy = "detector_conflict"
        intents = ["threat_context", "related_events"]
    if not evidence_ids:
        status = "insufficient_evidence"
        taxonomy = "insufficient_evidence"
        intents = ["none"]
        evidence_ids = []

    if taxonomy not in config.get("taxonomy_allowlist", []):
        taxonomy = "unknown"

    device_type = (event.get("asset") or {}).get("device_type", "device")
    verdict = assessment.get("verdict", "unknown")
    if status == "conflict":
        summary = (
            f"{device_type} detectors disagree; taxonomy=detector_conflict. "
            f"Human review required. Severity remains policy-owned; "
            f"no detector scores were modified. Verdict context={verdict}."
        )
    elif status == "insufficient_evidence":
        summary = (
            f"{device_type} event has insufficient detector evidence for a grounded label. "
            f"Status=insufficient_evidence. Severity remains policy-owned; "
            f"no detector scores were modified."
        )
    else:
        summary = (
            f"{device_type} event is assessed as {verdict} using only supplied detector evidence. "
            f"Severity remains policy-owned; no detector scores were modified."
        )
    return {
        "summary_en": summary[: int(config.get("max_summary_chars", 400))],
        "taxonomy": taxonomy,
        "evidence_ids": evidence_ids,
        "retrieval_intents": intents,
        "status": status,
    }


def hard_grounding_errors(
    output: dict[str, Any],
    event: dict[str, Any],
    config: dict[str, Any] | None = None,
) -> list[str]:
    """Errors that must trigger full template_fallback (no silent repair)."""
    config = config or load_slm_config()
    errors: list[str] = []
    detection = event.get("detection") or {}
    disagreement = bool(detection.get("disagreement"))
    partial = detection.get("status") == "partial_detection"

    allowed_evidence = {
        item.get("evidence_id")
        for item in event.get("evidence", [])
        if item.get("evidence_id")
    }
    evidence_ids = output.get("evidence_ids")
    if not isinstance(evidence_ids, list):
        errors.append("evidence_ids must be a list")
    else:
        for evidence_id in evidence_ids:
            if evidence_id not in allowed_evidence:
                errors.append(f"unknown evidence_id: {evidence_id}")

    summary = output.get("summary_en", "")
    if isinstance(summary, str) and summary.strip():
        if _PROHIBITED_ACTION_RE.search(summary):
            errors.append("summary_en contains prohibited action language")
        corpus = _event_grounding_corpus(event)
        if config.get("reject_ungrounded_ioc", True):
            for match in _IPV4_RE.findall(summary):
                if match not in corpus:
                    errors.append(f"ungrounded ipv4 in summary: {match}")
            for match in _CVE_RE.findall(summary):
                if match.upper() not in corpus.upper():
                    errors.append(f"ungrounded cve in summary: {match}")

    # Conflict / insufficient cases must abstain — do not accept a confident ok story.
    if disagreement:
        if output.get("taxonomy") != "detector_conflict":
            errors.append("disagreement requires taxonomy=detector_conflict")
        if output.get("status") != "conflict":
            errors.append("disagreement requires status=conflict")
    elif partial:
        if output.get("status") not in {"insufficient_evidence", "invalid"}:
            errors.append("partial_detection requires status=insufficient_evidence")
        if output.get("taxonomy") not in {"insufficient_evidence", "unknown"}:
            errors.append("partial_detection requires taxonomy=insufficient_evidence")

    return errors


def validate_slm_output(
    output: dict[str, Any],
    event: dict[str, Any],
    config: dict[str, Any] | None = None,
) -> list[str]:
    config = config or load_slm_config()
    errors: list[str] = []
    required = config.get("output_fields", [])
    for field in required:
        if field not in output:
            errors.append(f"missing field: {field}")

    taxonomy = output.get("taxonomy")
    if taxonomy not in config.get("taxonomy_allowlist", []):
        errors.append(f"taxonomy not allowlisted: {taxonomy}")

    status = output.get("status")
    if status not in config.get("status_allowlist", []):
        errors.append(f"status not allowlisted: {status}")

    allowed_intents = set(config.get("retrieval_intent_allowlist", []))
    intents = output.get("retrieval_intents")
    if not isinstance(intents, list):
        errors.append("retrieval_intents must be a list")
    else:
        for intent in intents:
            if intent not in allowed_intents:
                errors.append(f"retrieval intent not allowlisted: {intent}")

    errors.extend(hard_grounding_errors(output, event, config))

    summary = output.get("summary_en", "")
    if not isinstance(summary, str) or not summary.strip():
        errors.append("summary_en must be a non-empty string")
    elif len(summary) > int(config.get("max_summary_chars", 400)):
        errors.append("summary_en exceeds max_summary_chars")

    return errors


def coerce_slm_output(
    output: dict[str, Any],
    event: dict[str, Any],
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Repair near-miss model outputs before strict allowlist validation.

    Does not invent evidence_ids or mask unknown citations — those are hard failures.
    """
    config = config or load_slm_config()
    candidate = dict(output)
    detection = event.get("detection") or {}
    disagreement = bool(detection.get("disagreement"))
    partial = detection.get("status") == "partial_detection"
    no_evidence = not any(
        item.get("evidence_id") for item in event.get("evidence", []) if isinstance(item, dict)
    )

    # Detector conflict / partial always override model confidence.
    if disagreement:
        candidate["taxonomy"] = "detector_conflict"
        candidate["status"] = "conflict"
    elif partial or no_evidence:
        candidate["taxonomy"] = "insufficient_evidence"
        candidate["status"] = "insufficient_evidence"
    else:
        forbidden_tax = {
            "dos",
            "ddos",
            "mqtt",
            "recon",
            "spoofing",
            "benign",
            "attack",
            "docter_version",
        }
        taxonomy = str(candidate.get("taxonomy") or "").strip()
        allow = set(config.get("taxonomy_allowlist", []))
        if taxonomy not in allow or taxonomy.casefold() in forbidden_tax:
            candidate["taxonomy"] = "known_attack_suspected"
            candidate["status"] = "ok"

        status = str(candidate.get("status") or "").strip()
        if status not in config.get("status_allowlist", []):
            candidate["status"] = "ok"

    allowed_intents = set(config.get("retrieval_intent_allowlist", []))
    intents = candidate.get("retrieval_intents")
    if not isinstance(intents, list):
        intents = []
    cleaned = [str(item) for item in intents if str(item) in allowed_intents]
    if not cleaned:
        if disagreement:
            cleaned = ["threat_context", "related_events"]
        elif partial or no_evidence:
            cleaned = ["asset_context", "behavior_baseline"] if not no_evidence else ["none"]
        else:
            cleaned = ["asset_context", "playbook_lookup"]
    candidate["retrieval_intents"] = cleaned

    allowed_evidence = {
        item.get("evidence_id")
        for item in event.get("evidence", [])
        if item.get("evidence_id")
    }
    evidence_ids = candidate.get("evidence_ids")
    if not isinstance(evidence_ids, list):
        evidence_ids = []
    # Keep only grounded IDs; never backfill the full evidence list after a bad citation.
    candidate["evidence_ids"] = [str(item) for item in evidence_ids if str(item) in allowed_evidence]

    summary = candidate.get("summary_en")
    if not isinstance(summary, str) or not summary.strip():
        asset = (event.get("asset") or {}).get("device_type", "device")
        verdict = (event.get("assessment") or {}).get("verdict", "unknown")
        candidate["summary_en"] = (
            f"{asset} event is assessed as {verdict} using only supplied detector evidence. "
            f"Severity remains policy-owned; no detector scores were modified."
        )
    else:
        candidate["summary_en"] = summary.strip()[: int(config.get("max_summary_chars", 400))]

    return {
        "summary_en": candidate["summary_en"],
        "taxonomy": candidate["taxonomy"],
        "evidence_ids": candidate["evidence_ids"],
        "retrieval_intents": candidate["retrieval_intents"],
        "status": candidate["status"],
    }


def apply_slm_to_event(
    event: dict[str, Any],
    slm_output: dict[str, Any] | None = None,
    *,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Attach SLM fields without mutating detector-owned values.

    Hard grounding failures on raw model output force template_fallback without
    coercive repair that would hide hallucinations (SOW: no patch-and-publish).
    """
    config = config or load_slm_config()
    before = detector_owned_snapshot(event)
    errors: list[str] = []

    if slm_output is None:
        candidate = template_slm_output(event, config)
        generation_status = "template_fallback"
    else:
        hard_errors = hard_grounding_errors(slm_output, event, config)
        if hard_errors:
            candidate = template_slm_output(event, config)
            generation_status = "template_fallback"
            errors = hard_errors
        else:
            candidate = coerce_slm_output(slm_output, event, config)
            errors = validate_slm_output(candidate, event, config)
            if errors:
                candidate = template_slm_output(event, config)
                generation_status = "template_fallback"
            else:
                generation_status = "generated"

    summary_source = (
        "template_fallback"
        if generation_status == "template_fallback"
        else config.get("model_id", "slm")
    )

    updated = {
        **event,
        "enrichment": {
            **(event.get("enrichment") or {}),
            "status": "pending_rag" if candidate.get("retrieval_intents") else "unavailable",
            "retrieval_intents": candidate.get("retrieval_intents", []),
        },
        "assessment": {
            **(event.get("assessment") or {}),
            "summary": candidate["summary_en"],
            "summary_source": summary_source,
            "taxonomy": candidate["taxonomy"],
            "evidence_ids": candidate["evidence_ids"],
            "generation_status": generation_status,
            "slm_status": candidate["status"],
            "slm_validation_errors": errors,
        },
    }
    assert_detector_fields_unchanged(
        {"detection": before["detection"], "evidence": before["evidence"]},
        updated,
    )
    return updated


def parse_slm_json_text(text: str) -> dict[str, Any] | None:
    text = text.strip()
    if not text:
        return None

    def _try_load(raw: str) -> dict[str, Any] | None:
        try:
            payload = json.loads(raw)
            return payload if isinstance(payload, dict) else None
        except json.JSONDecodeError:
            return None

    direct = _try_load(text)
    if direct is not None:
        return direct

    # Prefer the first balanced JSON object.
    start = text.find("{")
    while start != -1:
        depth = 0
        for index in range(start, len(text)):
            char = text[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    candidate = _try_load(text[start : index + 1])
                    if candidate is not None:
                        return candidate
                    break
        start = text.find("{", start + 1)

    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not match:
        return None
    return _try_load(match.group(0))


class SlmFormatter:
    """Evidence-grounded formatter with mandatory schema/grounding fallback."""

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or load_slm_config()
        self.model_id = self.config.get("model_id", "HuggingFaceTB/SmolLM2-360M-Instruct")
        self.backend: str | None = None
        self._pipeline = None
        self._llama_bin: Path | None = None
        self._llama_model: Path | None = None
        self._llama_lib: Path | None = None
        self._llama_server: str | None = None

    @property
    def available(self) -> bool:
        return self.backend is not None

    def try_load(self) -> bool:
        """Load llama.cpp GGUF backend if configured, else transformers pipeline."""
        if self._try_load_llama_cpp():
            return True
        return self._try_load_transformers()

    def _try_load_llama_cpp(self) -> bool:
        server = os.environ.get("EDGEMED_LLAMA_SERVER") or self.config.get("llama_server")
        if server:
            self.backend = "llama_cpp_server"
            self.model_id = f"llama-server:{server}"
            self._llama_server = str(server).rstrip("/")
            self._pipeline = None
            return True

        bin_raw = os.environ.get("EDGEMED_LLAMA_BIN") or self.config.get("llama_bin")
        model_raw = os.environ.get("EDGEMED_LLAMA_MODEL") or self.config.get("llama_model")
        if not bin_raw or not model_raw:
            return False
        llama_bin = Path(str(bin_raw)).expanduser()
        llama_model = Path(str(model_raw)).expanduser()
        if not llama_bin.is_file() or not llama_model.is_file():
            return False
        self._llama_bin = llama_bin
        self._llama_model = llama_model
        self._llama_lib = llama_bin.parent
        self.backend = "llama_cpp"
        self.model_id = f"gguf:{llama_model.name}"
        self._pipeline = None
        return True

    def _try_load_transformers(self) -> bool:
        try:
            from transformers import pipeline

            self._pipeline = pipeline(
                "text-generation",
                model=self.model_id,
                max_new_tokens=int(self.config.get("max_tokens", 160)),
            )
            self.backend = "transformers"
            return True
        except Exception:
            self._pipeline = None
            self.backend = None
            return False

    def format_event(self, event: dict[str, Any]) -> dict[str, Any]:
        generated = None
        if self.backend is not None:
            prompt = self._prompt(event)
            try:
                if self.backend == "llama_cpp_server":
                    text = self._generate_llama_server(prompt)
                    generated = parse_slm_json_text(text)
                elif self.backend == "llama_cpp":
                    text = self._generate_llama_cpp(prompt)
                    generated = parse_slm_json_text(text)
                elif self._pipeline is not None:
                    result = self._pipeline(prompt)
                    text = result[0]["generated_text"]
                    generated = parse_slm_json_text(
                        text[len(prompt) :] if text.startswith(prompt) else text
                    )
            except Exception:
                generated = None
        return apply_slm_to_event(event, generated, config=self.config)

    def _generate_llama_server(self, prompt: str) -> str:
        assert self._llama_server is not None
        import urllib.error
        import urllib.request

        max_tokens = int(self.config.get("max_tokens", 160))
        timeout = int(self.config.get("llama_timeout_sec", 120))
        # Keep prompts short for small ctx on Pi.
        if len(prompt) > 1800:
            prompt = prompt[:1800]
        payload = json.dumps(
            {
                "prompt": prompt,
                "n_predict": max_tokens,
                "temperature": 0.2,
                "stop": ["\nINPUT:", "\n\n\n"],
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{self._llama_server}/completion",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"llama-server HTTP {exc.code}: {detail[:300]}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"llama-server request failed: {exc}") from exc
        if isinstance(body, dict) and body.get("error"):
            raise RuntimeError(f"llama-server error: {body.get('error')}")
        text = body.get("content") or body.get("generation") or ""
        if isinstance(text, list):
            text = "".join(str(part) for part in text)
        return str(text).strip()

    def _generate_llama_cpp(self, prompt: str) -> str:
        assert self._llama_bin is not None and self._llama_model is not None
        max_tokens = int(self.config.get("max_tokens", 160))
        threads = int(
            os.environ.get("EDGEMED_LLAMA_THREADS")
            or self.config.get("llama_threads")
            or 4
        )
        ctx = int(self.config.get("llama_ctx", 512))
        timeout = int(self.config.get("llama_timeout_sec", 90))
        env = os.environ.copy()
        if self._llama_lib is not None:
            lib = str(self._llama_lib)
            prev = env.get("LD_LIBRARY_PATH", "")
            env["LD_LIBRARY_PATH"] = f"{lib}:{prev}" if prev else lib

        # Prefer -f prompt file for long JSON prompts (safer than argv length).
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".txt", delete=False) as handle:
            handle.write(prompt)
            prompt_path = handle.name
        try:
            cmd = [
                str(self._llama_bin),
                "-m",
                str(self._llama_model),
                "-n",
                str(max_tokens),
                "-c",
                str(ctx),
                "--temp",
                "0.2",
                "-ngl",
                "0",
                "-t",
                str(threads),
                "-f",
                prompt_path,
            ]
            # Newer builds may support --no-conversation; ignore if unsupported.
            if "cli" in self._llama_bin.name:
                cmd.insert(1, "--no-conversation")
            completed = subprocess.run(
                cmd,
                cwd=str(self._llama_bin.parent),
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
        finally:
            try:
                Path(prompt_path).unlink(missing_ok=True)
            except OSError:
                pass

        text = (completed.stdout or "") + "\n" + (completed.stderr or "")
        # Keep the model completion portion when the binary echoes the prompt.
        if "OUTPUT:" in text:
            text = text.split("OUTPUT:", 1)[1]
        return text.strip()

    def _prompt(self, event: dict[str, Any]) -> str:
        payload = build_slm_input(event)
        return (
            "You are an evidence-grounded security event formatter. "
            "Return only JSON with keys summary_en, taxonomy, evidence_ids, "
            "retrieval_intents, status. Use only provided evidence IDs. "
            "Do not invent detector scores or tool calls.\n"
            f"INPUT:\n{json.dumps(payload, ensure_ascii=True)}\nOUTPUT:\n"
        )
