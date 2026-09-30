import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.data import write_json
from app.failure_injection import run_failure_matrix
from app.rag import build_default_orchestrator

parser = argparse.ArgumentParser(description="Run detector/SLM/RAG failure-injection matrix")
parser.add_argument("--output", default=str(ROOT / "artifacts" / "failure_injection_report.json"))
args = parser.parse_args()

report = run_failure_matrix(
    known_attack={"category": "Attack", "probability": 0.91, "model_version": "xgb-0.1.0"},
    anomaly={"score": 0.83, "threshold": 0.70, "model_version": "if-0.1.0"},
    orchestrator_factory=lambda: build_default_orchestrator(
        related_events_provider=lambda device_id, limit=5: []
    ),
)
write_json(Path(args.output), report)
print(json.dumps(report, indent=2))
raise SystemExit(0 if report["passed"] else 1)
