from __future__ import annotations

import argparse
import json

from .labs import check_labs
from .orchestrator import Orchestrator
from .policy import PolicyViolation


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Safe multi-agent pentest harness MVP")
    parser.add_argument("--scenario", choices=["demo", "local-web"], default="demo")
    parser.add_argument("--target", default="demo.local")
    parser.add_argument("--output", default="out")
    parser.add_argument("--serve", action="store_true", help="start the loopback web console")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--check-labs", action="store_true", help="read-only readiness check for required labs")
    parser.add_argument("--mode", choices=["auto", "deterministic", "llm"], default="auto", help="agent decision mode; LLM reads HARNESS_LLM_* environment variables")
    parser.add_argument("--resume", metavar="CHECKPOINT", help="resume a run from a checkpoint JSON file")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.check_labs:
        print(json.dumps([check.__dict__ for check in check_labs()], ensure_ascii=False, indent=2))
        return 0
    if args.serve:
        from .dashboard import serve

        serve(host="127.0.0.1", port=args.port, output_dir=args.output)
        return 0
    try:
        state = Orchestrator(mode=args.mode).run(args.target, args.scenario, args.output, resume_from=args.resume)
    except PolicyViolation as exc:
        print(f"POLICY BLOCKED: {exc}")
        return 2
    except ValueError as exc:
        print(f"CONFIGURATION ERROR: {exc}")
        return 2
    print(json.dumps({"run_id": state.run_id, "status": state.status.value, "findings": len(state.findings), "reports": state.report_paths}, ensure_ascii=False, indent=2))
    return 0 if state.status.value == "completed" else 1
