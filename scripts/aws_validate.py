"""Inspect a deployed stack or explicitly run a sanitized direct-SQS smoke test."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from faultline import __version__
from faultline.aws.live_validation import inspect_stack, smoke_test


def _commit() -> str | None:
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _dirty() -> bool | None:
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        ["git", "status", "--porcelain"], cwd=root, capture_output=True, text=True,
        check=False,
    )
    return bool(result.stdout.strip()) if result.returncode == 0 else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--expected-account", required=True)
    parser.add_argument("--stack", required=True)
    parser.add_argument("--report", type=Path)
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("inspect", help="read-only deployed-resource checks")
    smoke = subcommands.add_parser("smoke", help="send sanitized direct-SQS test events")
    smoke.add_argument("--send", action="store_true", help="explicit mutation gate")
    smoke.add_argument("--confirm-account", required=True)
    smoke.add_argument("--test-id", required=True)
    args = parser.parse_args()
    import boto3

    try:
        session = boto3.Session(profile_name=args.profile)
        if args.command == "inspect":
            report = inspect_stack(
                session, region=args.region, expected_account=args.expected_account,
                stack_name=args.stack,
            )
        else:
            report = smoke_test(
                session, region=args.region, expected_account=args.expected_account,
                stack_name=args.stack, confirmed_account=args.confirm_account,
                test_id=args.test_id, send=args.send,
            )
    except Exception as exc:
        report = {"kind": args.command, "status": "fail",
                  "checks": [{"name": "execution", "status": "fail",
                              "detail": f"validation stopped: {type(exc).__name__}"}]}
    report["application_version"] = __version__
    report["commit_sha"] = _commit()
    report["working_tree_dirty"] = _dirty()
    report["validation_mode"] = (
        "direct_sqs" if args.command == "smoke" else "read_only_deployed_inspection"
    )
    rendered = json.dumps(report, indent=2, sort_keys=True, default=str) + "\n"
    if args.report:
        args.report.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
