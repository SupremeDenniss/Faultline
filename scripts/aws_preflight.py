"""Explicit, read-only AWS preflight. Prints a sanitized JSON readiness report."""

from __future__ import annotations

import argparse
import json

from faultline.aws.readiness import run_preflight


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--expected-account", required=True)
    parser.add_argument("--stack", required=True)
    parser.add_argument("--bucket", required=True)
    args = parser.parse_args()
    import boto3

    try:
        session = boto3.Session(profile_name=args.profile)
        report = run_preflight(
            session, profile=args.profile, region=args.region,
            expected_account=args.expected_account, stack_name=args.stack,
            bucket=args.bucket,
        )
    except Exception as exc:
        report = {"kind": "read_only_preflight", "status": "fail",
                  "checks": [{"name": "setup", "status": "fail",
                              "detail": f"preflight setup failed: {type(exc).__name__}"}]}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
