"""After explicit approval, call a sandbox AssumeRole without exposing credentials."""

from __future__ import annotations

import argparse
import json
import re
from datetime import UTC, datetime


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--expected-account", required=True)
    parser.add_argument("--confirm-account", required=True)
    parser.add_argument("--role-arn", required=True)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if not args.run or args.confirm_account != args.expected_account:
        parser.error("--run and matching --confirm-account are required")
    match = re.fullmatch(r"arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9_+=,.@/-]+", args.role_arn)
    if not match or match.group(1) != args.expected_account:
        parser.error("role ARN must be an approved role in the expected account")
    import boto3

    try:
        session = boto3.Session(profile_name=args.profile)
        if session.region_name not in (None, args.region):
            raise ValueError("profile Region differs from requested Region")
        sts = session.client("sts", region_name=args.region)
        if sts.get_caller_identity()["Account"] != args.expected_account:
            raise ValueError("AWS account differs from expected account")
        name = "faultline-validation-" + datetime.now(UTC).strftime("%Y%m%d%H%M%S")
        response = sts.assume_role(RoleArn=args.role_arn, RoleSessionName=name,
                                   DurationSeconds=900)
        request_id = response.get("ResponseMetadata", {}).get("RequestId")
        del response
        print(json.dumps({"status": "submitted", "session_name": name,
                          "request_id": request_id, "region": args.region}))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "fail", "error_category": type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
