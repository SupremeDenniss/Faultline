"""Inspect a Lambda ZIP offline; no AWS credentials or package installation needed."""

from __future__ import annotations

import argparse
import ast
import base64
import csv
import hashlib
import io
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

REQUIRED = {
    "faultline/__init__.py", "faultline/aws/__init__.py",
    "faultline/aws/handler.py", "faultline/aws/store.py",
    "faultline/aws/gateway.py", "faultline/correlation.py", "faultline/normalize.py",
    "faultline/rules.py", "faultline/models.py", "boto3/__init__.py",
    "botocore/__init__.py", "jmespath/__init__.py", "s3transfer/__init__.py",
    "dateutil/__init__.py", "six.py",
    "urllib3/__init__.py",
    "botocore/data/endpoints.json", "botocore/data/partitions.json",
    "botocore/data/_retry.json",
    "botocore/data/dynamodb/2012-08-10/service-2.json.gz",
    "botocore/data/dynamodb/2012-08-10/paginators-1.json",
}
FORBIDDEN = (
    ".env", ".aws", ".git", "__pycache__", "tests/", ".pytest_cache",
    "faultline/fixtures/", "faultline/cli.py", "faultline/storage.py",
    "faultline/aws/live_validation.py", "faultline/aws/readiness.py",
)
NATIVE = (".pyd", ".dll", ".dylib", ".so")
SECRET_MARKERS = {
    "aws_access_key_pattern": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "pem_private_key_header": re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
}


def _vendor_example(name: str) -> str | None:
    parts = PurePosixPath(name).parts
    if len(parts) == 3 and parts[:2] == ("boto3", "examples") and name.endswith(".rst"):
        return "boto3"
    if (len(parts) == 5 and parts[:2] == ("botocore", "data")
            and re.fullmatch(r"\d{4}-\d{2}-\d{2}", parts[3])
            and parts[4] == "examples-1.json"):
        return "botocore"
    return None


def prune_verified_vendor_examples(stage: Path) -> tuple[str, ...]:
    """Remove only hashed wheel examples, leaving service models and code untouched."""
    records: dict[str, dict[str, tuple[str, str]]] = {}
    removed: list[str] = []
    for path in sorted(stage.rglob("*")):
        if not path.is_file():
            continue
        name = path.relative_to(stage).as_posix()
        vendor = _vendor_example(name)
        if vendor is None:
            continue
        if path.is_symlink():
            raise ValueError(f"member={name!r} category=vendor_example_symlink")
        if vendor not in records:
            manifests = list(stage.glob(f"{vendor}-*.dist-info/RECORD"))
            if len(manifests) != 1:
                raise ValueError(f"category={vendor}_wheel_record_missing_or_ambiguous")
            rows = csv.reader(io.StringIO(manifests[0].read_text(encoding="utf-8")))
            records[vendor] = {row[0]: (row[1], row[2]) for row in rows}
        expected = records[vendor].get(name)
        data = path.read_bytes()
        if expected is None or not expected[0].startswith("sha256="):
            raise ValueError(f"member={name!r} category=vendor_example_provenance_missing")
        encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
        if encoded != expected[0].partition("=")[2] or str(len(data)) != expected[1]:
            raise ValueError(f"member={name!r} category=vendor_example_provenance_mismatch")
        path.unlink()
        removed.append(name)
    return tuple(removed)


def verify_zip(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("category=duplicate_zip_member")
        missing = sorted(REQUIRED - set(names))
        if missing:
            raise ValueError(f"member={missing[0]!r} category=required_runtime_file_missing")
        for name in names:
            if (PurePosixPath(name).is_absolute() or Path(name).is_absolute()
                    or ".." in PurePosixPath(name).parts):
                raise ValueError(f"member={name!r} category=unsafe_zip_path")
        for name in names:
            lowered = name.lower()
            if _vendor_example(name) is not None:
                raise ValueError(f"member={name!r} category=unpruned_vendor_example")
            if (any(part in lowered for part in FORBIDDEN)
                    or lowered.endswith(NATIVE) or "win_amd64" in lowered):
                raise ValueError(f"member={name!r} category=forbidden_or_native_file")
            data = archive.read(name)
            for category, marker in SECRET_MARKERS.items():
                if marker.search(data):
                    raise ValueError(f"member={name!r} category={category}")
            if name.endswith(".py"):
                try:
                    ast.parse(data.decode("utf-8"), filename=name, feature_version=(3, 12))
                except (SyntaxError, UnicodeError):
                    raise ValueError(f"member={name!r} category=python312_syntax") from None
            if name.endswith(".dist-info/WHEEL"):
                tags = re.findall(rb"^Tag: (.+)$", data, flags=re.MULTILINE)
                if not tags or any(b"none-any" not in tag for tag in tags):
                    raise ValueError(f"member={name!r} category=non_pure_wheel")
        handler = ast.parse(archive.read("faultline/aws/handler.py").decode("utf-8"))
        if not any(isinstance(node, ast.FunctionDef) and node.name == "lambda_handler"
                   for node in handler.body):
            raise ValueError("member='faultline/aws/handler.py' category=handler_missing")
    return digest


def runtime_check_zip(path: Path) -> None:
    """Import the extracted artifact with Python 3.12 and load its DynamoDB model."""
    if sys.version_info[:2] != (3, 12):
        raise ValueError("category=python312_required_for_runtime_check")
    verify_zip(path)
    with tempfile.TemporaryDirectory() as temporary:
        stage = Path(temporary)
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                target = stage / PurePosixPath(name)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(name))
        code = "\n".join((
            "import sys",
            "sys.path.insert(0, sys.argv[1])",
            "step = 'handler_import'",
            "try:",
            "    from faultline.aws.handler import lambda_handler",
            "    step = 'boto3_import'",
            "    from faultline.aws.gateway import Boto3Gateway",
            "    Boto3Gateway(object())",
            "    step = 'dynamodb_model'",
            "    from botocore.loaders import Loader",
            "    model = Loader().load_service_model('dynamodb', 'service-2')",
            "    assert callable(lambda_handler)",
            "    assert {'GetItem', 'PutItem', 'Query', 'TransactWriteItems'} <= "
            "set(model['operations'])",
            "except Exception as exc:",
            "    print(step + ':' + type(exc).__name__, file=sys.stderr)",
            "    sys.exit(1)",
        ))
        result = subprocess.run(
            [sys.executable, "-I", "-c", code, str(stage)],
            capture_output=True, text=True, check=False,
        )
        if result.returncode:
            detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "unknown"
            raise ValueError(
                f"category=python312_runtime_import_or_model_failure detail={detail}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("zip_path", type=Path)
    parser.add_argument("--runtime-smoke", action="store_true",
                        help="also import the extracted ZIP with Python 3.12")
    args = parser.parse_args()
    digest = verify_zip(args.zip_path)
    if args.runtime_smoke:
        runtime_check_zip(args.zip_path)
    print(f"SHA-256 {digest}")
    if args.runtime_smoke:
        print("Python 3.12 handler import and DynamoDB model: pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
