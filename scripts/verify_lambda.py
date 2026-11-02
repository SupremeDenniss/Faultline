"""Inspect a Lambda ZIP offline; no AWS credentials or package installation needed."""

from __future__ import annotations

import argparse
import ast
import hashlib
import re
import zipfile
from pathlib import Path

REQUIRED = {
    "faultline/__init__.py", "faultline/aws/__init__.py",
    "faultline/aws/handler.py", "faultline/aws/store.py",
    "faultline/aws/gateway.py", "faultline/correlation.py", "faultline/normalize.py",
    "faultline/rules.py", "faultline/models.py", "boto3/__init__.py",
    "botocore/__init__.py", "jmespath/__init__.py", "s3transfer/__init__.py",
    "dateutil/__init__.py", "six.py",
}
FORBIDDEN = (
    ".env", ".aws", ".git", "__pycache__", "tests/", ".pytest_cache",
    "faultline/fixtures/", "faultline/cli.py", "faultline/storage.py",
    "faultline/aws/live_validation.py", "faultline/aws/readiness.py",
)
NATIVE = (".pyd", ".dll", ".dylib", ".so")
SECRET_MARKERS = (
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)


def verify_zip(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or not REQUIRED.issubset(names):
            raise ValueError("duplicate ZIP members or required Lambda modules are missing")
        if any(name.startswith("/") or ".." in Path(name).parts for name in names):
            raise ValueError("unsafe ZIP path")
        for name in names:
            lowered = name.lower()
            if (any(part in lowered for part in FORBIDDEN)
                    or lowered.endswith(NATIVE) or "win_amd64" in lowered):
                raise ValueError("development, secret, or native platform file in Lambda ZIP")
            data = archive.read(name)
            if any(marker.search(data) for marker in SECRET_MARKERS):
                raise ValueError("possible credential material in Lambda ZIP")
            if name.endswith(".py"):
                ast.parse(data.decode("utf-8"), filename=name, feature_version=(3, 12))
            if name.endswith(".dist-info/WHEEL"):
                tags = re.findall(rb"^Tag: (.+)$", data, flags=re.MULTILINE)
                if not tags or any(b"none-any" not in tag for tag in tags):
                    raise ValueError("dependency wheel is not platform independent")
        handler = ast.parse(archive.read("faultline/aws/handler.py").decode("utf-8"))
        if not any(isinstance(node, ast.FunctionDef) and node.name == "lambda_handler"
                   for node in handler.body):
            raise ValueError("configured Lambda handler is missing")
    return digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("zip_path", type=Path)
    args = parser.parse_args()
    print(f"SHA-256 {verify_zip(args.zip_path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
