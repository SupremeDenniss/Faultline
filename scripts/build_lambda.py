"""Build the Python 3.12 Linux x86_64 Lambda ZIP without touching AWS."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from verify_lambda import prune_verified_vendor_examples, runtime_check_zip, verify_zip

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_MODULES = (
    "__init__.py", "models.py", "normalize.py", "rules.py", "correlation.py",
    "aws/__init__.py", "aws/gateway.py", "aws/store.py", "aws/handler.py",
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, default=ROOT / ".faultline/dist/faultline-lambda.zip"
    )
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 12):
        parser.error("build with Python 3.12 to match the Lambda runtime")
    output = args.output.resolve()
    if not output.is_relative_to(ROOT):
        parser.error("output must be inside the repository")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        stage = Path(temporary) / "package"
        stage.mkdir()
        for module in RUNTIME_MODULES:
            source = ROOT / "src/faultline" / module
            destination = stage / "faultline" / module
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
             "--no-compile", "--no-deps", "--only-binary=:all:",
             "--platform", "manylinux2014_x86_64", "--implementation", "cp",
             "--python-version", "3.12", "--target", str(stage),
             "-r", str(ROOT / "infra/requirements-lambda.txt")],
            check=True,
        )
        removed = prune_verified_vendor_examples(stage)
        with zipfile.ZipFile(
            output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as archive:
            for path in sorted(stage.rglob("*")):
                if not path.is_file() or "__pycache__" in path.parts:
                    continue
                name = path.relative_to(stage).as_posix()
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o644 << 16
                archive.writestr(info, path.read_bytes())
    digest = verify_zip(output)
    runtime_check_zip(output)
    output.with_suffix(".zip.sha256").write_text(
        f"{digest}  {output.name}\n", encoding="ascii"
    )
    print(f"{output}\nExcluded verified SDK examples: {len(removed)}\nSHA-256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
