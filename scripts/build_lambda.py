"""Build a repeatable, self-contained Python 3.12 Lambda ZIP on Windows or Linux."""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
             "--no-compile", "--target", str(stage), "--no-deps", str(ROOT)],
            check=True,
        )
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
             "--no-compile", "--target", str(stage), "--no-deps", "-r",
             str(ROOT / "infra/requirements-lambda.txt")],
            check=True,
        )
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
                archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
