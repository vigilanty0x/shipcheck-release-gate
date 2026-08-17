#!/usr/bin/env python3
"""Build Shipcheck wheel and sdist with the declared setuptools backend."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="dist")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = Path(args.out).resolve()
    output.mkdir(parents=True, exist_ok=True)
    from setuptools import build_meta
    old = Path.cwd()
    try:
        os.chdir(root)
        sdist = build_meta.build_sdist(str(output))
        wheel = build_meta.build_wheel(str(output))
    finally:
        os.chdir(old)
    print(json.dumps({"schema_version": "shipcheck/build-v1", "wheel": str(output / wheel), "sdist": str(output / sdist)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
