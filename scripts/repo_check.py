#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一键运行发布前的离线、隐私与 Windows 权限门禁。"""

from __future__ import annotations

import argparse
import os
import shutil

# 仅执行下方固定命令数组，不启用 shell。
import subprocess  # nosec B404
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run_check(name: str, command: list[str], env: dict[str, str]) -> bool:
    print(f"\n== {name} ==", flush=True)
    # command 只来自 main 内固定门禁列表。
    result = subprocess.run(  # nosec B603
        command, cwd=ROOT, env=env, check=False
    )
    if result.returncode:
        print(f"[FAIL] {name} (exit={result.returncode})", flush=True)
        return False
    print(f"[OK] {name}", flush=True)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-history", action="store_true",
                        help="隐私检查跳过 Git 历史（发布前不要使用）")
    args = parser.parse_args()
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    python = sys.executable
    git = shutil.which("git")
    if not git:
        print("REPO_CHECK_FAILED: 未找到 Git 可执行文件")
        return 2
    git_path = Path(git).resolve()
    if git_path == ROOT or ROOT in git_path.parents:
        print("REPO_CHECK_FAILED: 拒绝执行仓库目录内的 Git 可执行文件")
        return 2
    privacy = [python, "scripts/privacy_check.py"]
    if args.no_history:
        privacy.append("--no-history")
    checks = (
        ("Python 编译", [python, "-m", "compileall", "-q", "scripts", "tests"]),
        ("单元测试", [python, "-m", "unittest", "discover", "-s", "tests", "-v"]),
        ("加密自检", [python, "scripts/selftest_crypto.py"]),
        ("加密自检 (-O)", [python, "-O", "scripts/selftest_crypto.py"]),
        ("Windows DACL 自检", [python, "scripts/win_dacl.py"]),
        ("隐私检查", privacy),
        ("Git 空白错误检查", [str(git_path), "diff", "--check"]),
    )
    failed = [name for name, command in checks if not run_check(name, command, env)]
    print("\n" + "=" * 52)
    if failed:
        print("REPO_CHECK_FAILED: " + ", ".join(failed))
        return 1
    print("REPO_CHECK_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
