#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""只读预检：为人类和 AI 助手给出可执行的环境准备结果。"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import struct
import sys
from pathlib import Path

from workflow_common import (
    WorkflowConfigError,
    count_encrypted_databases,
    discover_db_dirs,
    discover_weixin_exes,
    get_file_version,
    resolve_anchor_config,
    resolve_db_dir,
    resolve_secrets_dir,
    resolve_weixin_dll,
    resolve_weixin_paths,
)


def _path_info(path: Path) -> dict[str, object]:
    digest = hashlib.sha256(os.fspath(path).encode("utf-8")).hexdigest()[:12]
    return {"candidate_id": digest, "leaf": path.name, "exists": path.exists()}


def build_report() -> dict[str, object]:
    checks: list[dict[str, object]] = []
    missing_config = False
    invalid = False

    def add(name: str, status: str, detail: object, action: str = "") -> None:
        nonlocal missing_config, invalid
        checks.append({"name": name, "status": status, "detail": detail, "action": action})
        missing_config |= status == "needs_input"
        invalid |= status == "error"

    py_ok = sys.version_info >= (3, 10)
    add("python", "ok" if py_ok else "error",
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "安装 64 位 Python 3.10 或更高版本" if not py_ok else "")
    platform_ok = os.name == "nt" and struct.calcsize("P") == 8
    add("platform", "ok" if platform_ok else "error",
        {"os": os.name, "pointer_bits": struct.calcsize("P") * 8},
        "必须在 Windows 10/11 x64 与 64 位 Python 中运行" if not platform_ok else "")

    if os.environ.get("WX_EXE", "").strip():
        try:
            exe, workdir = resolve_weixin_paths()
            add("wechat_install", "ok", {
                "exe": _path_info(exe),
                "workdir": _path_info(workdir),
                "exe_file_version": get_file_version(exe),
            })
        except WorkflowConfigError as exc:
            add("wechat_install", "error", str(exc), "修正 WX_EXE / WX_DIR")
    else:
        exe_candidates = discover_weixin_exes() if os.name == "nt" else []
        add("wechat_install", "needs_input",
            {"detected_candidates": [_path_info(path) for path in exe_candidates]},
            "由用户确认候选后，在当前终端设置 WX_EXE；WX_DIR 通常可省略")

    if os.environ.get("WX_DB_DIR", "").strip():
        try:
            db_dir = resolve_db_dir()
            encrypted, plaintext = count_encrypted_databases(db_dir)
            status = "ok" if encrypted else "error"
            add("database_dir", status, {
                "directory": _path_info(db_dir),
                "encrypted_db_count": encrypted,
                "plaintext_db_count": plaintext,
            }, "确认 WX_DB_DIR 指向所选账号的 db_storage" if not encrypted else "")
        except WorkflowConfigError as exc:
            add("database_dir", "error", str(exc), "修正 WX_DB_DIR")
    else:
        db_candidates = discover_db_dirs() if os.name == "nt" else []
        add("database_dir", "needs_input",
            {"detected_candidates": [_path_info(path) for path in db_candidates]},
            "由用户确认账号目录后，在当前终端设置 WX_DB_DIR")

    try:
        rva, expected_version, expected_bytes = resolve_anchor_config()
        actual_version = ""
        dll_error = None
        if os.environ.get("WX_EXE", "").strip():
            try:
                exe, workdir = resolve_weixin_paths()
                actual_version = get_file_version(resolve_weixin_dll(exe, workdir))
            except WorkflowConfigError as exc:
                dll_error = str(exc)
        if dll_error:
            add("breakpoint_profile", "error", dll_error, "修正 WX_DLL")
        else:
            status = "ok"
            action = ""
            if os.environ.get("WX_EXE", "").strip() and not actual_version:
                status = "error"
                action = "无法读取 Weixin.dll 完整文件版本；不要继续运行步骤 1"
            elif actual_version and actual_version != expected_version:
                status = "error"
                action = "先运行 find_kdf_anchor.py，再设置三个 WX_* 锚点环境变量"
            add("breakpoint_profile", status, {
                "rva": hex(rva),
                "expected_version": expected_version,
                "actual_dll_version": actual_version or None,
                "expected_bytes_length": len(expected_bytes),
            }, action)
    except WorkflowConfigError as exc:
        add("breakpoint_profile", "error", str(exc), "修正 WX_BP_RVA / WX_EXPECTED_VERSION / WX_EXPECTED_FN_BYTES")

    try:
        secrets_dir = resolve_secrets_dir()
        add("sensitive_output", "ok", {
            "directory": "WX_SECRETS_DIR" if os.environ.get("WX_SECRETS_DIR") else "repository secrets/",
            "exists": secrets_dir.exists(),
        })
    except WorkflowConfigError as exc:
        add("sensitive_output", "error", str(exc), "修正 WX_SECRETS_DIR")

    dependencies = {
        "pycryptodome_for_selftest": importlib.util.find_spec("Crypto") is not None,
        "capstone_for_version_adaptation": importlib.util.find_spec("capstone") is not None,
    }
    dependencies_ok = all(dependencies.values())
    add("optional_dependencies", "ok" if dependencies_ok else "warning",
        dependencies,
        "" if dependencies_ok else "运行 python -m pip install -r requirements.txt")

    exit_code = 1 if invalid else (2 if missing_config else 0)
    return {
        "schema_version": 1,
        "ready": exit_code == 0,
        "exit_code": exit_code,
        "checks": checks,
        "next_step": (
            "python scripts/1_capture_launch.py" if exit_code == 0
            else "按 action 修正环境后重新运行预检"
        ),
    }


def _print_human(report: dict[str, object]) -> None:
    labels = {"ok": "OK", "warning": "WARN", "needs_input": "INPUT", "error": "ERROR"}
    print("WX-chatlog 环境预检（只读）")
    print("=" * 48)
    for check in report["checks"]:
        label = labels[check["status"]]
        print(f"[{label}] {check['name']}: {json.dumps(check['detail'], ensure_ascii=False)}")
        if check["action"]:
            print(f"       → {check['action']}")
    print("=" * 48)
    print("READY" if report["ready"] else f"NOT READY (exit={report['exit_code']})")
    print(report["next_step"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="输出供 AI/脚本读取的 JSON")
    args = parser.parse_args()
    report = build_report()
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        _print_human(report)
    return int(report["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
