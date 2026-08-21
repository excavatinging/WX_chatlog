#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证并安装 all_keys.json 与 db_dir 到当前用户的 wechat-cli 状态目录。"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
from pathlib import Path, PurePosixPath

from win_dacl import secure_directory, secure_write_text
from workflow_common import (
    WorkflowConfigError,
    require_windows_x64,
    resolve_db_dir,
    resolve_secrets_dir,
)

HEX_64 = re.compile(r"[0-9a-fA-F]{64}")
HEX_32 = re.compile(r"[0-9a-fA-F]{32}")


def validate_key_map(payload: object) -> dict[str, dict[str, object]]:
    if not isinstance(payload, dict) or not payload:
        raise WorkflowConfigError("all_keys.json 必须是非空对象")
    result: dict[str, dict[str, object]] = {}
    seen_paths: set[str] = set()
    for raw_path, info in payload.items():
        if not isinstance(raw_path, str) or not isinstance(info, dict):
            raise WorkflowConfigError("all_keys.json 的路径或记录类型无效")
        normalized = raw_path.replace("\\", "/")
        pure_path = PurePosixPath(normalized)
        parts = pure_path.parts
        canonical = pure_path.as_posix()
        if (not parts or normalized.startswith("/") or ".." in parts
                or any(":" in part or "\x00" in part for part in parts)):
            raise WorkflowConfigError("all_keys.json 含不安全的数据库相对路径")
        if not canonical.casefold().endswith(".db"):
            raise WorkflowConfigError("all_keys.json 的路径必须指向 .db 文件")
        path_key = canonical.casefold()
        if path_key in seen_paths:
            raise WorkflowConfigError("all_keys.json 含归一化后重复的数据库路径")
        enc_key = info.get("enc_key")
        salt = info.get("salt")
        size_mb = info.get("size_mb")
        if not isinstance(enc_key, str) or not HEX_64.fullmatch(enc_key):
            raise WorkflowConfigError("all_keys.json 含无效 enc_key（值已隐藏）")
        if not isinstance(salt, str) or not HEX_32.fullmatch(salt):
            raise WorkflowConfigError("all_keys.json 含无效 salt（值已隐藏）")
        if (isinstance(size_mb, bool) or not isinstance(size_mb, (int, float))
                or not math.isfinite(size_mb) or size_mb < 0):
            raise WorkflowConfigError("all_keys.json 含无效 size_mb")
        seen_paths.add(path_key)
        result[canonical] = dict(info)
    return result


def load_existing_config(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkflowConfigError("现有 wechat-cli config.json 无法安全解析，未覆盖") from exc
    if not isinstance(value, dict):
        raise WorkflowConfigError("现有 wechat-cli config.json 不是对象，未覆盖")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true",
                        help="确认写入 ~/.wechat-cli；不带此参数只做预演")
    args = parser.parse_args()
    try:
        require_windows_x64()
        db_dir = resolve_db_dir()
        source = resolve_secrets_dir() / "all_keys.json"
        if not source.is_file():
            raise WorkflowConfigError("尚未生成 all_keys.json；先运行步骤 3")
        try:
            key_map = validate_key_map(json.loads(source.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError) as exc:
            raise WorkflowConfigError("all_keys.json 无法解析") from exc
        state_dir = Path.home() / ".wechat-cli"
        keys_target = state_dir / "all_keys.json"
        config_target = state_dir / "config.json"
        config = load_existing_config(config_target)
        config["db_dir"] = os.fspath(db_dir)
    except WorkflowConfigError as exc:
        print(f"[!] {exc}")
        return 1

    print(f"[*] 已验证 {len(key_map)} 条数据库密钥记录（未显示任何密钥）")
    print("[*] 目标状态目录: ~/.wechat-cli")
    if not args.apply:
        print("[DRY-RUN] 未写入。确认后运行: python scripts/4_configure_wechat_cli.py --apply")
        return 0

    secure_directory(state_dir)
    secure_write_text(keys_target,
                      json.dumps(key_map, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    secure_write_text(config_target,
                      json.dumps(config, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    print("[OK] wechat-cli 本地状态已配置，两个文件均通过当前用户 DACL 复验")
    print("下一步: wechat-cli sessions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
