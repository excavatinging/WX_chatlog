#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
③ 密钥派生: 用 ② 的 passphrase 对每个加密库派生 enc_key 并验证,
   输出 wechat-cli 兼容的 all_keys.json

用法: python 3_derive_keys.py   (从 secrets/passphrase.txt 读取)
输出: secrets/all_keys.json
"""
import hashlib
import hmac
import json
import os
import struct

from win_dacl import secure_directory, secure_write_text
from workflow_common import (
    WorkflowConfigError,
    require_windows_x64,
    resolve_db_dir,
    resolve_secrets_dir,
)

# ═══════════════════ CONFIG ═══════════════════
DB_DIR = ""
KEY_FILE = ""
OUT_FILE = ""
# ═════════════════════════════════════════════

PAGE_SIZE = 4096
SALT_SIZE = 16
IV_SIZE = 16
HMAC_SIZE = 64
ROUNDS = 256000
RESERVE = IV_SIZE + HMAC_SIZE


def verify(enc_key, page1):
    """SQLCipher 变体首页 HMAC 验证 (页号小端)"""
    salt = page1[:SALT_SIZE]
    mac_salt = bytes(b ^ 0x3a for b in salt)
    mk = hashlib.pbkdf2_hmac('sha512', enc_key, mac_salt, 2, dklen=32)
    de = PAGE_SIZE - RESERVE + IV_SIZE
    m = hmac.new(mk, digestmod=hashlib.sha512)
    m.update(page1[SALT_SIZE:de])
    m.update(struct.pack('<I', 1))
    return hmac.compare_digest(m.digest(), page1[de:de + HMAC_SIZE])


def derive_all(secret: bytes, db_dir: str):
    result = {}
    ok = fail = 0
    for root, dirs, files in os.walk(db_dir):
        dirs.sort()
        for name in sorted(files):
            if not name.casefold().endswith(".db"):
                continue
            p = os.path.join(root, name)
            try:
                with open(p, 'rb') as f:
                    page1 = f.read(PAGE_SIZE)
            except OSError:
                fail += 1
                print(f"  FAIL {os.path.relpath(p, db_dir).replace(os.sep, '/')} (无法读取)")
                continue
            if len(page1) < PAGE_SIZE or page1[:15] == b"SQLite format 3":
                continue
            rel = os.path.relpath(p, db_dir).replace("\\", "/")
            salt = page1[:SALT_SIZE]
            enc_key = hashlib.pbkdf2_hmac('sha512', secret, salt, ROUNDS, dklen=32)
            if verify(enc_key, page1):
                result[rel] = {
                    "enc_key": enc_key.hex(),
                    "salt": salt.hex(),
                    "size_mb": round(os.path.getsize(p) / 1048576, 1),
                }
                ok += 1
                print(f"  OK   {rel}")
            else:
                fail += 1
                print(f"  FAIL {rel}")
    return result, ok, fail


def load_passphrase(path: str) -> bytes:
    try:
        with open(path, encoding="ascii") as handle:
            raw = handle.read().strip()
    except OSError as exc:
        raise WorkflowConfigError("passphrase 文件无法读取") from exc
    if ":" in raw:
        kind, hexpart = raw.split(":", 1)
        if kind.strip() != "passphrase":
            raise WorkflowConfigError(
                "仅支持 4.1.8+ passphrase；旧版 enckey 不能生成完整的逐库密钥表")
    else:
        hexpart = raw
    try:
        secret = bytes.fromhex(hexpart.strip())
    except ValueError as exc:
        raise WorkflowConfigError("passphrase 文件不是有效十六进制格式") from exc
    if len(secret) != 32:
        raise WorkflowConfigError(f"passphrase 长度为 {len(secret)} 字节，预期 32 字节")
    return secret


def main():
    global DB_DIR, KEY_FILE, OUT_FILE
    try:
        require_windows_x64()
        DB_DIR = os.fspath(resolve_db_dir())
        secrets_dir = resolve_secrets_dir(create=True)
        secure_directory(secrets_dir)
        KEY_FILE = os.fspath(secrets_dir / "passphrase.txt")
        OUT_FILE = os.fspath(secrets_dir / "all_keys.json")
    except (WorkflowConfigError, RuntimeError) as exc:
        print(f"[!] 环境未准备好: {exc}")
        print("    先运行: python scripts/0_preflight.py")
        return 2

    # 隐私: 不再支持命令行传入密钥 (会进入 shell 历史); 只从文件读取
    if not os.path.exists(KEY_FILE):
        print("[!] 敏感输出目录/passphrase.txt 不存在\n    先运行 2_extract_passphrase.py")
        return 1
    try:
        secret = load_passphrase(KEY_FILE)
    except WorkflowConfigError as exc:
        print(f"[!] {exc}")
        return 1

    result, ok, fail = derive_all(secret, DB_DIR)
    print(f"\n{ok} OK / {fail} FAIL")
    if not result:
        print("[!] 全部失败 — passphrase 不正确或 WX_DB_DIR 配置错误")
        return 3
    if fail:
        print("[!] 存在未验证数据库，拒绝写出不完整 all_keys.json")
        return 4

    payload = json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    secure_write_text(OUT_FILE, payload)
    print("已写入敏感输出目录/all_keys.json")

    print("\n下一步 (可选，接入 wechat-cli):")
    print("  1. 按 README 的固定提交安装 wechat-cli")
    print("  2. python scripts/4_configure_wechat_cli.py  # 只预演")
    print("  3. python scripts/4_configure_wechat_cli.py --apply")
    print("  4. wechat-cli sessions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
