#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
③ 密钥派生: 用 ② 的 passphrase 对每个加密库派生 enc_key 并验证,
   输出 wechat-cli 兼容的 all_keys.json (可直接放入 ~/.wechat-cli/)

用法: python 3_derive_keys.py [passphrase_hex]
      (无参数时从 secrets/passphrase.txt 读取)
输出: secrets/all_keys.json
"""
import hashlib
import hmac
import json
import os
import struct
import sys

# ═══════════════════ CONFIG ═══════════════════
DB_DIR   = os.environ.get("WX_DB_DIR", r"D:\xwechat_files\<你的wxid目录>\db_storage")
BASE     = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(BASE, "..", "secrets", "passphrase.txt")
OUT_FILE = os.path.join(BASE, "..", "secrets", "all_keys.json")
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


def derive_all(secret: bytes, is_passphrase: bool):
    result = {}
    ok = fail = 0
    for root, dirs, files in os.walk(DB_DIR):
        for name in files:
            if not name.endswith(".db"):
                continue
            p = os.path.join(root, name)
            try:
                with open(p, 'rb') as f:
                    page1 = f.read(PAGE_SIZE)
            except OSError:
                continue
            if len(page1) < PAGE_SIZE or page1[:15] == b"SQLite format 3":
                continue
            rel = os.path.relpath(p, DB_DIR)
            salt = page1[:SALT_SIZE]
            if is_passphrase:
                # Way A: passphrase → 逐库派生
                enc_key = hashlib.pbkdf2_hmac('sha512', secret, salt, ROUNDS, dklen=32)
            else:
                # Way B: secret 本身就是 enc_key (4.0 形态), 不再二次派生
                enc_key = secret
            if verify(enc_key, page1):
                result[rel] = {
                    "enc_key": enc_key.hex(),
                    "salt": salt.hex(),
                    "size_mb": round(os.path.getsize(p) / 1048576, 1),
                }
                ok += 1
                print(f"  OK   {rel}  key={enc_key.hex()[:8]}...")
            else:
                fail += 1
                print(f"  FAIL {rel}")
    return result, ok, fail


def main():
    # 隐私: 不再支持命令行传入密钥 (会进入 shell 历史); 只从文件读取
    if not os.path.exists(KEY_FILE):
        sys.exit(f"密钥文件不存在: {KEY_FILE}\n先运行 2_extract_passphrase.py")
    raw = open(KEY_FILE).read().strip()
    # ② 输出格式: "kind:hex" (kind ∈ passphrase|enckey); 兼容裸 hex (视为 passphrase)
    if ":" in raw:
        kind, hexpart = raw.split(":", 1)
        secret = bytes.fromhex(hexpart.strip())
        is_passphrase = (kind.strip() == "passphrase")
    else:
        secret = bytes.fromhex(raw)
        is_passphrase = True

    result, ok, fail = derive_all(secret, is_passphrase)
    print(f"\n{ok} OK / {fail} FAIL")
    if not result:
        sys.exit("[!] 全部失败 — 密钥不正确或 DB_DIR 配置错误")

    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    try:
        os.chmod(OUT_FILE, 0o600)
    except OSError:
        pass
    print(f"已写入 {OUT_FILE}")

    print(f"""
下一步 (接入 wechat-cli):
  1. pip install -e <wechat-cli 源码路径>
  2. mkdir %USERPROFILE%\\.wechat-cli  (已存在则跳过)
  3. 复制 {OUT_FILE} → %USERPROFILE%\\.wechat-cli\\all_keys.json
  4. 写入 %USERPROFILE%\\.wechat-cli\\config.json:
     {{"db_dir": "{DB_DIR}"}}
  5. wechat-cli sessions / history "联系人备注" / export ...
""")


if __name__ == "__main__":
    main()
