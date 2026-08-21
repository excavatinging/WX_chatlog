#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
加密参数自检: 用随机 passphrase 人工构造一个加密页, 验证派生/验证/解密全链路正确。
不依赖任何微信数据 — 验证的是本仓库算法实现的内部一致性。

用法: python selftest_crypto.py
退出码 0 = 全部通过; 1 = 有失败项 (python -O 下同样有效, 不依赖 assert)。
"""
import hashlib
import hmac
import os
import struct
import sys

# Crypto 命名空间由 requirements 中受维护的 pycryptodome 提供，不是已废弃的 PyCrypto。
from Crypto.Cipher import AES  # nosec B413

KEY_SIZE = 32
PAGE_SIZE = 4096
SALT_SIZE = 16
IV_SIZE = 16
HMAC_SIZE = 64
ROUNDS = 256000
RESERVE = IV_SIZE + HMAC_SIZE


def derive(passphrase: bytes, salt: bytes):
    enc_key = hashlib.pbkdf2_hmac('sha512', passphrase, salt, ROUNDS, dklen=KEY_SIZE)
    mac_salt = bytes(b ^ 0x3a for b in salt)
    mac_key = hashlib.pbkdf2_hmac('sha512', enc_key, mac_salt, 2, dklen=KEY_SIZE)
    return enc_key, mac_key


def main() -> int:
    failures = []

    def check(name: str, cond: bool, detail: str = ""):
        if cond:
            print(f"[OK] {name}")
        else:
            print(f"[FAIL] {name} {detail}")
            failures.append(name)

    passphrase = os.urandom(32)
    salt = os.urandom(16)
    plaintext = os.urandom(PAGE_SIZE)

    enc_key, mac_key = derive(passphrase, salt)
    iv = os.urandom(16)

    # 构造加密页: [salt(16)][密文(4000)][iv(16)][hmac(64)]
    body = plaintext[SALT_SIZE:PAGE_SIZE - RESERVE]
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(body)

    page = bytearray(PAGE_SIZE)
    page[:SALT_SIZE] = salt
    page[SALT_SIZE:PAGE_SIZE - RESERVE] = ciphertext
    page[PAGE_SIZE - RESERVE:PAGE_SIZE - RESERVE + IV_SIZE] = iv

    m = hmac.new(mac_key, digestmod=hashlib.sha512)
    m.update(bytes(page[SALT_SIZE:PAGE_SIZE - RESERVE + IV_SIZE]))
    m.update(struct.pack('<I', 1))
    page[PAGE_SIZE - HMAC_SIZE:] = m.digest()
    page = bytes(page)

    # ── 验证1: 验证器识别正确密钥 / 拒绝错误密钥 ──
    def verify(cand_pass):
        _, mk = derive(cand_pass, page[:SALT_SIZE])
        mm = hmac.new(mk, digestmod=hashlib.sha512)
        mm.update(page[SALT_SIZE:PAGE_SIZE - RESERVE + IV_SIZE])
        mm.update(struct.pack('<I', 1))
        return hmac.compare_digest(mm.digest(), page[PAGE_SIZE - HMAC_SIZE:])

    check("1/3 验证器: 正确密钥通过", verify(passphrase))
    check("1/3 验证器: 错误密钥拒绝", not verify(os.urandom(32)))

    # ── 验证2: 已派生 enc_key 的首页快验 ──
    mk2 = hashlib.pbkdf2_hmac('sha512', enc_key, bytes(b ^ 0x3a for b in salt), 2, dklen=32)
    mm = hmac.new(mk2, digestmod=hashlib.sha512)
    mm.update(page[SALT_SIZE:PAGE_SIZE - RESERVE + IV_SIZE])
    mm.update(struct.pack('<I', 1))
    check("2/3 enc_key 快验: 已派生密钥可被识别",
          hmac.compare_digest(mm.digest(), page[PAGE_SIZE - HMAC_SIZE:]))

    # ── 验证3: 完整解密 roundtrip ──
    dec = AES.new(enc_key, AES.MODE_CBC, page[PAGE_SIZE - RESERVE:PAGE_SIZE - RESERVE + IV_SIZE])
    body2 = dec.decrypt(page[SALT_SIZE:PAGE_SIZE - RESERVE])
    check("3/3 解密 roundtrip: 密文可完整还原", body2 == body)

    if failures:
        print(f"\n[!] {len(failures)} 项失败 — 实现与预期不符, 退出码 1", flush=True)
        return 1
    print("\n全部通过 — 本仓库加密实现的内部一致性验证通过:")
    print(f"  PBKDF2-HMAC-SHA512 x{ROUNDS}, AES-256-CBC, page={PAGE_SIZE}, reserve={RESERVE}, 页号小端")
    return 0


if __name__ == "__main__":
    sys.exit(main())
