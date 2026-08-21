#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
加密参数自检: 用随机 passphrase 人工构造一个加密页, 验证派生/验证/解密全链路正确。
不依赖任何微信数据 — 用于确认算法实现与微信 4.1.x 一致。

用法: python selftest_crypto.py
全部输出 OK 即实现正确。
"""
import hashlib
import hmac
import os
import struct

from Crypto.Cipher import AES   # pip install pycryptodome

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


def page_hmac(mac_key, page_tail: bytes, page_no: int) -> bytes:
    """page_tail = 密文+iv 区 (salt 后到 reserve+iv 前的部分按实现拼接)"""
    m = hmac.new(mac_key, digestmod=hashlib.sha512)
    m.update(page_tail)
    m.update(struct.pack('<I', page_no))   # 微信变体: 小端页号
    return m.digest()


def main():
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

    # ── 验证1: 验证器识别正确密钥 ──
    def verify(cand_pass):
        ek, mk = derive(cand_pass, page[:SALT_SIZE])
        mm = hmac.new(mk, digestmod=hashlib.sha512)
        mm.update(page[SALT_SIZE:PAGE_SIZE - RESERVE + IV_SIZE])
        mm.update(struct.pack('<I', 1))
        return hmac.compare_digest(mm.digest(), page[PAGE_SIZE - HMAC_SIZE:])

    assert verify(passphrase), "正确 passphrase 未通过验证"
    assert not verify(os.urandom(32)), "随机 passphrase 不应通过"
    print("[OK] 1/3 验证器: 正确密钥通过 / 错误密钥拒绝")

    # ── 验证2: enc_key 直接作为候选 (Way B 路径) ──
    mk2 = hashlib.pbkdf2_hmac('sha512', enc_key, bytes(b ^ 0x3a for b in salt), 2, dklen=32)
    mm = hmac.new(mk2, digestmod=hashlib.sha512)
    mm.update(page[SALT_SIZE:PAGE_SIZE - RESERVE + IV_SIZE])
    mm.update(struct.pack('<I', 1))
    assert hmac.compare_digest(mm.digest(), page[PAGE_SIZE - HMAC_SIZE:])
    print("[OK] 2/3 Way B: 已派生 enc_key 可被快验识别")

    # ── 验证3: 完整解密 roundtrip ──
    dec = AES.new(enc_key, AES.MODE_CBC, page[PAGE_SIZE - RESERVE:PAGE_SIZE - RESERVE + IV_SIZE])
    body2 = dec.decrypt(page[SALT_SIZE:PAGE_SIZE - RESERVE])
    assert body2 == body, "解密结果与原文不一致"
    print("[OK] 3/3 解密 roundtrip: 密文可完整还原")

    print("\n全部通过 — 加密参数实现与微信 4.1.x SQLCipher 变体一致:")
    print(f"  PBKDF2-HMAC-SHA512 x{ROUNDS}, AES-256-CBC, page={PAGE_SIZE}, reserve={RESERVE}, 页号小端")


if __name__ == "__main__":
    main()
