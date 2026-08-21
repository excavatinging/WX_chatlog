#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
② passphrase 提取: 对 ① 的转储字节做滑窗, 每个窗口作为 passphrase 候选,
   PBKDF2-HMAC-SHA512(cand, salt, 256000, 32) 派生后用第一页 HMAC 验证。

加速策略 (让 256000 轮暴力变得可行):
  - 单样本门控: 先只对一个数据库验证 (同一 passphrase 派生所有库), 命中即停
  - 同时快验 Way B (候选=已派生 enc_key, 仅 2 轮, 兼容 4.0 遗留形态)
  - 8 字节步进滑窗 + 去重

用法: python 2_extract_passphrase.py
输出: secrets/passphrase.txt  (敏感! 勿外传)
实测: ~5MB 转储 ≈ 6.7 万候选 ≈ 45 分钟 (14 核)
"""
import glob
import hashlib
import hmac
import json
import multiprocessing as mp
import os
import struct
import sys
import time

# ═══════════════════ CONFIG ═══════════════════
DB_DIR   = os.environ.get("WX_DB_DIR", r"D:\xwechat_files\<你的wxid目录>\db_storage")
DUMP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "secrets", "ctx_dumps")
OUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "secrets", "passphrase.txt")
GATE_DB  = r"contact\contact.db"   # 门控样本 (任意常打开的小库均可)
# ═════════════════════════════════════════════

KEY_SIZE = 32
PAGE_SIZE = 4096
SALT_SIZE = 16
IV_SIZE = 16
HMAC_SIZE = 64
ROUNDS = 256000
RESERVE = IV_SIZE + HMAC_SIZE


def load_all_samples():
    """收集 DB_DIR 下所有加密 .db 的第一页验证材料"""
    samples = []
    for root, dirs, files in os.walk(DB_DIR):
        for name in files:
            if not name.endswith(".db"):
                continue
            p = os.path.join(root, name)
            try:
                with open(p, 'rb') as f:
                    page = f.read(PAGE_SIZE)
            except OSError:
                continue
            if len(page) < PAGE_SIZE or page[:15] == b"SQLite format 3":
                continue
            salt = page[:SALT_SIZE]
            mac_salt = bytes(b ^ 0x3a for b in salt)
            de = PAGE_SIZE - RESERVE + IV_SIZE
            samples.append((os.path.relpath(p, DB_DIR), salt, mac_salt,
                            page[SALT_SIZE:de], page[de:de + HMAC_SIZE]))
    return samples


GATE = None   # (salt, mac_salt, dseg, stored)


def _init(gate):
    global GATE
    GATE = gate


def check_passphrase(cand):
    """单候选 × 门控样本。返回 (cand, is_passphrase, fmt) 或 None
    注意: 返回候选本身而非索引 — imap_unordered 的完成顺序是任意的"""
    salt, mac_salt, dseg, stored = GATE
    # Way A: cand 是 passphrase → 完整派生 (256000 轮)
    enc = hashlib.pbkdf2_hmac('sha512', cand, salt, ROUNDS, dklen=KEY_SIZE)
    mk = hashlib.pbkdf2_hmac('sha512', enc, mac_salt, 2, dklen=KEY_SIZE)
    for fmt in ('<I', '>I'):
        m = hmac.new(mk, digestmod=hashlib.sha512)
        m.update(dseg)
        m.update(struct.pack(fmt, 1))
        if hmac.compare_digest(m.digest(), stored):
            return (cand, True, fmt)
    # Way B: cand 本身就是已派生 enc_key (4.0 形态, 顺手兼容)
    mk2 = hashlib.pbkdf2_hmac('sha512', cand, mac_salt, 2, dklen=KEY_SIZE)
    for fmt in ('<I', '>I'):
        m = hmac.new(mk2, digestmod=hashlib.sha512)
        m.update(dseg)
        m.update(struct.pack(fmt, 1))
        if hmac.compare_digest(m.digest(), stored):
            return (cand, False, fmt)
    return None


def main():
    files = sorted(glob.glob(os.path.join(DUMP_DIR, "*.json")))
    if not files:
        print(f"[!] {DUMP_DIR} 无转储文件, 先运行 1_capture_launch.py")
        sys.exit(1)
    print(f"[*] {len(files)} 个转储", flush=True)

    samples = load_all_samples()
    if not samples:
        print(f"[!] {DB_DIR} 未找到加密数据库, 检查 CONFIG")
        sys.exit(1)
    gate_sample = next((s for s in samples if s[0] == GATE_DB), samples[0])
    gate = (gate_sample[1], gate_sample[2], gate_sample[3], gate_sample[4])
    print(f"[*] 门控样本: {gate_sample[0]}, 共 {len(samples)} 个库备全量确认", flush=True)

    # 全部转储区域字节 → 8 字节步进滑窗候选
    blobs = []
    for fn in files:
        try:
            with open(fn) as f:
                d = json.load(f)
            for addr_hex, hexdata in d["regions"].items():
                blobs.append(bytes.fromhex(hexdata))
        except Exception:
            continue
    total = sum(len(b) for b in blobs)
    cands = set()
    for b in blobs:
        for off in range(0, len(b) - KEY_SIZE + 1, 8):
            cands.add(b[off:off + KEY_SIZE])
    keys = list(cands)
    print(f"[*] {total / 1e6:.1f}MB → {len(keys)} 候选 (步8)", flush=True)

    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    # 输出文件限权 (仅当前用户可读)
    t0 = time.time()
    with mp.Pool(min(mp.cpu_count(), 14), initializer=_init, initargs=(gate,)) as pool:
        for i, r in enumerate(pool.imap_unordered(check_passphrase, keys, chunksize=8)):
            if r:
                cand, is_pass, fmt = r
                kind = "passphrase" if is_pass else "enckey"
                # 隐私: 不回显完整密钥, 只显示前 8 hex 供人工核对
                print(f"\n[✓✓✓] 命中! 类型={kind} 字节序={fmt} key={cand[:4].hex()}...", flush=True)
                with open(OUT_FILE, "w") as f:
                    f.write(f"{kind}:{cand.hex()}\n")
                try:
                    os.chmod(OUT_FILE, 0o600)
                except OSError:
                    pass
                pool.terminate()
                print(f"[*] 已保存 {OUT_FILE}", flush=True)
                return
            if (i + 1) % 2000 == 0:
                el = time.time() - t0
                eta = el / (i + 1) * (len(keys) - i - 1)
                print(f"    {i + 1}/{len(keys)} ({el:.0f}s, ETA {eta / 60:.0f}min)", flush=True)
    print(f"[!] 未命中 ({(time.time() - t0) / 60:.0f}min) — 检查 BP_RVA 是否匹配当前微信版本", flush=True)
    sys.exit(2)


if __name__ == "__main__":
    main()
