#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
② passphrase 提取: 对 ① 的转储字节做滑窗, 每个窗口作为 passphrase 候选,
   PBKDF2-HMAC-SHA512(cand, salt, 256000, 32) 派生后用第一页 HMAC 验证。

加速策略 (让 256000 轮暴力变得可行):
  - 单样本门控: 先只对一个数据库验证 (同一 passphrase 派生所有库), 命中即停
  - 8 字节步进滑窗 + 去重

用法: python 2_extract_passphrase.py
输出: secrets/passphrase.txt  (敏感! 勿外传)
耗时取决于转储量、CPU、候选去重效果与 WX_SCAN_STEP。
"""
import glob
import hashlib
import hmac
import json
import multiprocessing as mp
import os
import struct
import time

from win_dacl import secure_directory, secure_write_text
from workflow_common import (
    WorkflowConfigError,
    require_windows_x64,
    resolve_db_dir,
    resolve_secrets_dir,
)

# ═══════════════════ CONFIG ═══════════════════
DB_DIR = ""
DUMP_DIR = ""
OUT_FILE = ""
GATE_DB = "contact/contact.db"   # 门控样本 (任意常打开的小库均可)
# ═════════════════════════════════════════════

KEY_SIZE = 32
PAGE_SIZE = 4096
SALT_SIZE = 16
IV_SIZE = 16
HMAC_SIZE = 64
ROUNDS = 256000
RESERVE = IV_SIZE + HMAC_SIZE


def load_all_samples(db_dir):
    """收集 DB_DIR 下所有加密 .db 的第一页验证材料"""
    samples = []
    for root, dirs, files in os.walk(db_dir):
        dirs.sort()
        for name in sorted(files):
            if not name.casefold().endswith(".db"):
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
            rel = os.path.relpath(p, db_dir).replace("\\", "/")
            samples.append((rel, salt, mac_salt,
                            page[SALT_SIZE:de], page[de:de + HMAC_SIZE]))
    return samples


GATE = None   # (rel, salt, mac_salt, dseg, stored)


def _init(gate):
    global GATE
    GATE = gate


def verify_passphrase(cand, sample):
    """验证 passphrase 是否匹配一个数据库首页。"""
    _, salt, mac_salt, dseg, stored = sample
    enc = hashlib.pbkdf2_hmac('sha512', cand, salt, ROUNDS, dklen=KEY_SIZE)
    mk = hashlib.pbkdf2_hmac('sha512', enc, mac_salt, 2, dklen=KEY_SIZE)
    m = hmac.new(mk, digestmod=hashlib.sha512)
    m.update(dseg)
    m.update(struct.pack('<I', 1))
    return hmac.compare_digest(m.digest(), stored)


def check_passphrase(cand):
    """单候选 × 门控样本。返回 cand 或 None。
    注意: 返回候选本身而非索引 — imap_unordered 的完成顺序是任意的"""
    return cand if verify_passphrase(cand, GATE) else None


def main():
    global DB_DIR, DUMP_DIR, OUT_FILE
    try:
        require_windows_x64()
        DB_DIR = os.fspath(resolve_db_dir())
        secrets_dir = resolve_secrets_dir(create=True)
        secure_directory(secrets_dir)
        DUMP_DIR = os.fspath(secrets_dir / "ctx_dumps")
        secure_directory(DUMP_DIR)
        OUT_FILE = os.fspath(secrets_dir / "passphrase.txt")
    except (WorkflowConfigError, RuntimeError) as exc:
        print(f"[!] 环境未准备好: {exc}")
        print("    先运行: python scripts/0_preflight.py")
        return 2

    files = sorted(glob.glob(os.path.join(DUMP_DIR, "*.json")))
    if not files:
        print("[!] 敏感输出目录/ctx_dumps 无转储文件, 先运行 1_capture_launch.py")
        return 1
    print(f"[*] {len(files)} 个转储", flush=True)

    samples = load_all_samples(DB_DIR)
    if not samples:
        print("[!] WX_DB_DIR 未找到可用加密数据库")
        return 1
    gate_sample = next((s for s in samples if s[0] == GATE_DB), samples[0])
    gate = gate_sample
    print(f"[*] 门控样本: {gate_sample[0]}, 共 {len(samples)} 个库备全量确认", flush=True)

    # 全部转储区域字节 → 8 字节步进滑窗候选
    blobs = []
    skipped = 0
    for fn in files:
        try:
            with open(fn, encoding="utf-8") as f:
                d = json.load(f)
            if not isinstance(d.get("regions"), dict):
                raise TypeError("regions 不是对象")
            for hexdata in d["regions"].values():
                if not isinstance(hexdata, str):
                    raise TypeError("转储区域不是十六进制字符串")
                blobs.append(bytes.fromhex(hexdata))
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            skipped += 1
    if skipped:
        print(f"[WARN] 跳过 {skipped} 个损坏或格式不兼容的转储", flush=True)
    if not blobs:
        print("[!] 没有可用转储区域")
        return 1
    total = sum(len(b) for b in blobs)
    try:
        scan_step = int(os.environ.get("WX_SCAN_STEP", "8"))
    except ValueError:
        print("[!] WX_SCAN_STEP 必须是 1、2、4 或 8")
        return 2
    if scan_step not in (1, 2, 4, 8):
        print("[!] WX_SCAN_STEP 必须是 1、2、4 或 8")
        return 2
    cands = set()
    for b in blobs:
        for off in range(0, len(b) - KEY_SIZE + 1, scan_step):
            cands.add(b[off:off + KEY_SIZE])
    keys = sorted(cands)
    print(f"[*] {total / 1e6:.1f}MB → {len(keys)} 候选 (步{scan_step})", flush=True)

    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    # 输出文件限权 (仅当前用户可读)
    t0 = time.time()
    try:
        workers = int(os.environ.get("WX_WORKERS", str(min(mp.cpu_count(), 14))))
    except ValueError:
        print("[!] WX_WORKERS 必须是正整数")
        return 2
    if workers < 1:
        print("[!] WX_WORKERS 必须是正整数")
        return 2
    workers = min(workers, mp.cpu_count())
    with mp.Pool(workers, initializer=_init, initargs=(gate,)) as pool:
        for i, r in enumerate(pool.imap_unordered(check_passphrase, keys, chunksize=8)):
            if r:
                cand = r
                matched = sum(verify_passphrase(cand, sample) for sample in samples)
                if matched != len(samples):
                    print(f"[WARN] 门控命中但全量验证仅 {matched}/{len(samples)}，继续搜索", flush=True)
                    continue
                print(f"\n[✓✓✓] passphrase 命中并通过 {matched}/{len(samples)} 个数据库验证", flush=True)
                secure_write_text(OUT_FILE, f"passphrase:{cand.hex()}\n")
                pool.terminate()
                print("[*] 已保存敏感输出目录/passphrase.txt", flush=True)
                return 0
            if (i + 1) % 2000 == 0:
                el = time.time() - t0
                eta = el / (i + 1) * (len(keys) - i - 1)
                print(f"    {i + 1}/{len(keys)} ({el:.0f}s, ETA {eta / 60:.0f}min)", flush=True)
    print(f"[!] 未命中 ({(time.time() - t0) / 60:.0f}min) — 检查 BP_RVA 是否匹配当前微信版本", flush=True)
    if scan_step != 1:
        print("    若版本锚点已确认，可设置 WX_SCAN_STEP=1 后重试（候选约增至 8 倍）")
    return 3


if __name__ == "__main__":
    mp.freeze_support()
    raise SystemExit(main())
