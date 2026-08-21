#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
kdf 锚点定位器: 在 Weixin.dll 中定位 SQLCipher kdf_iter setter 的 RVA。
微信版本升级、断点失效时用本工具重新定位, 更新 1_capture_launch.py 的 BP_RVA。

原理:
  PBKDF2 迭代次数 256000 (0x3E800) 会作为立即数出现在调用点:
      mov reg, 0x3E800
      call kdf_iter_setter
  setter 的特征是紧凑的"写上下文字段"函数:
      mov [rcx+N], edx/r8d    (把迭代次数存进 codec ctx)
      ... ret, 后接 int3 填充

用法: python find_kdf_anchor.py <Weixin.dll 路径>
      例: python find_kdf_anchor.py "C:\Program Files\Tencent\Weixin\4.1.12.26\Weixin.dll"

输出: 候选 setter 的 RVA 列表 + 反汇编片段 (人工确认后更新 BP_RVA)
依赖: pip install capstone
"""
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64


def parse_sections(data):
    e_lfanew = struct.unpack('<I', data[0x3c:0x40])[0]
    opt = e_lfanew + 24
    nsec = struct.unpack('<H', data[e_lfanew + 6:e_lfanew + 8])[0]
    secoff = opt + 240
    image_base = struct.unpack('<Q', data[opt + 24:opt + 32])[0]
    secs = []
    for i in range(nsec):
        s = secoff + i * 40
        name = data[s:s + 8].rstrip(b'\0').decode(errors='replace')
        vsize, va, rsize, raw = struct.unpack('<IIII', data[s + 8:s + 24])
        secs.append((name, va, vsize, raw, rsize))
    return image_base, secs


def rva2off(rva, secs):
    for name, va, vsize, raw, rsize in secs:
        if va <= rva < va + vsize:
            return raw + (rva - va)
    return None


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    path = sys.argv[1]
    data = open(path, 'rb').read()
    image_base, secs = parse_sections(data)
    text = next(s for s in secs if s[0] == '.text')
    _, TEXT_VA, TEXT_SZ, TEXT_RAW, _ = text
    print(f"[*] {path}")
    print(f"    ImageBase=0x{image_base:x}, .text va=0x{TEXT_VA:x} size={TEXT_SZ // 1048576}MB")

    # .text 内搜索 0x3E800 立即数
    needle = struct.pack('<I', 256000)
    hits = []
    i = TEXT_RAW
    end = TEXT_RAW + TEXT_SZ
    while True:
        i = data.find(needle, i, end)
        if i < 0:
            break
        hits.append(i)
        i += 1
    print(f"[*] 256000 (0x3E800) 命中: {len(hits)} 处")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    candidates = []
    for hv in hits:
        # 从不同起点回溯反汇编, 找 "mov reg, 0x3e800" 指令
        found = False
        for back in range(4, 40):
            s = hv - back
            if s < TEXT_RAW:
                continue
            rva = TEXT_VA + (s - TEXT_RAW)
            insns = list(md.disasm(data[s:hv + 40], image_base + rva))
            hit_va = image_base + TEXT_VA + (hv - TEXT_RAW)
            for idx, ins in enumerate(insns):
                if ins.address <= hit_va < ins.address + ins.size:
                    if ins.mnemonic == 'mov' and '0x3e800' in ins.op_str:
                        # 找后续的 call 目标
                        for j in range(idx + 1, min(idx + 5, len(insns))):
                            if insns[j].mnemonic == 'call':
                                target = int(insns[j].op_str, 16)
                                candidates.append((ins.address, insns[j].address, target))
                                found = True
                    break
            if found:
                break

    print(f"[*] 'mov reg, 0x3E800; call target' 调用点: {len(candidates)} 处\n")
    seen_targets = {}
    for mov_va, call_va, target in candidates:
        seen_targets.setdefault(target, []).append(mov_va)

    def score_setter(insns):
        """setter 特征评分 0-5, ≥4 为强疑似:
        ① 前 2 条内 mov [rcx+disp], reg (开头即写 codec ctx 字段)
        ② 12 条内出现 ret (紧凑函数)
        ③ ret 在前 6 条内 (极紧凑, 典型如 mov [rcx+4],edx; ret)
        ④ 前 12 条无 call (叶子函数, setter 不再调用别人)
        ⑤ ret 后紧跟 int3/对齐填充 (独立小函数的编译器特征)"""
        def writes_ctx(i):
            # capstone 的目的操作数形如 "dword ptr [rcx + 4]", 不能用 startswith('[rcx')
            if i.mnemonic != 'mov' or ',' not in i.op_str:
                return False
            dest = i.op_str.split(',', 1)[0].strip()
            return '[rcx' in dest and dest.endswith(']')
        score = 0
        if any(writes_ctx(i) for i in insns[:2]):
            score += 2
        ret_idx = next((k for k, i in enumerate(insns[:12]) if i.mnemonic == 'ret'), None)
        if ret_idx is not None:
            score += 1
            if ret_idx < 6:
                score += 1
            if ret_idx + 1 < len(insns) and insns[ret_idx + 1].mnemonic in ('int3', 'nop'):
                score += 0.5
        if not any(i.mnemonic == 'call' for i in insns[:12]):
            score += 1
        return score

    scored = []
    for target, call_sites in seen_targets.items():
        rva = target - image_base
        fo = rva2off(rva, secs)
        if fo is None:
            continue
        insns = list(md.disasm(data[fo:fo + 120], target))
        scored.append((score_setter(insns), target, rva, call_sites, insns))

    scored.sort(reverse=True, key=lambda t: t[0])
    for sc, target, rva, call_sites, insns in scored:
        mark = "  ← 强疑似 kdf_iter setter" if sc >= 4 else ""
        print(f"=== call target 0x{target:x}  RVA 0x{rva:x}  调用点 {len(call_sites)} 处  评分 {sc}{mark}")
        for k in insns[:10]:
            print(f"    {k.address:x}: {k.mnemonic} {k.op_str}")
        print()

    print("确认 setter 后, 将其 RVA 填入 1_capture_launch.py 的 BP_RVA,")
    print("并同步更新 EXPECTED_FN_BYTES 为该函数开头字节 (版本门禁用)。")
    if scored and scored[0][0] >= 4:
        print(f"\n[建议] 评分最高: RVA 0x{scored[0][2]:x} (评分 {scored[0][0]})")
    else:
        print("\n[!] 无强疑似候选 — 请人工核对反汇编")


if __name__ == "__main__":
    main()
