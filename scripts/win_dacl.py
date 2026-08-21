#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows DACL 工具: 把敏感产物文件限制为"仅当前用户可访问"。

背景: os.chmod(path, 0o600) 在 Windows 上只改只读位, 不影响 ACL —
同机其他账户仍可读取继承宽权限的密钥/转储文件。本模块用纯 ctypes
调用 advapi32 显式重写 DACL:
  - 撤销继承 (PROTECTED_DACL, 父目录的宽 ACL 不再生效)
  - 仅保留当前用户一条 ACCESS_ALLOWED_ACE (GENERIC_ALL)
  - 写后回读 GetNamedSecurityInfo 验证 AceCount == 1

用法 (①②③脚本的公共依赖):
    from win_dacl import restrict_to_current_user
    restrict_to_current_user(path)   # 失败抛 RuntimeError
"""
import ctypes
import ctypes.wintypes as wt
import os
import tempfile

advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# ── 常量 (winnt.h / aclapi.h) ──
FILE_ALL_ACCESS = 0x001F01FF
GRANT_ACCESS = 0x1
PROTECTED_DACL = 0x80000000
DACL_SECURITY_INFORMATION = 0x00000004
SE_FILE_OBJECT = 0x1
SE_DACL_PROTECTED = 0x1000

TRUSTEE_IS_SID = 0x0
TRUSTEE_IS_USER = 0x1
ACCESS_ALLOWED_ACE_TYPE = 0x0
ERROR_INSUFFICIENT_BUFFER = 122
SUB_CONTAINERS_AND_OBJECTS_INHERIT = 0x3

NO_ERROR = 0

# ── 当前用户 SID 获取 ──
def _current_user_sid_buf():
    """动态查询当前用户 SID；返回的缓冲由调用方持有。"""
    import getpass
    advapi32.LookupAccountNameW.argtypes = [wt.LPCWSTR, wt.LPCWSTR,
                                            ctypes.c_void_p, ctypes.POINTER(wt.DWORD),
                                            wt.LPWSTR, ctypes.POINTER(wt.DWORD),
                                            ctypes.POINTER(wt.DWORD)]
    advapi32.LookupAccountNameW.restype = wt.BOOL

    sidlen = wt.DWORD(0)
    domlen = wt.DWORD(0)
    nameuse = wt.DWORD()
    ctypes.set_last_error(0)
    advapi32.LookupAccountNameW(None, getpass.getuser(), None, ctypes.byref(sidlen),
                                None, ctypes.byref(domlen), ctypes.byref(nameuse))
    err = ctypes.get_last_error()
    if err != ERROR_INSUFFICIENT_BUFFER or not sidlen.value:
        raise RuntimeError(f"LookupAccountNameW 尺寸查询失败 err={err}")

    sidbuf = ctypes.create_string_buffer(sidlen.value)
    domain = ctypes.create_unicode_buffer(max(domlen.value, 1))
    ok = advapi32.LookupAccountNameW(None, getpass.getuser(), sidbuf, ctypes.byref(sidlen),
                                     domain, ctypes.byref(domlen), ctypes.byref(nameuse))
    if not ok:
        raise RuntimeError(f"LookupAccountNameW 失败 err={ctypes.get_last_error()}")
    return sidbuf


class TRUSTEE_W(ctypes.Structure):
    """TRUSTEE_W (accctrl.h)。ptstrName 是多态指针:
    TrusteeForm=TRUSTEE_IS_NAME 时为 LPCWSTR, =TRUSTEE_IS_SID 时为 PSID。
    ctypes 对 LPWSTR 字段赋非字符串会触发自动转换导致堆损坏, 故声明 c_void_p。"""
    _fields_ = [("pMultipleTrustee", ctypes.c_void_p),
                ("MultipleTrusteeOperation", ctypes.c_int),
                ("TrusteeForm", ctypes.c_int),
                ("TrusteeType", ctypes.c_int),
                ("ptstrName", ctypes.c_void_p)]


class EXPLICIT_ACCESS_W(ctypes.Structure):
    _fields_ = [("grfAccessPermissions", wt.DWORD),
                ("grfAccessMode", ctypes.c_int),
                ("grfInheritance", wt.DWORD),
                ("Trustee", TRUSTEE_W)]


class ACL(ctypes.Structure):
    _fields_ = [("AclRevision", ctypes.c_uint8),
                ("Sbz1", ctypes.c_uint8),
                ("AclSize", wt.WORD),
                ("AceCount", wt.WORD),
                ("Sbz2", wt.WORD)]


class ACE_HEADER(ctypes.Structure):
    _fields_ = [("AceType", ctypes.c_ubyte),
                ("AceFlags", ctypes.c_ubyte),
                ("AceSize", wt.WORD)]


class ACCESS_ALLOWED_ACE(ctypes.Structure):
    _fields_ = [("Header", ACE_HEADER),
                ("Mask", wt.DWORD),
                ("SidStart", wt.DWORD)]


# ── API 签名 ──
advapi32.SetEntriesInAclW.argtypes = [wt.ULONG, ctypes.POINTER(EXPLICIT_ACCESS_W),
                                      ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
advapi32.SetEntriesInAclW.restype = wt.DWORD
advapi32.SetNamedSecurityInfoW.argtypes = [wt.LPWSTR, ctypes.c_int, wt.DWORD,
                                           ctypes.c_void_p, ctypes.c_void_p,
                                           ctypes.c_void_p, ctypes.c_void_p]
advapi32.SetNamedSecurityInfoW.restype = wt.DWORD
advapi32.GetNamedSecurityInfoW.argtypes = [wt.LPWSTR, ctypes.c_int, wt.DWORD,
                                           ctypes.POINTER(ctypes.c_void_p),
                                           ctypes.POINTER(ctypes.c_void_p),
                                           ctypes.POINTER(ctypes.c_void_p),
                                           ctypes.POINTER(ctypes.c_void_p),
                                           ctypes.POINTER(ctypes.c_void_p)]
advapi32.GetNamedSecurityInfoW.restype = wt.DWORD
advapi32.GetAce.argtypes = [ctypes.c_void_p, wt.DWORD,
                            ctypes.POINTER(ctypes.c_void_p)]
advapi32.GetAce.restype = wt.BOOL
advapi32.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
advapi32.EqualSid.restype = wt.BOOL
advapi32.GetSecurityDescriptorControl.argtypes = [ctypes.c_void_p,
                                                   ctypes.POINTER(wt.WORD),
                                                   ctypes.POINTER(wt.DWORD)]
advapi32.GetSecurityDescriptorControl.restype = wt.BOOL
kernel32.LocalFree.argtypes = [ctypes.c_void_p]
kernel32.LocalFree.restype = ctypes.c_void_p


def _free(handle):
    if handle:
        kernel32.LocalFree(handle)


def restrict_to_current_user(path: str) -> None:
    """重写文件 DACL: 仅当前用户完全控制, 不继承父目录。
    成功静默; 失败抛 RuntimeError (调用方决定是否容忍)。"""
    path = os.path.abspath(os.fspath(path))
    sid_buf = _current_user_sid_buf()
    psid = ctypes.cast(sid_buf, ctypes.c_void_p)   # PSID 指向 sid_buf 内部; sid_buf 持有引用

    ea = EXPLICIT_ACCESS_W()
    ea.grfAccessPermissions = FILE_ALL_ACCESS
    ea.grfAccessMode = GRANT_ACCESS
    # 目录的唯一 ACE 需要向现有/后续子项传播，否则阻断父目录继承后，
    # 原本只靠继承访问的转储文件会变成当前用户也无法读取。
    ea.grfInheritance = (
        SUB_CONTAINERS_AND_OBJECTS_INHERIT if os.path.isdir(path) else 0
    )
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID
    ea.Trustee.TrusteeType = TRUSTEE_IS_USER
    ea.Trustee.ptstrName = psid

    pacl = ctypes.c_void_p()
    rc = advapi32.SetEntriesInAclW(1, ctypes.byref(ea), None, ctypes.byref(pacl))
    if rc != NO_ERROR or not pacl.value:
        raise RuntimeError(f"SetEntriesInAclW 失败 rc={rc}")
    try:
        # PROTECTED_DACL: 阻断继承, 父目录的宽 ACE 不再合并进来
        rc = advapi32.SetNamedSecurityInfoW(path, SE_FILE_OBJECT,
                                            DACL_SECURITY_INFORMATION | PROTECTED_DACL,
                                            None, None, pacl, None)
        if rc != NO_ERROR:
            raise RuntimeError(f"SetNamedSecurityInfoW 失败 rc={rc}")

        # GetNamedSecurityInfo 返回的 owner/DACL 都指向同一个安全描述符缓冲。
        # 只能 LocalFree 最后的 security descriptor，不能分别释放内部指针。
        pdacl_v = ctypes.c_void_p()
        psd = ctypes.c_void_p()
        rc = advapi32.GetNamedSecurityInfoW(path, SE_FILE_OBJECT,
                                            DACL_SECURITY_INFORMATION,
                                            None, None, ctypes.byref(pdacl_v), None,
                                            ctypes.byref(psd))
        if rc != NO_ERROR or not pdacl_v.value or not psd.value:
            _free(psd.value)
            raise RuntimeError(f"回读 DACL 失败 rc={rc}")
        try:
            acl = ctypes.cast(pdacl_v, ctypes.POINTER(ACL)).contents
            if acl.AceCount != 1:
                raise RuntimeError(f"DACL 验证失败: AceCount={acl.AceCount} (预期 1)")

            pace = ctypes.c_void_p()
            if not advapi32.GetAce(pdacl_v, 0, ctypes.byref(pace)) or not pace.value:
                raise RuntimeError(f"DACL 验证失败: GetAce err={ctypes.get_last_error()}")
            ace = ctypes.cast(pace, ctypes.POINTER(ACCESS_ALLOWED_ACE)).contents
            if ace.Header.AceType != ACCESS_ALLOWED_ACE_TYPE:
                raise RuntimeError(f"DACL 验证失败: AceType={ace.Header.AceType}")
            expected_inheritance = (
                SUB_CONTAINERS_AND_OBJECTS_INHERIT if os.path.isdir(path) else 0
            )
            if (ace.Header.AceFlags & SUB_CONTAINERS_AND_OBJECTS_INHERIT
                    != expected_inheritance):
                raise RuntimeError(
                    f"DACL 验证失败: AceFlags=0x{ace.Header.AceFlags:02x}"
                )
            if (ace.Mask & FILE_ALL_ACCESS) != FILE_ALL_ACCESS:
                raise RuntimeError(f"DACL 验证失败: access mask=0x{ace.Mask:08x}")
            ace_sid = ctypes.c_void_p(pace.value + ACCESS_ALLOWED_ACE.SidStart.offset)
            if not advapi32.EqualSid(ace_sid, psid):
                raise RuntimeError("DACL 验证失败: ACE 不属于当前用户")

            control = wt.WORD()
            revision = wt.DWORD()
            if not advapi32.GetSecurityDescriptorControl(
                    psd, ctypes.byref(control), ctypes.byref(revision)):
                raise RuntimeError(
                    f"DACL 验证失败: GetSecurityDescriptorControl err={ctypes.get_last_error()}")
            if not (control.value & SE_DACL_PROTECTED):
                raise RuntimeError("DACL 验证失败: DACL 仍在继承父目录权限")
        finally:
            _free(psd.value)
    finally:
        _free(pacl.value)


def protect_file(path: str, *, strict: bool = True) -> None:
    """敏感文件落盘后的标准动作: DACL 限制 + 失败处理。
    strict=True: DACL 失败直接抛异常 (调用方终止);
    strict=False: 打印警告后继续 (旧 chmod 行为的对等替代)。"""
    try:
        restrict_to_current_user(path)
    except RuntimeError as e:
        msg = f"[!] DACL 保护失败 ({os.path.basename(path)}): {e}"
        if strict:
            raise RuntimeError(msg)
        print(msg + " — 文件权限可能过宽, 请手动检查", flush=True)


def secure_directory(path: str) -> None:
    """创建目录（如需要）并把目录本身限制为仅当前用户可访问。"""
    path = os.path.abspath(os.fspath(path))
    os.makedirs(path, exist_ok=True)
    if not os.path.isdir(path):
        raise RuntimeError("敏感输出路径不是目录")
    restrict_to_current_user(path)


def secure_write_bytes(path: str, data: bytes) -> None:
    """先保护空临时文件，再写敏感内容，最后同目录原子替换并复验。"""
    path = os.path.abspath(os.fspath(path))
    parent = os.path.dirname(path)
    os.makedirs(parent, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.",
                                     suffix=".tmp", dir=parent)
    os.close(fd)
    replaced = False
    try:
        # 此时文件为空；DACL 失败不会留下任何敏感字节。
        restrict_to_current_user(temp_path)
        with open(temp_path, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        restrict_to_current_user(temp_path)
        os.replace(temp_path, path)
        replaced = True
        restrict_to_current_user(path)
    finally:
        if not replaced and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


def secure_write_text(path: str, text: str, *, encoding: str = "utf-8") -> None:
    secure_write_bytes(path, text.encode(encoding))


if __name__ == "__main__":
    # 自检: 建临时文件 → 加固 → 验证 → 删除
    with tempfile.TemporaryDirectory(prefix="wx-chatlog-dacl-") as temp_dir:
        p = os.path.join(temp_dir, "dacl_selftest.txt")
        secure_write_text(p, "x")
        with open(p, encoding="utf-8") as handle:
            content = handle.read()
        if content != "x":
            raise RuntimeError("DACL 自检失败: 内容回读不一致")
        print("[OK] DACL 自检通过 (仅当前用户一条 ACE, DACL 已阻断继承)")
