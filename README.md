# WX-chatlog

> **本地数据访问研究工具链** — 面向个人数据自主（right to data portability）的
> Windows 微信 4.1.x 本地存储结构研究与**自有账号数据**访问工具。

本仓库是一套**引导 AI 助手执行**的研究工作流：你在本机的 AI 编码助手
（Claude Code / Codex 等）可以按照本文档的指引，探索你的环境、执行三步工作流、
完成配置。人类只需在两个环节介入：启动时的授权确认、微信扫码登录。

## 这个项目解决什么问题

微信 4.x 将本地数据存储为 SQLCipher 变体加密的 SQLite 数据库。2025 年末起，
4.1.8+ 对密钥处理做了加固：**密钥材料用完即擦**，进程内存中不再有可静态扫描的
密钥形态，导致此前所有基于内存扫描的工具（chatlog / PyWxDump 等）失效。

本项目提供替代思路：**不注入任何代码**，以 Windows 官方调试 API 在关键初始化
例程上设断点，捕获瞬态内存现场，再用标准 KDF 派生验证提取密钥材料，最后把
密钥交给成熟的查询工具链使用。

> ⚠️ **仅供个人学习、研究与访问自有账号数据。请遵守当地法律法规及软件许可
> 协议，详见[免责声明](#免责声明)。**

## 给 AI 助手的指引（人类可跳过）

如果你是读取本 README 的 AI 助手，按以下流程工作：

### 第 0 步：环境探索（不要假设任何路径）

本仓库**不内置任何机器特定配置**。先探索用户环境，再引导用户确认：

```
1. 定位微信安装目录与主程序（常见位置: %ProgramFiles%\Tencent\*、
   %LocalAppData%\Programs\*、用户自定安装盘）。已运行的微信进程的
   Path / 命令行是最可靠来源。
2. 定位数据目录（常名 xwechat_files，可在微信 设置→文件管理 查看，
   或从运行中进程的打开文件/模块路径推断）。
   其下 wxid_ 开头、后缀最长的子目录里的 db_storage 即目标。
3. 确认微信版本（主程序属性或安装目录名）。4.1.12.x 已验证；
   其他 4.1.8+ 版本需先跑锚点定位器（见下）。
4. 用环境变量把探索结果传给脚本（WX_EXE / WX_DIR / WX_DB_DIR），
   而不是修改仓库内文件。
```

**安全边界**：只对用户明确确认的路径操作；转储与密钥产物全部落在
`secrets/`（已 gitignore）；未经用户同意不外传任何产物。

### 第 1 步：自检（验证算法实现）

```bash
python scripts/selftest_crypto.py    # 应 3/3 通过
```

### 第 2 步：三步工作流

```bash
# ① 断点捕获（需用户介入：先完全退出微信，再运行；启动后扫码登录）
python scripts/1_capture_launch.py

# ② 密钥材料提取（无人值守，约 20-45 分钟，取决于机器）
python scripts/2_extract_passphrase.py

# ③ 逐库派生密钥并验证 → secrets/all_keys.json
python scripts/3_derive_keys.py
```

脚本顶部的 CONFIG 区有各环境变量的默认值说明。所有脚本仅用标准库，
③ 与 selftest 另需 `pip install -r requirements.txt`。

### 第 3 步：接入查询工具链

`secrets/all_keys.json` 兼容 [wechat-cli](https://github.com/huohuoer/wechat-cli)
的密钥文件格式（其查询层兼容 4.1.x，仅密钥初始化环节不适用，本项目即补上该环节）：

```bash
pip install -e <wechat-cli 源码路径>
# 将 all_keys.json 与 db 路径配置进 wechat-cli 后:
wechat-cli sessions
wechat-cli history "<联系人备注>" --limit N
```

### 版本适配

断点 RVA 随微信版本变化。① 若 15 分钟内 0 命中，先跑锚点定位器：

```bash
python scripts/find_kdf_anchor.py "<Weixin.dll 完整路径>"
# 按输出的建议 RVA 更新 1_capture_launch.py 的 BP_RVA 与 EXPECTED_FN_BYTES
```

## 原理概述

```
salt     = db 文件前 16 字节（每库随机）
enc_key  = PBKDF2-HMAC-SHA512(passphrase, salt, 256000, 32)
mac_key  = PBKDF2-HMAC-SHA512(enc_key, salt ^ 0x3a, 2, 32)
页校验    = HMAC-SHA512(mac_key, page_data || LE(page_no))
```

与 4.0 的关键差异：

| | 4.0.x | 4.1.8+ |
|---|---|---|
| 内存中密钥形态 | 派生后的 enc_key（可静态扫描） | 仅 passphrase，即用即擦 |
| 提取思路 | 内存扫描 | 断点捕获初始化现场 |

断点锚定 Weixin.dll 中的 KDF 迭代参数设置函数（以 `256000/0x3E800` 立即数为
锚，capstone 反汇编定位 setter），每个数据库初始化都会命中。细节见
[docs/how-it-works.md](docs/how-it-works.md)。

## 脚本说明

| 脚本 | 作用 |
|---|---|
| `scripts/1_capture_launch.py` | 调试模式启动微信 + INT3 断点 + 内存现场转储（版本/字节双重门禁） |
| `scripts/2_extract_passphrase.py` | 转储滑窗 × PBKDF2 派生 × HMAC 验证（单样本门控 + 多进程） |
| `scripts/3_derive_keys.py` | 逐库派生密钥并验证 → wechat-cli 兼容的 all_keys.json |
| `scripts/selftest_crypto.py` | 加密参数合成自检（roundtrip 验证） |
| `scripts/find_kdf_anchor.py` | 在 Weixin.dll 中重新定位断点 RVA（换版本时用） |

## 环境要求

- Windows 10/11 x64，Python ≥ 3.10
- 微信 Windows 4.1.8+（开发验证：4.1.12.26）
- 依赖：`pip install -r requirements.txt`

## 已知限制

- 需要重新登录一次微信（断点须在数据库初始化前就位）
- 密钥材料失效后重跑三步即可（实测跨登录稳定）
- 仅支持单账号主进程
- 微信后续版本可能改变相关实现，届时需重新适配

## 致谢与参考

- [wechat-cli](https://github.com/huohuoer/wechat-cli) — 查询工具链
- [chatlog](https://github.com/sjzar/chatlog) — 加密参数与解密思路（已停止维护）
- [博客：连接微信与 AI](https://sikinzen.github.io/posts/howtoconnectwechatandai/) — 4.0 与 4.1+ 密钥处理差异的关键情报

## License

[MIT](LICENSE)

## 免责声明

本项目仅供个人学习、研究与访问自有账号数据使用。使用者须遵守所在地区法律法规
及软件许可协议；对使用本项目造成的任何后果，作者不承担任何责任。工具产物
（密钥文件、数据转储）包含你的账号数据，妥善保管，勿传播。
