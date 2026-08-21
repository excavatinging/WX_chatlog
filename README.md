# WX-chatlog

针对 **Windows 微信 4.1.x（4.1.8+，含 4.1.12）** 的本地聊天记录解密导出工具链。

2025 年末起，微信 4.1.8+ 对密钥机制做了加固：数据库密钥**用完即擦**，内存中不再常驻明文密钥，导致 chatlog / PyWxDump / wechat-dump-rs 等所有基于"静态内存扫描"的传统工具全部失效（相关项目也多已被 DMCA 下架）。

本项目提供一套**无第三方 DLL 注入**的替代方案：以调试器断点在密钥初始化瞬间捕获内存现场，结合 PBKDF2 派生验证提取 passphrase，再用成熟工具链完成解密与导出。

> ⚠️ **仅供个人学习、研究与备份本人聊天记录。请遵守当地法律法规，详见[免责声明](#免责声明)。**

## 原理

微信 4.x 数据库为 SQLCipher 变体加密：

```
salt     = db 文件前 16 字节（每个库随机）
enc_key  = PBKDF2-HMAC-SHA512(passphrase, salt, 256000, 32)
mac_key  = PBKDF2-HMAC-SHA512(enc_key, salt ^ 0x3a, 2, 32)
页 HMAC   = HMAC-SHA512(mac_key, page_data || LE(page_no))   ← 页号小端，非标准 SQLCipher
```

与 4.0 的关键差异（本项目存在的意义）：

| | 微信 4.0.x | 微信 4.1.8+ |
|---|---|---|
| 内存中的密钥形态 | 派生后的 enc_key（可静态扫描） | **仅 passphrase，且即用即擦** |
| 提取方式 | 内存扫描 | **断点拦截初始化现场** |

本项目断点锚定 Weixin.dll 中的 SQLCipher `kdf_iter` 设置函数（通过搜索 PBKDF2 迭代次数 `256000/0x3E800` 立即数 + capstone 反汇编定位），登录时每个数据库初始化都会命中，转储 codec 上下文内存；passphrase 即藏于其中，用"候选 × PBKDF2 派生 × HMAC 验证"命中。

## 工作流（三步）

```bash
# ① 断点捕获：以调试模式启动微信，登录后自动捕获并转储（数分钟）
#    ⚠️ 运行前必须完全退出微信（托盘右键退出），断点须在数据库初始化前就位
python scripts/1_capture_launch.py

# ② passphrase 提取：对转储字节做 PBKDF2 派生验证（约 45 分钟，无人值守）
python scripts/2_extract_passphrase.py

# ③ 派生全部库密钥 → wechat-cli 格式 all_keys.json
python scripts/3_derive_keys.py
```

### 路径配置（微信不在默认位置时必须设置）

脚本默认假定微信安装在 `C:\Program Files\Tencent\Weixin`。若你的微信装在其他位置，
通过环境变量覆盖（PowerShell 示例）：

```powershell
$env:WX_EXE   = "D:\Apps\Weixin\Weixin.exe"        # 微信主程序
$env:WX_DIR   = "D:\Apps\Weixin"                    # 微信安装目录
$env:WX_DB_DIR = "D:\xwechat_files\<你的wxid目录>\db_storage"   # ②③ 需要
```

`WX_DB_DIR` 即微信数据目录下以 `wxid_` 开头、后缀最长的那个文件夹里的 `db_storage`。

bash（Git Bash / MSYS）写法：

```bash
export WX_EXE='D:\Apps\Weixin\Weixin.exe' WX_DIR='D:\Apps\Weixin'
cd scripts && python -X utf8 1_capture_launch.py
```

注意环境变量与命令须在**同一条** shell 命令中设置并使用（每条 `!` 命令是独立 shell）。

之后即可用 [wechat-cli](https://github.com/huohuoer/wechat-cli) 查询/导出（其查询层与 4.1.12 兼容，仅 init 提取环节失效，本项目即为其替代）：

```bash
pip install -e <wechat-cli 源码路径>
wechat-cli history "联系人备注" --limit 100
wechat-cli export "联系人备注" --format markdown --output chat.md --limit 10000000
```

## 环境要求

- Windows 10/11 x64，Python ≥ 3.10
- 微信 Windows 版 4.1.8+（开发验证版本：4.1.12.26）
- 依赖：`pip install -r requirements.txt`（①② 仅用标准库；③/selftest 需 pycryptodome，锚点定位需 capstone）

## 脚本说明

| 脚本 | 作用 | 输入 → 输出 |
|---|---|---|
| `scripts/1_capture_launch.py` | 调试模式启动微信 + INT3 断点 + 内存转储 | 登录操作 → `secrets/ctx_dumps/*.json` |
| `scripts/2_extract_passphrase.py` | 转储字节滑窗 × PBKDF2 派生 × HMAC 验证（单样本门控加速） | `ctx_dumps/` → `passphrase.txt` |
| `scripts/3_derive_keys.py` | passphrase 派生全部库密钥并验证 → `all_keys.json` | `passphrase.txt` → `all_keys.json` |
| `scripts/selftest_crypto.py` | 加密参数自检（合成数据 roundtrip） | 无依赖验证算法正确性 |
| `scripts/find_kdf_anchor.py` | 在 Weixin.dll 中定位 kdf_iter setter 的 RVA（换微信版本时用） | Weixin.dll → 断点 RVA |

路径通过脚本顶部 **CONFIG 区** 或环境变量配置；所有敏感输出（passphrase/密钥/转储）均落在 `secrets/` 目录（已 gitignore）。

## 微信升级后怎么办

断点 RVA 随版本变化。若 ① 步骤 15 分钟内断点 0 命中：

```bash
python scripts/find_kdf_anchor.py "<微信安装目录>\<版本号>\Weixin.dll"
# 将输出的 RVA 更新到 1_capture_launch.py 的 BP_RVA
```

定位原理见 `docs/how-it-works.md`。

## 已知限制

- 需要重新登录一次微信（断点须在数据库初始化前就位）
- passphrase 可能随微信重启/重新登录变化，失效后重跑三步即可
- 仅支持单开账号主进程；多账号场景取内存最大的进程
- 与所有逆向工具一样，存在被后续微信版本再次封锁的可能

## 致谢与参考

- [wechat-cli](https://github.com/huohuoer/wechat-cli)（huohuoer）— 查询/导出层
- [chatlog](https://github.com/sjzar/chatlog)（sjzar）— 加密参数与解密思路（已停止维护）
- wechat-dump-rs（0xlane，已下架）— v4 参数与验证逻辑参考
- [博客：连接微信与 AI](https://sikinzen.github.io/posts/howtoconnectwechatandai/) — 4.0 与 4.1+ 密钥机制差异的关键情报

## License

[MIT](LICENSE)

## 免责声明

本项目仅供个人学习、研究与备份本人聊天记录使用。使用者须遵守所在地区法律法规及微信软件许可协议；对使用本项目造成的任何后果，作者不承担任何责任。导出的数据与密钥文件包含你的全部聊天记录，妥善保管，勿传播。
