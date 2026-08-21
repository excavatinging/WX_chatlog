# WX-chatlog

> Windows 本地数据访问工具链：帮助你在自己的电脑上，对自己有权访问的微信账号数据进行离线研究和只读查询。

本项目把环境检查、版本确认、临时材料捕获、逐库密钥验证和下游只读查询串成一条可重复的工作流。它不是云服务，也不会把你的本地数据上传到仓库或第三方服务；涉及退出客户端、扫码登录和是否写入下游配置的动作，都由你亲自确认。

请只处理你本人有权访问的数据，并遵守当地法律、软件许可协议和组织政策。

## 先确认是否适合你

当前主流程适用于：

- Windows 10/11 x64
- 64 位 Python 3.10 或更高版本
- 已验证的客户端基线 `4.1.12.26`
- 你自己的账号，以及你能明确确认位置的数据目录

当前版本不适用于 Linux、WSL 或远程服务器，也不会因为版本号相近就尝试运行。客户端升级后，必须先重新定位锚点并完成真实回归；离线自检通过不等于新版本已经兼容。

## 你需要准备什么

1. 安装好 64 位 Weixin，并确认正在使用的客户端版本。
2. 确认自己的数据目录。可以从正在运行的 `Weixin.exe` 路径，或客户端“设置 → 文件管理”中核对。
3. 安装 64 位 Python 3.10+。
4. 使用 Windows PowerShell 完成下面的步骤，并尽量在同一个 PowerShell 窗口中操作。

### 为什么要在运行时填写路径

脚本需要知道本机的客户端位置和数据目录，但这些路径通常包含 Windows 用户名、账号标识或个人目录结构。你会在运行时把它们临时提供给当前 PowerShell 窗口，仓库只保留变量名和使用说明，不保留真实路径。

这样做的意义是降低误提交、误同步和让 AI 助手复述本机信息的风险。环境变量不是加密措施：不要把真实值贴到 issue、聊天、截图或终端共享记录中；关闭 PowerShell 后，这些临时设置也不会自动保留到下一次窗口。

## 快速开始

### 1. 获取代码并检查环境

```powershell
git clone https://github.com/excavatinging/WX_chatlog.git
Set-Location WX_chatlog

# 先做不依赖第三方包的隐私检查
python scripts\privacy_check.py

python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python scripts\repo_check.py
```

隐私检查和环境预检不依赖第三方包。`pycryptodome` 用于加密自检，`capstone` 只在客户端升级、需要重新定位锚点时使用。

### 2. 设置本机路径并运行预检

先由你确认安装位置和账号数据目录，再在当前 PowerShell 窗口设置变量。下面尖括号中的内容是占位符，请替换成你确认过的值；不要把替换后的命令写回 README、提交记录或聊天。

```powershell
$env:WX_EXE = '<你的 Weixin.exe 完整路径>'
$env:WX_DB_DIR = '<你的 db_storage 完整路径>'

# 安装目录有多个候选 Weixin.dll 时才设置
# $env:WX_DLL = '<你确认的 Weixin.dll 完整路径>'

# 可选：敏感产物目录。默认使用仓库内被忽略的 secrets\
# $env:WX_SECRETS_DIR = '<你确认的本地敏感产物目录>'

python scripts\0_preflight.py --json
```

预检是只读的，并且会检查平台、目录、`Weixin.dll`、完整版本号和函数字节。结果含义如下：

| 退出码 | 含义 | 你要做什么 |
|---|---|---|
| `0` | 环境已准备好 | 可以继续 |
| `2` | 缺少需要你确认的输入 | 补齐或修正环境变量后重试 |
| `1` | 平台、目录或版本资料无效 | 停止并修正问题，不要绕过门禁 |

主脚本不会猜测默认安装目录。预检未通过时，后续步骤会停止。

### 3. 运行加密实现自检

```powershell
python scripts\selftest_crypto.py
```

退出码 `0` 只表示仓库内的加密实现可以完成合成数据往返验证，不表示你的客户端版本已经适配。

### 4. 执行本地工作流

开始前，请由你亲自完全退出微信。脚本不会替你结束进程，也不会替你输入密码或完成登录。

```powershell
# ① 启动后由你完成扫码登录；收集结束后脚本会脱离调试
python scripts\1_capture_launch.py

# ② 在本机计算派生材料
python scripts\2_extract_passphrase.py

# ③ 逐库派生并验证；所有可读加密数据库通过后才写入 all_keys.json
python scripts\3_derive_keys.py
```

步骤 ② 可按需要设置：

- `WX_WORKERS`：并行进程数，默认最多使用 14 个逻辑 CPU。
- `WX_SCAN_STEP`：候选窗口步长，只允许 `1/2/4/8`，默认 `8`。已确认锚点但没有命中时，可在同一窗口设置为 `1` 重试，代价是通常增加扫描时间。

敏感结果默认写入被 Git 忽略的 `secrets/`：

- `ctx_dumps/*.json`：进程内存片段
- `passphrase.txt`：逐库派生材料
- `all_keys.json`：数据库密钥映射

不要同步、上传、截图或提交这些文件。是否在本机保留它们，由你根据自己的安全要求决定。

## 可选：接入 wechat-cli

如果你需要在本机使用下游只读查询工具，可以先预演配置，再决定是否写入本地配置目录。兼容性已对照其固定提交
[`a378923`](https://github.com/huohuoer/wechat-cli/blob/a3789232d4f79bf0b30634d9dadbce71e4acd601/wechat_cli/keys/common.py#L128-L162)
及其[路径兼容逻辑](https://github.com/huohuoer/wechat-cli/blob/a3789232d4f79bf0b30634d9dadbce71e4acd601/wechat_cli/core/key_utils.py#L14-L33)。

```powershell
python -m pip install "wechat-cli @ git+https://github.com/huohuoer/wechat-cli.git@a3789232d4f79bf0b30634d9dadbce71e4acd601"

# 默认只校验并预演，不写用户目录
python scripts\4_configure_wechat_cli.py

# 你确认后才写本地配置
python scripts\4_configure_wechat_cli.py --apply

wechat-cli sessions
```

步骤 ④ 会保留已有 `config.json` 的其他字段，只更新数据库目录，并对状态文件执行同样的 Windows 权限保护。查询内容仍属于个人数据，不要把它复制到 AI 对话、issue 或日志中。

## 客户端升级适配

预检会直接核验 `Weixin.dll`，不会用 `Weixin.exe` 的版本替代它。若一个安装目录中存在多个候选 DLL，必须由你确认并设置 `WX_DLL`。如果实际版本不同，先停止主流程：

```powershell
python scripts\find_kdf_anchor.py '<你确认的 Weixin.dll 完整路径>'
```

定位器会校验 PE32+ x64 文件结构，并给出当前 PowerShell 可使用的三个变量：

- `WX_BP_RVA`
- `WX_EXPECTED_VERSION`
- `WX_EXPECTED_FN_BYTES`

候选评分只是线索。最高分并列时必须人工核对调用关系；之后仍要重新运行预检和真实回归。无法读取完整 `FileVersion` 时，定位器会拒绝生成不完整资料。不要为了适配本机而直接修改仓库源码。

## 如果你让 AI 助手协助操作

AI 可以帮助你解释预检结果、检查代码、运行离线测试和组织命令；以下动作必须由你掌握：

1. 确认正在操作的是自己的电脑和账号。
2. 选择并确认客户端路径、数据目录和账号。
3. 完全退出客户端，并在需要时亲自完成扫码登录。
4. 查看预演结果后，再决定是否使用 `--apply`。
5. 保留或删除敏感产物，并承担最终授权与合规责任。

要求 AI 只报告退出码、状态和计数，不要复述真实路径、账号目录、联系人、密钥、消息或查询结果。仓库根目录的 [AGENTS.md](AGENTS.md) 是更完整的协作契约。

## 维护者与贡献者检查

提交修改前运行：

```powershell
python scripts\repo_check.py
```

它会执行 Python 编译、合成数据单元测试、普通模式及 `python -O` 加密自检、Windows DACL 设置与回读、当前工作树及完整 Git 历史隐私扫描、不可扫描文件阻断和 `git diff --check`。

GitHub Actions 会在 Windows 和 Python `3.10`、`3.12`、`3.14` 上重复执行离线门禁；Python 3.12 任务还会执行 Bandit 和 `pip-audit`。CI 不会接触真实客户端、数据库或账号数据。

## 原理摘要

```text
salt     = db 文件前 16 字节
enc_key  = PBKDF2-HMAC-SHA512(passphrase, salt, 256000, 32)
mac_key  = PBKDF2-HMAC-SHA512(enc_key, salt XOR 0x3a, 2, 32)
页校验    = HMAC-SHA512(mac_key, page_data || LE(page_no))
```

传统的派生密钥字符串扫描在部分 4.1.8+ 构建中无法取得完整材料。本项目在 KDF 初始化路径设置版本受控的断点，捕获上下文，再离线派生并以数据库首页 HMAC 验证。技术细节见 [docs/how-it-works.md](docs/how-it-works.md)。

## 文件说明

| 文件 | 作用 |
|---|---|
| `AGENTS.md` | AI 助手的授权、隐私和执行契约 |
| `scripts/0_preflight.py` | 只读环境发现与机器可读预检 |
| `scripts/1_capture_launch.py` | 版本受控的调试启动、断点与敏感转储 |
| `scripts/2_extract_passphrase.py` | 转储滑窗、PBKDF2 门控与全库确认 |
| `scripts/3_derive_keys.py` | 逐库派生并全量验证 `all_keys.json` |
| `scripts/4_configure_wechat_cli.py` | 预演或安装下游本地配置 |
| `scripts/find_kdf_anchor.py` | 新版本 KDF 锚点候选定位 |
| `scripts/win_dacl.py` | Windows 当前用户 DACL 与安全写入 |
| `scripts/privacy_check.py` | 工作树、历史和提交元数据隐私门禁 |
| `scripts/repo_check.py` | 一键发布前验证 |

## 已知限制

- 默认版本资料只覆盖 `4.1.12.26`。
- 步骤 ① 需要重新登录一次，只支持单账号主流程。
- 步骤 ② 可能运行较久，实际时间取决于转储量、CPU 和扫描步长。
- 调试器会短暂暂停线程，存在客户端卡顿或崩溃风险；脚本尽力恢复字节并脱离调试，但不能承诺对未来版本零影响。
- 下游项目会变化，使用前应重新核对其安装方式和文件格式。

## 参考

- [wechat-cli](https://github.com/huohuoer/wechat-cli)：本地下游查询工具链
- [chatlog](https://github.com/sjzar/chatlog)：历史加密参数与实现参考
- [连接微信与 AI](https://sikinzen.github.io/posts/howtoconnectwechatandai/)：版本差异研究线索

## License

[MIT](LICENSE)

## 免责声明

本项目仅供个人学习、研究与访问自有账号数据。使用者负责确认授权范围并遵守所在地法律法规、软件许可协议和组织政策。作者不保证对未来版本持续兼容，也不对使用后果承担责任。
