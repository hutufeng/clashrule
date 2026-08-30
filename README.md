# Clash / mihomo 规则自动合并项目

本项目基于 GitHub Actions 与 Python，自动从 [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script/tree/master/rule/Clash) 或其他标准 Clash 规则源下载指定的规则，按用户定义的分组进行**合并、去重、排序**，并输出为标准的 Clash `rule-provider` YAML 规则文件，同时自动生成可直接复制使用的 `clash_config_snippet.yaml` 配置片段。

---

## ✨ 特性

- 🗂️ **灵活分组**：支持在 `config.yaml` 中自定义任意分组（如 `Reject`、`Streaming`、`Proxy` 等）。
- 🔄 **自动去重**：同一分组内的重复规则自动合并为一条，减少规则体积。
- ⚡ **mihomo 全规则支持与智能排序**：
  - 域名类：`DOMAIN` → `DOMAIN-SUFFIX` → `DOMAIN-KEYWORD` → `DOMAIN-WILDCARD` → `DOMAIN-REGEX` → `GEOSITE`
  - IP 类：`IP-CIDR` → `IP-CIDR6` → `IP-SUFFIX` → `IP-ASN` → `GEOIP` → `SRC-IP-CIDR` → `SRC-IP-SUFFIX` → `SRC-GEOIP` → `SRC-IP-ASN`
  - 端口/网络类：`DST-PORT` → `SRC-PORT` → `NETWORK` → `DSCP`
  - 入站类：`IN-PORT` → `IN-TYPE` → `IN-NAME` → `IN-USER`
  - 进程类：`PROCESS-NAME` → `PROCESS-NAME-WILDCARD` → `PROCESS-NAME-REGEX` → `PROCESS-PATH` → `PROCESS-PATH-WILDCARD` → `PROCESS-PATH-REGEX` → `UID`
  - 逻辑类：`AND` → `OR` → `NOT` → `SUB-RULE` → `RULE-SET`
- 🤖 **GitHub Actions 自动化**：
  - 每天凌晨（北京时间 04:00）自动拉取上游最新规则并合并提交
  - 修改 `config.yaml` 推送后立即自动重新合并
  - 支持在 GitHub Actions 界面手动一键触发 (`workflow_dispatch`)
- 📋 **配置片段自生成**：自动生成 `clash_config_snippet.yaml`，包含 `rule-providers:` 与 `rules:` 段，直接复制即可使用。
- 📊 **运行状态与日志追踪**：每次自动/手动运行均会生成并更新 [`SYNC_LOG.md`](SYNC_LOG.md)，直观展示每个规则源的下载状态、解析条数、去重条数及近 30 次运行历史。
- 🛡️ **容错处理**：若某单一来源下载失败，记录警告并继续处理其他规则源，不影响整体流程。
- 🌐 **自动识别仓库**：免去手动写死的烦恼，自动通过 Actions 环境变量或 Git Remote 检测仓库 URL。

---

## 📁 目录结构

```
clashrule/
├── config.yaml                    # 分组与规则源配置文件（用户维护）
├── merge.py                       # 核心合并与生成脚本
├── requirements.txt               # Python 依赖
├── .github/
│   └── workflows/
│       └── merge-rules.yml        # GitHub Actions 定时/推送工作流
├── rules/                         # 生成的规则文件目录（由 Actions 自动生成并提交）
│   ├── Reject.yaml
│   ├── Streaming.yaml
│   └── Proxy.yaml
├── clash_config_snippet.yaml      # 自动生成的 Clash 配置片段（直接复制使用）
├── SYNC_LOG.md                    # 运行日志（记录每次运行状态、规则源抓取明细与历史）
├── run_merge.ps1                  # 本地 PowerShell 一键测试脚本
└── README.md                      # 项目说明文档
```

---

## ⚙️ 配置说明 (`config.yaml`)

编辑仓库根目录下的 [`config.yaml`](config.yaml) 文件：

```yaml
# ============================
# Clash 规则合并配置
# ============================

# 1. 仓库信息（可选）
# 默认会自动根据当前 Git/GitHub Actions 环境推导 raw 地址
# 如需使用 CDN 加速（如 jsDelivr / Ghproxy），可取消注释并配置 raw_url_prefix：
# repo:
#   raw_url_prefix: "https://fastly.jsdelivr.net/gh/hutufeng/clashrule@main"

# 2. rule-providers 更新间隔（秒），默认 604800（7天）
interval: 604800

# 3. rules 最后的兜底匹配规则
final_rule: "MATCH,DIRECT"

# 4. 规则分组配置 (groups)
groups:
  Reject:
    policy: REJECT       # Clash rules 中对应的策略名
    priority: 1          # 匹配优先级，数字越小越排在前面
    sources:
      - https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Advertising/Advertising.yaml
      - https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Privacy/Privacy.yaml

  Streaming:
    policy: Streaming
    priority: 2
    sources:
      - https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Netflix/Netflix.yaml
      - https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Disney/Disney.yaml
      - https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Spotify/Spotify.yaml
      - https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/YouTube/YouTube.yaml

  Proxy:
    policy: Proxy
    priority: 3
    sources:
      - https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Google/Google.yaml
      - https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Telegram/Telegram.yaml
      - https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Twitter/Twitter.yaml
      - https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/OpenAI/OpenAI.yaml
      - https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/GitHub/GitHub.yaml
```

---

## 🚀 使用方法

### 方式一：直接复制 `clash_config_snippet.yaml`（推荐）

每次 Actions 运行后，会生成 [`clash_config_snippet.yaml`](clash_config_snippet.yaml)。将其中的内容直接粘贴到你的 Clash / mihomo / Clash Verge 配置文件对应位置：

```yaml
rule-providers:
  Reject:
    type: http
    behavior: classical
    url: "https://raw.githubusercontent.com/hutufeng/clashrule/main/rules/Reject.yaml"
    path: ./ruleset/Reject.yaml
    interval: 604800
    format: yaml

  Streaming:
    type: http
    behavior: classical
    url: "https://raw.githubusercontent.com/hutufeng/clashrule/main/rules/Streaming.yaml"
    path: ./ruleset/Streaming.yaml
    interval: 604800
    format: yaml

  Proxy:
    type: http
    behavior: classical
    url: "https://raw.githubusercontent.com/hutufeng/clashrule/main/rules/Proxy.yaml"
    path: ./ruleset/Proxy.yaml
    interval: 604800
    format: yaml

rules:
  - RULE-SET,Reject,REJECT
  - RULE-SET,Streaming,Streaming
  - RULE-SET,Proxy,Proxy
  - MATCH,DIRECT
```

### 方式二：CDN 加速（国内网络优化）

如果直连 `raw.githubusercontent.com` 速度较慢，可在 `config.yaml` 中配置 CDN 地址，例如：

- jsDelivr: `https://fastly.jsdelivr.net/gh/hutufeng/clashrule@main`
- Ghproxy: `https://ghproxy.net/https://raw.githubusercontent.com/hutufeng/clashrule/main`

---

## 🛠️ 本地运行与调试

如果需要在本地电脑手动测试生成：

```powershell
# 1. 进入项目目录
cd c:\Users\hutu_\clashrule

# 2. 安装 Python 依赖
pip install -r requirements.txt

# 3. 运行合并脚本
python merge.py
```

运行完成后，可以在 `rules/` 目录查看生成的规则文件，以及根目录下的 `clash_config_snippet.yaml`。
