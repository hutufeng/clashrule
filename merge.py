#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Clash / mihomo 规则自动合并脚本
- 支持从 blackmatrix7 等上游仓库下载规则
- 自动按分组合并、去重
- 支持 mihomo 全部规则类型，并按 域名类 -> IP类 -> 端口/网络类 -> 入站类 -> 进程类 -> 逻辑类 智能排序
- 自动生成 rules/<分组>.yaml (rule-provider 规则文件)
- 自动生成 clash_config_snippet.yaml (Clash 配置引用片段)
- 原生支持 Python 标准库（零外部依赖），亦兼容 requests/pyyaml 环境
"""

import os
import sys
import re
import subprocess
import datetime
from typing import Dict, List, Tuple, Any, Optional
import urllib.parse
import urllib.request
import ssl

# 确保在 Windows 控制台下正常输出 UTF-8 中文字符
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# 尝试可选导入第三方库
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# ==============================================================================
# mihomo / Clash Meta 规则类型权重映射（优先级从高到低）
# ==============================================================================
RULE_TYPE_ORDER: Dict[str, int] = {
    # 1. 域名类规则
    'DOMAIN': 1,
    'DOMAIN-SUFFIX': 2,
    'DOMAIN-KEYWORD': 3,
    'DOMAIN-WILDCARD': 4,
    'DOMAIN-REGEX': 5,
    'GEOSITE': 6,

    # 2. 目的 IP 类规则
    'IP-CIDR': 10,
    'IP-CIDR6': 11,
    'IP-SUFFIX': 12,
    'IP-ASN': 13,
    'GEOIP': 14,

    # 3. 来源 IP 类规则
    'SRC-IP-CIDR': 15,
    'SRC-IP-CIDR6': 16,
    'SRC-IP-SUFFIX': 17,
    'SRC-GEOIP': 18,
    'SRC-IP-ASN': 19,

    # 4. 端口与网络协议类
    'DST-PORT': 20,
    'SRC-PORT': 21,
    'NETWORK': 22,
    'DSCP': 23,

    # 5. 入站类规则
    'IN-PORT': 30,
    'IN-TYPE': 31,
    'IN-NAME': 32,
    'IN-USER': 33,

    # 6. 进程与系统类
    'PROCESS-NAME': 40,
    'PROCESS-NAME-WILDCARD': 41,
    'PROCESS-NAME-REGEX': 42,
    'PROCESS-PATH': 43,
    'PROCESS-PATH-WILDCARD': 44,
    'PROCESS-PATH-REGEX': 45,
    'UID': 46,

    # 7. 逻辑与子规则
    'AND': 50,
    'OR': 51,
    'NOT': 52,
    'SUB-RULE': 53,
    'RULE-SET': 54,

    # 8. 兜底匹配
    'MATCH': 99,
}


def log(msg: str) -> None:
    """标准格式化输出"""
    print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")


def parse_simple_yaml(text: str) -> Dict[str, Any]:
    """
    轻量级原生 YAML 解析器（当未安装 PyYAML 时提供标准字典、列表和标量解析）
    """
    result: Dict[str, Any] = {}
    current_section: Optional[str] = None
    current_group: Optional[str] = None
    current_list: Optional[List[Any]] = None

    lines = text.splitlines()
    for raw_line in lines:
        # 去除纯注释和空行
        line = raw_line.rstrip()
        if not line or line.strip().startswith("#"):
            continue

        indent = len(raw_line) - len(raw_line.lstrip())
        stripped = line.strip()

        # 顶层键 (indent == 0)
        if indent == 0 and ":" in stripped:
            key, val = [p.strip() for p in stripped.split(":", 1)]
            val = val.strip("\"' ")
            if not val:
                current_section = key
                if key not in result:
                    result[key] = {}
            else:
                if val.isdigit():
                    result[key] = int(val)
                elif val.lower() == "true":
                    result[key] = True
                elif val.lower() == "false":
                    result[key] = False
                else:
                    result[key] = val
                current_section = None
            current_group = None
            current_list = None
            continue

        # groups 内部二级键 (分组名，indent == 2)
        if current_section == "groups" and indent == 2 and ":" in stripped:
            g_name = stripped.split(":", 1)[0].strip()
            current_group = g_name
            if "groups" not in result:
                result["groups"] = {}
            result["groups"][current_group] = {"sources": []}
            current_list = None
            continue

        # 分组内属性 (policy, priority, sources, indent == 4)
        if current_section == "groups" and current_group and indent == 4:
            if ":" in stripped:
                k, v = [p.strip() for p in stripped.split(":", 1)]
                v = v.strip("\"' ")
                if k == "sources":
                    current_list = result["groups"][current_group]["sources"]
                elif v:
                    if v.isdigit():
                        result["groups"][current_group][k] = int(v)
                    else:
                        result["groups"][current_group][k] = v
                    current_list = None
            continue

        # 列表项 (sources 中的 URL，indent >= 6)
        if current_section == "groups" and current_group and stripped.startswith("-"):
            item_val = stripped[1:].strip().strip("\"' ")
            if item_val:
                if "sources" not in result["groups"][current_group]:
                    result["groups"][current_group]["sources"] = []
                result["groups"][current_group]["sources"].append(item_val)

    return result


def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """读取配置文件"""
    if not os.path.exists(config_path):
        log(f"错误: 找不到配置文件 {config_path}")
        sys.exit(1)
    
    with open(config_path, "r", encoding="utf-8") as f:
        content = f.read()

    if HAS_YAML:
        try:
            config = yaml.safe_load(content) or {}
            return config
        except Exception as e:
            log(f"PyYAML 解析异常，切换为内置解析: {e}")

    return parse_simple_yaml(content)


def detect_repo_info(config: Dict[str, Any]) -> Dict[str, str]:
    """
    自动推导仓库信息（用于生成 rule-providers 的 raw URL）
    优先级:
    1. config.yaml 中的 repo 字段（如有）
    2. GitHub Actions 环境变量 (GITHUB_REPOSITORY, GITHUB_REF_NAME)
    3. 本地 git 命令解析
    4. 兜底默认值
    """
    repo_cfg = config.get("repo") or {}
    user = repo_cfg.get("user")
    name = repo_cfg.get("name")
    branch = repo_cfg.get("branch")
    raw_prefix = repo_cfg.get("raw_url_prefix")

    # 1. 如果已手动指定完整 prefix
    if raw_prefix:
        return {"raw_url_prefix": raw_prefix.rstrip("/")}

    # 2. 检查 GitHub Actions 环境变量
    gh_repo = os.environ.get("GITHUB_REPOSITORY")  # 格式如: hutufeng/clashrule
    gh_ref_name = os.environ.get("GITHUB_REF_NAME")  # 格式如: main

    if not user or not name:
        if gh_repo and "/" in gh_repo:
            user, name = gh_repo.split("/", 1)
        else:
            # 3. 尝试从本地 Git 获取
            try:
                git_remote = subprocess.check_output(
                    ["git", "remote", "get-url", "origin"],
                    stderr=subprocess.DEVNULL,
                    text=True
                ).strip()
                
                match = re.search(r"github\.com[:/]([^/]+)/([^/.]+)(?:\.git)?", git_remote)
                if match:
                    user = user or match.group(1)
                    name = name or match.group(2)
            except Exception:
                pass

    if not branch:
        if gh_ref_name:
            branch = gh_ref_name
        else:
            try:
                git_branch = subprocess.check_output(
                    ["git", "branch", "--show-current"],
                    stderr=subprocess.DEVNULL,
                    text=True
                ).strip()
                if git_branch:
                    branch = git_branch
            except Exception:
                pass

    # 4. 兜底默认值
    user = user or "hutufeng"
    name = name or "clashrule"
    branch = branch or "main"

    raw_url_prefix = f"https://raw.githubusercontent.com/{user}/{name}/{branch}"
    log(f"推导仓库信息: {user}/{name} (branch: {branch}) -> {raw_url_prefix}")

    return {
        "user": user,
        "name": name,
        "branch": branch,
        "raw_url_prefix": raw_url_prefix
    }


def download_rule_source(url: str, retries: int = 3, timeout: int = 20) -> Optional[str]:
    """使用标准库 urllib 下载远程规则文件（支持重试与 SSL）"""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
        }
    )
    # 创建宽松的 SSL 上下文以保证各种网络环境下顺利拉取
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
                if response.status == 200:
                    data = response.read()
                    return data.decode("utf-8", errors="ignore")
                else:
                    log(f"  [警告] 响应状态码 {response.status}: {url} (重试 {attempt}/{retries})")
        except Exception as e:
            log(f"  [警告] 下载异常: {url} ({e}) (重试 {attempt}/{retries})")

    return None


def extract_source_name_from_url(url: str) -> str:
    """从 URL 中提取规则来源名称，例如 .../Google/Google.yaml -> Google"""
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.rstrip("/")
    basename = os.path.basename(path)
    name, _ = os.path.splitext(basename)
    return name or basename


def parse_and_clean_rules(content: str) -> List[str]:
    """
    解析规则文本，提取每条规则并规范化格式
    支持 YAML payload 格式以及纯文本 .list 格式
    """
    lines: List[str] = []

    # 逐行文本处理（比全量 YAML 解析性能更优且兼容性更好）
    in_payload = False
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//") or line.startswith(";"):
            continue

        if line == "payload:":
            in_payload = True
            continue

        # 去除 YAML 列表项前导 '- '
        if line.startswith("-"):
            line = line[1:].strip()

        # 去除行尾注释
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        elif " //" in line:
            line = line.split(" //", 1)[0].strip()

        # 去除多余引号
        line = line.strip("\"'")

        if line and "," in line:
            lines.append(line)

    return lines


def normalize_rule(rule_line: str) -> Tuple[str, str, str]:
    """
    规范化单条规则
    返回: (规范化后的完整规则字符串, 规则大写类型, 规则主体内容)
    例如: "  domain-suffix , google.com , Proxy " -> ("DOMAIN-SUFFIX,google.com", "DOMAIN-SUFFIX", "google.com")
    """
    parts = [p.strip() for p in rule_line.split(",") if p.strip()]
    if not parts:
        return "", "", ""

    rule_type = parts[0].upper()

    cleaned_parts = [rule_type]
    for p in parts[1:]:
        if p.lower() == "no-resolve":
            cleaned_parts.append("no-resolve")
        else:
            cleaned_parts.append(p)

    normalized_str = ",".join(cleaned_parts)
    rule_value = ",".join(cleaned_parts[1:]) if len(cleaned_parts) > 1 else ""

    return normalized_str, rule_type, rule_value


def sort_key_for_rule(rule_tuple: Tuple[str, str, str]) -> Tuple[int, str, str]:
    """规则排序键：规则类型优先级 -> 规则类型名 -> 规则内容"""
    _, rule_type, rule_value = rule_tuple
    order_val = RULE_TYPE_ORDER.get(rule_type, 90)
    return (order_val, rule_type, rule_value)


def process_group(
    group_name: str,
    group_cfg: Dict[str, Any],
    output_dir: str = "rules"
) -> Tuple[bool, int, Dict[str, int], List[Dict[str, Any]]]:
    """
    处理单个规则分组：下载、合并、去重、排序、写入 rules/<分组名>.yaml
    返回: (是否成功, 规则总数, 各类型规则统计, 规则源详细报告列表)
    """
    sources: List[str] = group_cfg.get("sources") or []
    if not sources:
        log(f"[{group_name}] 没有配置任何 sources，跳过")
        return False, 0, {}, []

    log(f"[{group_name}] 开始处理，共 {len(sources)} 个规则源...")

    raw_rules_dict: Dict[str, Tuple[str, str, str]] = {}
    source_names: List[str] = []
    source_reports: List[Dict[str, Any]] = []

    for src_url in sources:
        src_name = extract_source_name_from_url(src_url)
        if src_name not in source_names:
            source_names.append(src_name)

        log(f"  -> 下载: {src_name} ({src_url})")
        content = download_rule_source(src_url)
        if content is None:
            source_reports.append({
                "name": src_name,
                "url": src_url,
                "success": False,
                "parsed_count": 0,
                "added_count": 0,
                "error": "下载失败或超时"
            })
            continue

        parsed_lines = parse_and_clean_rules(content)
        count_before = len(raw_rules_dict)
        for line in parsed_lines:
            norm_str, r_type, r_val = normalize_rule(line)
            if norm_str and norm_str not in raw_rules_dict:
                raw_rules_dict[norm_str] = (norm_str, r_type, r_val)

        added = len(raw_rules_dict) - count_before
        log(f"     解析得到 {len(parsed_lines)} 条规则，去重后新增 {added} 条")

        source_reports.append({
            "name": src_name,
            "url": src_url,
            "success": True,
            "parsed_count": len(parsed_lines),
            "added_count": added,
            "error": ""
        })

    # 排序规则
    sorted_rule_tuples = sorted(raw_rules_dict.values(), key=sort_key_for_rule)
    final_rules = [t[0] for t in sorted_rule_tuples]

    # 统计各类规则数量
    type_counts: Dict[str, int] = {}
    for _, r_type, _ in sorted_rule_tuples:
        type_counts[r_type] = type_counts.get(r_type, 0) + 1

    # 准备写入文件
    os.makedirs(output_dir, exist_ok=True)
    out_file = os.path.join(output_dir, f"{group_name}.yaml")

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    now_str = now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")

    failed_srcs = [s["url"] for s in source_reports if not s["success"]]

    # 构造头部元信息注释
    header_lines = [
        f"# NAME: {group_name}",
        f"# UPDATED: {now_str}",
        f"# SOURCES: {', '.join(source_names)}",
    ]
    if failed_srcs:
        header_lines.append(f"# WARNING_FAILED_SOURCES: {len(failed_srcs)}")

    for r_type, cnt in sorted(type_counts.items(), key=lambda x: (RULE_TYPE_ORDER.get(x[0], 90), x[0])):
        header_lines.append(f"# {r_type}: {cnt}")
    header_lines.append(f"# TOTAL: {len(final_rules)}")
    header_lines.append("payload:")

    # 写入 YAML 文件
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(header_lines) + "\n")
        for rule in final_rules:
            f.write(f"  - {rule}\n")

    log(f"[{group_name}] 生成完成 -> {out_file} (共 {len(final_rules)} 条规则)")
    return True, len(final_rules), type_counts, source_reports


def generate_clash_snippet(
    config: Dict[str, Any],
    repo_info: Dict[str, str],
    valid_groups: List[Tuple[str, Dict[str, Any]]],
    output_path: str = "clash_config_snippet.yaml"
) -> None:
    """
    生成可直接复制使用的 Clash / mihomo 配置片段文件
    包含 rule-providers: 和 rules: 两大段
    """
    interval = config.get("interval", 604800)
    final_rule = config.get("final_rule", "MATCH,DIRECT")
    raw_prefix = repo_info["raw_url_prefix"]
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # 1. 构建 rule-providers 节点
    rule_providers_dict: Dict[str, Any] = {}
    for group_name, _ in valid_groups:
        rule_providers_dict[group_name] = {
            "type": "http",
            "behavior": "classical",
            "url": f"{raw_prefix}/rules/{group_name}.yaml",
            "path": f"./ruleset/{group_name}.yaml",
            "interval": interval,
            "format": "yaml"
        }

    # 2. 构建 rules 列表
    rules_list: List[str] = []
    for group_name, group_cfg in valid_groups:
        policy = group_cfg.get("policy", group_name)
        rules_list.append(f"RULE-SET,{group_name},{policy}")

    if final_rule:
        rules_list.append(final_rule)

    # 3. 组织完整的 YAML 输出
    snippet_content = f"""# ==============================================================================
# Clash / mihomo 配置片段 (自动生成)
# 更新时间: {now_str}
# 仓库地址: {raw_prefix}
# 使用方法: 将下方内容复制并合并至您的 Clash 配置文件对应段落
# ==============================================================================

rule-providers:
"""
    # 格式化 rule-providers
    for name, provider in rule_providers_dict.items():
        snippet_content += f"  {name}:\n"
        snippet_content += f"    type: {provider['type']}\n"
        snippet_content += f"    behavior: {provider['behavior']}\n"
        snippet_content += f"    url: \"{provider['url']}\"\n"
        snippet_content += f"    path: {provider['path']}\n"
        snippet_content += f"    interval: {provider['interval']}\n"
        snippet_content += f"    format: {provider['format']}\n\n"

    # 格式化 rules
    snippet_content += "rules:\n"
    for r in rules_list:
        snippet_content += f"  - {r}\n"

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(snippet_content)

    log(f"生成 Clash 配置片段 -> {output_path}")


def write_sync_log(
    group_reports: List[Dict[str, Any]],
    total_rules: int,
    log_path: str = "SYNC_LOG.md"
) -> None:
    """
    生成并维护运行日志文件 SYNC_LOG.md
    记录每次运行时间、各分组状态、每个规则源下载情况及历史记录
    """
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    time_utc_str = now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # 计算北京时间 (UTC+8)
    bj_time = now_utc + datetime.timedelta(hours=8)
    time_bj_str = bj_time.strftime("%Y-%m-%d %H:%M:%S (北京时间)")

    total_sources = sum(len(g["reports"]) for g in group_reports)
    failed_sources = sum(
        sum(1 for r in g["reports"] if not r["success"])
        for g in group_reports
    )
    success_sources = total_sources - failed_sources

    if failed_sources == 0:
        status_badge = "🟢 运行成功 (全部正常)"
        status_summary = "✅ 所有规则源均已成功获取并合并"
        status_short = "✅ 成功"
    elif success_sources > 0:
        status_badge = f"🟡 部分成功 ({failed_sources} 个源失败)"
        status_summary = f"⚠️ 部分规则源获取失败，已跳过失败源并成功合并其余规则"
        status_short = f"⚠️ 部分失败({failed_sources})"
    else:
        status_badge = "🔴 运行失败"
        status_summary = "❌ 所有规则源均获取失败"
        status_short = "❌ 失败"

    # 读取旧日志中的历史记录
    history_lines: List[str] = []
    if os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                old_content = f.read()
                if "<!-- HISTORY_START -->" in old_content and "<!-- HISTORY_END -->" in old_content:
                    history_block = old_content.split("<!-- HISTORY_START -->")[1].split("<!-- HISTORY_END -->")[0]
                    for h_line in history_block.strip().splitlines():
                        h_line_str = h_line.strip()
                        if h_line_str.startswith("|") and not h_line_str.startswith("| 执行时间") and not h_line_str.startswith("|:"):
                            history_lines.append(h_line_str)
        except Exception as e:
            log(f"读取旧日志历史异常: {e}")

    # 当前这次记录加入历史最前面
    current_history_row = f"| {time_bj_str} | {len(group_reports)} | {total_rules} | {total_sources} | {failed_sources} | {status_short} |"
    history_lines.insert(0, current_history_row)
    history_lines = history_lines[:30]  # 保留最近 30 次记录

    # 组装 SYNC_LOG.md 内容
    lines = [
        "# 📋 Clash / mihomo 规则自动合并运行日志",
        "",
        f"> **最后运行时间**：`{time_bj_str}` / `{time_utc_str}`  ",
        f"> **运行状态**：{status_badge}  ",
        f"> **总体概况**：处理分组 `{len(group_reports)}` 个，规则源 `{total_sources}` 个（成功 `{success_sources}` / 失败 `{failed_sources}`），合并后总规则数 `{total_rules}` 条",
        "",
        f"**状态说明**：{status_summary}",
        "",
        "---",
        "",
        "## 📊 本次运行分组明细",
        "",
        "| 分组名称 | 代理策略 (Policy) | 优先级 | 规则源总数 | 成功 | 失败 | 生成规则数 | 状态 |",
        "|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|",
    ]

    for g in group_reports:
        g_name = g["name"]
        g_policy = g["policy"]
        g_priority = g["priority"]
        g_src_total = len(g["reports"])
        g_src_fail = sum(1 for r in g["reports"] if not r["success"])
        g_src_ok = g_src_total - g_src_fail
        g_count = g["rule_count"]
        g_status = "✅ 正常" if g_src_fail == 0 else f"⚠️ {g_src_fail}源失败"

        lines.append(
            f"| `{g_name}` | `{g_policy}` | `{g_priority}` | {g_src_total} | {g_src_ok} | {g_src_fail} | **{g_count}** | {g_status} |"
        )

    lines.extend([
        "",
        "### 🔗 各规则源抓取详情",
        "",
    ])

    for g in group_reports:
        g_name = g["name"]
        lines.append(f"<details>")
        lines.append(f"<summary><b>📂 {g_name} 分组规则源详情 (共 {len(g['reports'])} 个源)</b></summary>")
        lines.append("")
        lines.append("| 规则源名称 | 抓取状态 | 解析条数 | 去重后新增 | 规则源链接 | 备注 |")
        lines.append("|:---|:---:|:---:|:---:|:---|:---|")
        for r in g["reports"]:
            r_status = "✅ 成功" if r["success"] else "❌ 失败"
            r_parsed = r["parsed_count"]
            r_added = r["added_count"]
            r_url = r["url"]
            r_err = r["error"] or "-"
            lines.append(f"| `{r['name']}` | {r_status} | {r_parsed} | {r_added} | [链接]({r_url}) | {r_err} |")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    lines.extend([
        "---",
        "",
        "## 📜 运行历史记录 (最近 30 次)",
        "",
        "| 执行时间 (北京时间) | 处理分组数 | 总规则数 | 规则源总数 | 失败源数 | 整体状态 |",
        "|:---|:---:|:---:|:---:|:---:|:---:|",
        "<!-- HISTORY_START -->",
    ])
    lines.extend(history_lines)
    lines.extend([
        "<!-- HISTORY_END -->",
        "",
        "> *注：本文件由 GitHub Actions 或本地 `merge.py` 每次执行后自动更新。*",
        ""
    ])

    with open(log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    log(f"运行日志已更新 -> {log_path}")


def main() -> None:
    log("=== 开始执行 Clash 规则合并任务 ===")
    config = load_config("config.yaml")
    repo_info = detect_repo_info(config)

    groups_cfg: Dict[str, Dict[str, Any]] = config.get("groups") or {}
    if not groups_cfg:
        log("警告: config.yaml 中未配置任何 groups 分组")
        sys.exit(0)

    # 按 priority 优先级排序各个分组
    sorted_groups = sorted(
        groups_cfg.items(),
        key=lambda item: item[1].get("priority", 999)
    )

    valid_groups: List[Tuple[str, Dict[str, Any]]] = []
    group_reports: List[Dict[str, Any]] = []
    total_rules_all = 0
    all_failed_sources: List[str] = []

    for group_name, g_cfg in sorted_groups:
        success, rule_count, type_counts, src_reports = process_group(group_name, g_cfg, output_dir="rules")
        if success:
            valid_groups.append((group_name, g_cfg))
            total_rules_all += rule_count
            
        group_reports.append({
            "name": group_name,
            "policy": g_cfg.get("policy", group_name),
            "priority": g_cfg.get("priority", 999),
            "rule_count": rule_count,
            "type_counts": type_counts,
            "reports": src_reports
        })

        for r in src_reports:
            if not r["success"]:
                all_failed_sources.append(r["url"])

    # 1. 生成 Clash 配置片段
    if valid_groups:
        generate_clash_snippet(config, repo_info, valid_groups, "clash_config_snippet.yaml")

    # 2. 清理 rules/ 目录下已不再存在于 config.yaml 中的旧规则文件
    valid_file_names = {f"{g_name}.yaml" for g_name, _ in valid_groups}
    if os.path.exists("rules"):
        for fname in os.listdir("rules"):
            if fname.endswith(".yaml") and fname not in valid_file_names:
                old_path = os.path.join("rules", fname)
                try:
                    os.remove(old_path)
                    log(f"清理已废弃的旧规则文件: {old_path}")
                except Exception as e:
                    log(f"清理文件失败 {old_path}: {e}")

    # 3. 生成/更新运行日志文件 SYNC_LOG.md
    write_sync_log(group_reports, total_rules_all, "SYNC_LOG.md")

    log("=== 合并任务完成 ===")
    log(f"成功处理分组数: {len(valid_groups)}, 总规则数: {total_rules_all}")
    if all_failed_sources:
        log(f"注意: 共有 {len(all_failed_sources)} 个规则源下载失败")
        for f_url in all_failed_sources:
            log(f"  - 失败源: {f_url}")


if __name__ == "__main__":
    main()
