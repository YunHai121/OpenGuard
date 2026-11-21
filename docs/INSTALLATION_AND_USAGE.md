# OpenGuard 安装、运行与第三方集成使用文档 (v1.3+)

## 1. 环境要求与安装

- **操作系统**：Windows 10/11、Linux (Ubuntu/Debian/CentOS)、macOS
- **Python 版本**：`>= 3.10`（已验证支持至 Python 3.14）
- **可选工具**：`git`（启用 `--git-history`、`--staged`、`--diff` 或远程 URL 扫描时需要）

### 本地源码安装

```bash
git clone https://github.com/YunHai121/OpenGuard.git
cd OpenGuard
pip install -r requirements.txt
pip install -e . --no-build-isolation --no-deps
```

验证安装与一键环境体检：

```bash
openguard version
openguard doctor .
```

---

## 2. 命令行 (CLI) 核心用法

### 2.1 零摩擦初始化与安全态势自检 (`init` / `doctor`)

```bash
# 自动探测目标仓库技术栈，幂等生成定制 .openguard.yml / .openguardignore / 策略模板
openguard init .

# 执行 7 项环境与仓库安全就绪度体检（附可复制修复指引；支持 --json）
openguard doctor .
```

### 2.2 全维度项目审计 (`scan`)

```bash
# 扫描本地项目并在终端展示 5 维得分、质量门禁与风险详情
openguard scan examples/vulnerable_demo_repo --offline

# 启用 SHA-256 增量文件缓存提速二次扫描
openguard scan . --offline --cache

# 仅审计 PR 增量变更，并静默存量基线问题
openguard baseline create . -o .openguard-baseline.json
openguard scan . --diff origin/main --baseline .openguard-baseline.json --fail-on high

# 回溯 Git 提交历史（捕获已从最新代码中删除的历史幽灵密钥）
openguard scan path/to/git_repo --git-history --max-commits 100

# 纯净 JSON 输出（静默 Rich 装饰，可直接管道接入 jq/CI），退出码约定 0/1/2/3
openguard scan . --offline --json | jq '.summary'

# 老项目非阻塞灰度观察模式（触发阈值仍返回退出码 0）
openguard scan path/to/legacy_repo --offline --fail-on high --audit-mode

# 一键导出全套 9 份报告 (HTML / PDF / JSON / SARIF / CycloneDX VEX / SPDX / SLSA v1.0 / Markdown / SVG 徽章)
openguard scan examples/vulnerable_demo_repo --offline --format all --output demo_outputs/demo_audit
```

### 2.3 一键脱敏重构、安全依赖升级与文档补齐 (`autofix`)

```bash
# 默认 Dry-Run 预览 Unified Diff（支持密钥剥离、CVE 依赖升级、规范文档补齐）
openguard autofix path/to/repo --secrets --deps --docs --license MIT

# 确认写入修改（自动备份原文件至 .openguard_backup/ 并生成 .env.example）
openguard autofix path/to/repo --secrets --deps --docs --license MulanPSL-2.0 --apply
```

### 2.4 SBOM 生成、供应链漂移对比、NTIA 评分与 SLSA 证明 (`sbom` / `sbom-diff` / `sbom-score` / `attest`)

```bash
# 导出 CycloneDX 1.5 (含 VEX analysis) 或 SPDX 2.3 SBOM
openguard sbom . --spec cyclonedx -o sbom.cdx.json
openguard sbom . --spec spdx -o sbom.spdx.json

# 对比两份 SBOM，拦截新增高危 CVE 或 Copyleft 许可证漂移
openguard sbom-diff before.cdx.json after.cdx.json --fail-on-drift -o sbom_diff.md

# 依据 7 项 NTIA/CISA 最小要素给出 0–10.0 SBOM 质量评分（对标 sbomqs）
openguard sbom-score . --min-score 8.0

# 生成与校验 in-toto v1 / SLSA Provenance v1.0 供应链完整度证明
openguard attest generate . -o slsa_provenance.json
openguard attest verify slsa_provenance.json --repo .
```

### 2.5 组织/竞赛级多仓批量审计 (`batch`)

```bash
# 一键审计父目录下所有子仓库，流式导出 JSONL (SIEM/BI) 与 Portfolio Markdown 排行榜
openguard batch path/to/projects_dir --offline --cache --jsonl-out audit.jsonl --md-out portfolio.md --fail-on-gate
```

### 2.6 本地 Pre-commit 防线与 CI/CD 模板 (`hook`)

```bash
# 安装提交前实时防泄露拦截钩子
openguard hook install .

# 生成 GitHub Actions 或校内 git.hust.edu.cn GitLab CI 流水线
openguard hook ci . --ci-platform github
openguard hook ci . --ci-platform gitlab
```

### 2.7 启动可视化 Web 工作台 (`serve`) 与代码统计/基准实验 (`cloc` / `benchmark`)

```bash
openguard serve --host 127.0.0.1 --port 8080 --open
openguard cloc . --json-out loc_stats.json
openguard benchmark --output-dir benchmarks
```

---

## 3. AI 编程助手 MCP Server 接入 (`openguard mcp`)

OpenGuard 内置零额外依赖的 JSON-RPC 2.0 stdio **MCP Server**（暴露 `audit_repository`、`audit_code_snippet`、`check_package_safety`、`generate_pr_comment`、`diagnose_repo_posture`、`evaluate_sbom_quality` 6 项工具），可在 Claude Code / Cursor / Antigravity 的 `mcp.json` 中一键配置：

```json
{
  "mcpServers": {
    "openguard": {
      "command": "openguard",
      "args": ["mcp"]
    }
  }
}
```

---

## 4. 第三方系统集成 / Python SDK 调用方法

OpenGuard 可作为标准 Python 库直接嵌入第三方 DevSecOps 平台、实验评测系统或发布门禁脚本（完整示例见 [examples/third_party_ci_integration.py](../examples/third_party_ci_integration.py)）：

```python
from pathlib import Path
from openguard import OpenGuardAuditor, AuditConfig

config = AuditConfig(
    include_git_history=True,
    offline=True,
    use_cache=True,
    min_confidence=0.45,
)
auditor = OpenGuardAuditor(config)

# 1. 审计本地或远程仓库
report = auditor.audit(Path("./my_project"))
print(f"Score: {report.summary.total_score}, Grade: {report.summary.grade}")

# 2. 导出 PDF / SARIF / CycloneDX / SLSA 报告
auditor.export_report(report, "pdf", Path("report.pdf"))
auditor.export_report(report, "sarif", Path("report.sarif.json"))
auditor.export_report(report, "slsa", Path("slsa_provenance.json"))

# 3. 实时审计内存中的代码片段
snippet_report = auditor.audit_snippet('API_KEY = "AKIA..."', filename="app.py")
```

---

## 5. Policy-as-Code 自定义策略与忽略规则

- **`.openguardignore`**：采用 `.gitignore` 风格 glob 语法，跳过测试靶场、构建产物或第三方目录。
- **`.openguard.yml`**：可配置 `weights`、`use_cache`、`max_workers`、`custom_rules`、`custom_sast_rules` 及声明式 `policy`（`denied_licenses`、`allowed_licenses`、`denied_packages`）。
- **`.openguard/rules/*.yml`**：零代码声明团队专属正则 SAST 策略规则（可运行 `openguard init .` 生成标准模板）。
- **行内豁免注释**：在确认安全的行尾添加 `# openguard: ignore` 或 `// openguard: ignore` 即可精准豁免。
