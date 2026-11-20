# OpenGuard 安装、运行与第三方集成使用文档

## 1. 环境要求与安装

- **操作系统**：Windows 10/11、Linux (Ubuntu/Debian/CentOS)、macOS
- **Python 版本**：`>= 3.10`（已验证支持至 Python 3.14）
- **可选工具**：`git`（仅启用 `--git-history`、`--staged` 或远程 URL 扫描时需要）

### 本地源码安装

```bash
git clone <repository-url> OpenGuard
cd OpenGuard
pip install -r requirements.txt
pip install -e . --no-build-isolation --no-deps
```

验证安装成功：

```bash
openguard version
```

---

## 2. 命令行 (CLI) 核心用法

### 2.1 全维度项目审计 (`scan`)

```bash
# 扫描本地项目并在终端展示 5 维得分与风险详情
openguard scan examples/vulnerable_demo_repo --offline

# 回溯 Git 提交历史（捕获已从最新代码中删除的历史幽灵密钥）
openguard scan path/to/git_repo --git-history --max-commits 100

# 一键导出全套报告 (HTML / PDF / JSON / SARIF / CycloneDX / SPDX / Markdown / SVG 徽章)
openguard scan examples/vulnerable_demo_repo --offline --format all --output demo_outputs/demo_audit

# 扫描远程 Git 仓库并设置 CI 门禁阈值
openguard scan https://git.hust.edu.cn/owner/project.git --fail-on high
```

### 2.2 一键脱敏重构与文档生成 (`autofix`)

```bash
# 默认 Dry-Run 预览修改 Unified Diff（不改动原文件）
openguard autofix path/to/repo --secrets --docs --license MIT

# 确认应用修改（自动备份源文件至 .openguard_backup/ 并生成 .env.example）
openguard autofix path/to/repo --secrets --docs --license MulanPSL-2.0 --apply
```

### 2.3 SBOM 物料清单导出 (`sbom`)

```bash
openguard sbom . --spec cyclonedx -o sbom.cdx.json
openguard sbom . --spec spdx -o sbom.spdx.json
```

### 2.4 本地 Pre-commit 防线与 CI/CD 模板 (`hook`)

```bash
# 安装提交前实时防泄露拦截钩子
openguard hook install .

# 生成适配校内 git.hust.edu.cn 的 GitLab CI 流水线
openguard hook ci . --ci-platform gitlab
```

### 2.5 启动可视化 Web 工作台 (`serve`)

```bash
openguard serve --host 127.0.0.1 --port 8080 --open
```

### 2.6 有效代码行数统计与性能对比实验 (`cloc` / `benchmark`)

```bash
openguard cloc . --json-out loc_stats.json
openguard benchmark --output-dir benchmarks
```

---

## 3. 第三方系统集成 / Python SDK 调用方法

OpenGuard 可作为标准 Python 库直接嵌入第三方 DevSecOps 平台、实验评测系统或发布门禁脚本（完整示例见 [examples/third_party_ci_integration.py](../examples/third_party_ci_integration.py)）：

```python
from pathlib import Path
from openguard import OpenGuardAuditor, AuditConfig

config = AuditConfig(
    include_git_history=True,
    offline=True,
    min_confidence=0.45,
)
auditor = OpenGuardAuditor(config)

# 1. 审计本地或远程仓库
report = auditor.audit(Path("./my_project"))
print(f"Score: {report.summary.total_score}, Grade: {report.summary.grade}")

# 2. 导出 PDF / SARIF / CycloneDX 报告
auditor.export_report(report, "pdf", Path("report.pdf"))
auditor.export_report(report, "sarif", Path("report.sarif.json"))

# 3. 实时审计内存中的代码片段
snippet_report = auditor.audit_snippet('API_KEY = "AKIA..."', filename="app.py")
```

---

## 4. 自定义策略与忽略规则配置

- **`.openguardignore`**：采用与 `.gitignore` 类似的 glob 路径语法，跳过测试靶场、生成产物或第三方目录。
- **`.openguard.yml`**：可配置 `weights`（五维权重）、`min_confidence`、`entropy_threshold` 及 `custom_rules`（自定义企业/高校内部正则检测规则）。
- **行内豁免注释**：在确认安全的行尾添加 `# openguard: ignore` 或 `// openguard: ignore` 即可跳过告警。
