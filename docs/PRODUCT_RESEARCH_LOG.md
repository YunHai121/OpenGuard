# OpenGuard 持续竞品调研与产品迭代日志 (Product Research Log)

本日志由 OpenGuard 每小时持续产品调研与迭代流程自动维护，记录每轮对标同类开源/商业产品的核心发现、差距分析与实际落地的产品改进，确保“集他人之所长、补己之短”持续闭环、不重复造轮子。

---

## Round #1 — 2026-11-21 20:30–20:55 (对应发布版本 `v1.2.0`)

### 本轮重点对标产品
- **OpenSSF Scorecard / Zizmor**（CI/CD 供应链安全、Actions 40 位 SHA 锁定、`GITHUB_TOKEN` 最小权限）
- **Socket.dev**（函数级可达性降噪、AI 幻觉包 Slopsquatting 防护、AI Coding Agent 防线）
- **Trivy / OSV-Scanner**（现代锁文件解析、CycloneDX VEX 可利用性声明、Dockerfile 静态安全）
- **Semgrep / Gitleaks / Snyk**（Diff-Aware PR 增量扫描、Baseline 存量债豁免、PR 评审评论、漏洞依赖自动升级、`.pre-commit-hooks.yaml`）

### 核心发现与已落地改进 (`v1.2.0`)
1. 新增 `CIWorkflowScanner`（`OG-CI-001`–`OG-CI-006`），并将 OpenGuard 自身 `.github/workflows/openguard.yml` 加固为全 40 位 SHA 锁定 + 最小权限 + GitHub Code Scanning SARIF 上传。
2. 升级 `ReachabilityAnalyzer` 至 **Call-Graph 函数调用级可达性**（`call_reachable` / `import_only` / `unreachable`），自动在 CycloneDX 1.5 输出 VEX `analysis` 区块（`exploitable` / `in_triage` / `not_affected` + `code_not_reachable`），并修复 SARIF 漏洞定位及评分引擎不可达降权。
3. 新增 `uv.lock`、`poetry.lock`、`yarn.lock`、`pnpm-lock.yaml` 解析器、`DockerfileScanner`（`OG-DOCKER-001`–`OG-DOCKER-005`）及 Go SAST 规则（`OG-SAST-GO-001`–`003`）。
4. 新增 `--diff <base_ref>` 增量扫描、`openguard baseline create` / `--baseline` 基线机制、`--format pr-comment` 及全文件 AST 上下文修复的 `--staged` 扫描。
5. 新增 `openguard autofix --deps` 安全依赖自动升级（`requirements*.txt` / `pyproject.toml` / `package.json`）。
6. 新增零依赖 JSON-RPC 2.0 MCP Server（`openguard mcp`，暴露 4 个面向 AI 编程助手的安全工具）与 `.pre-commit-hooks.yaml`。

### 验证结果
- 全量单元测试：**72 / 72 通过**；
- 自身审计：**100.0/100 (A+)**，**Quality Gate: PASSED**。

### 下一轮候选调研方向（待每小时逐步深化）
- **TruffleHog v3 / Kingfisher / GitGuardian**：离线凭据格式校验（checksum/prefix/length，如 GitHub Fine-Grained PAT / AWS / Stripe / Slack / PyPI token CRC 校验）与低误报凭据分类；
- **SLSA / Sigstore / Cosign / GitHub Artifact Attestations**：构建来源证明（Provenance）、SBOM 完整性签名校验与发布产物防篡改检查；
- **OSV-SCALIBR / Syft / Grype**：更多生态（`go.sum`、`Gemfile.lock`、`composer.lock`、`.NET *.csproj / packages.lock.json`、GitHub Actions `uses` 纳入 SBOM 组件图）；
- **SonarQube / CodeQL / Bandit / Semgrep Taint**：Python/JS 跨语句污点传播（Taint Tracking，区分常量字符串与外部用户输入，进一步压低 SAST 误报）；
- **Web 工作台产品体验对标（Socket / Snyk / Dependency-Track）**：前端实时展示 Call-Graph 可达性徽章、VEX 状态筛选、CI/Dockerfile 分类视图与依赖一键升级面板；
- **AI Agent / LLM 供应链安全（2026 新赛道）**：检测仓库内 `.cursorrules` / `CLAUDE.md` / `AGENTS.md` / MCP 配置中的 **Indirect Prompt Injection（隐蔽 Unicode 零宽字符/双向控制字符投毒、恶意外联指令）**（对标 2026 年爆发的 Rules-File Backdoor 攻击！）。
