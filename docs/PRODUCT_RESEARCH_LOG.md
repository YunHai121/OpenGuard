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
- ~~**TruffleHog v3 / Kingfisher / GitGuardian**：离线凭据格式校验~~（已在 Round #2 落地 GitHub/npm CRC32 校验与 GitLab Routable Token 适配）
- ~~**AI Agent / LLM 供应链安全（2026 新赛道）**：Rules-File Backdoor / 隐蔽 Unicode / MCP 配置投毒检测~~（已在 Round #2 落地 `AIConfigSecurityScanner`）
- ~~**SLSA / Sigstore / Cosign / GitHub Artifact Attestations**：构建来源证明（Provenance）、SBOM 完整性签名校验与发布产物防篡改检查~~（已在 Round #4 落地 `slsa_provenance.py` 与 `openguard attest generate|verify`）
- ~~**OSV-SCALIBR / Syft / Grype**：更多生态（`go.sum`、`Gemfile.lock`、`composer.lock`、`.NET *.csproj`、GitHub Actions `uses` 纳入 SBOM 组件图）~~（已在 Round #3 落地 10 生态 SBOM 扩展）
- ~~**SonarQube / CodeQL / Bandit / Semgrep Taint**：Python/JS 跨语句污点传播（Taint Tracking，区分常量字符串与外部用户输入，进一步压低 SAST 误报）~~（已在 Round #4 落地 `PythonTaintAnalyzer`）
- ~~**Web 工作台产品体验对标（Socket / Snyk / Dependency-Track）**：前端实时展示 Call-Graph 可达性徽章、VEX 状态筛选、CI/Dockerfile/AI-Config 分类视图与依赖一键升级面板~~（已在 Round #3 落地）
- **下一阶段新候选方向**：
  - **EPSS / CISA KEV 真实利用优先级（对标 Dependency-Track / Wiz / Grype）**：内置高频 CISA KEV（已知在野利用漏洞）离线清单，将“在野利用 + 函数可达”提升为 P0 最高优先级；
  - **IaC 云原生配置审计（对标 Checkov / Trivy Misconfig / Terrascan）**：扫描 `docker-compose.yml`、Kubernetes YAML (`privileged: true`、`hostNetwork`、`runAsRoot`) 与 Terraform (`0.0.0.0/0` 公网开放、公开 S3 Bucket)；
  - **Custom YAML Rule Engine（对标 Semgrep / Gitleaks 自定义规则包）**：支持团队通过 `.openguard/rules/*.yml` 零代码编写自定义 SAST/合规策略规则。

---

## Round #2 — 2026-11-21 21:28–21:33

### 本轮重点对标产品与行业威胁
- **Pillar Security / Johann Rehberger `aid` / OWASP MCP Top 10 / Invariant Labs `mcp-scan`**：2025–2026 爆发的 **Rules-File Backdoor**、**Unicode Tags (`U+E0000–U+E007F`) 不可见隐写（ASCII Smuggling）**、**Trojan Source 双向控制符（CVE-2021-42574）** 以及 **MCP STDIO 配置投毒 / Rug-Pull 攻击**。
- **GitGuardian / TruffleHog / GitHub Secret Scanning**：基于 **CRC32 + Base62 离线密码学校验和** 消除非生产测试/文档中的伪造 `ghp_`/`gho_`/`npm_` 误报，以及修复现代多段式 **GitLab Routable Token**（含 `.01.` 分隔段）正则截断痛点。

### 核心发现与已落地改进
1. **新增 `AIConfigSecurityScanner`（`openguard/scanners/ai_config_scanner.py`）**，集成至 `OpenGuardAuditor.audit` 与 `audit_snippet`：
   - `OG-AI-001` (CRITICAL, CWE-94)：检测不可见 Unicode Tag Block (`U+E0000–U+E007F`) 隐写，并自动解码输出隐藏 ASCII 载荷预览；
   - `OG-AI-002` (HIGH, CWE-1007)：检测 Trojan Source 双向文本控制符（`U+202A–U+202E`、`U+2066–U+2069` 等）及 AI 规则文件中的高密度零宽字符簇；
   - `OG-AI-003` (HIGH, CWE-77)：检测 `.cursorrules`、`.cursor/rules/*`、`CLAUDE.md`、`AGENTS.md`、`GEMINI.md`、`copilot-instructions.md` 中的隐蔽覆盖指令与 `.env`/`~/.ssh` 外联窃取提示词；
   - `OG-AI-004` (CRITICAL/HIGH/MEDIUM, CWE-78/829/798)：检测 `.mcp.json` / `mcp.json` / `claude_desktop_config.json` 中的危险 Shell/管道命令执行、未锁定版本的 `npx -y` / `uvx` Rug-Pull 风险及 `env` 明文凭据硬编码。
2. **离线密码学 CRC32 校验与多段式 GitLab Token 适配（`openguard/scanners/secret_rules.py` + `secret_scanner.py`）**：
   - 实现 `validate_github_token_crc32`（`zlib.crc32` + 6 位 Base62 校验），挂载至 `OG-SEC-018`（GitHub PAT）、`OG-SEC-020`（GitHub OAuth/App）与 `OG-SEC-024`（npm Token）：校验通过直接提升置信度至 `>=0.96` 并标记 `verified_crc32_checksum`；非生产测试/文档中未通过 CRC32 的伪造 Token 自动降权过滤；
   - 扩展 `OG-SEC-021` 支持 GitLab 17+ 多段式 Routable Token（`glpat-<payload>.<ver>.<crc>`），避免在 `.` 处截断。

### 验证结果
- 新增单元测试文件 `tests/test_v12_ai_and_checksum.py`（6 项核心测试），全量单测增至 **78 / 78 通过**；
- 自身审计：**100.0/100 (A+)**，**Quality Gate: PASSED**（63 文件 / 13024 行，0 告警）。

---

## Round #3 — 2026-11-21 22:28–22:34

### 本轮重点对标产品
- **Anchore Syft / Google OSV-SCALIBR**：将 GitHub Actions 工作流第三方 `uses` 纳入标准 SBOM（`pkg:githubactions/owner/repo@ref`），并扩展多语言精确锁文件解析覆盖面（`go.sum`、`Gemfile.lock`、`composer.lock`、`.NET *.csproj`）。
- **Dependency-Track / Socket.dev / Snyk Web UX**：在 Web 工作台突出“上下文可利用性（VEX + Call-Graph Reachability）”以消除告警疲劳，并提供最小破坏性依赖安全升级 Diff 预览与一键 PR 评论导出。

### 核心发现与已落地改进
1. **10 生态 SBOM 扩展（`openguard/scanners/dependency_parser.py`）**：
   - 新增 **GitHub Actions (`pkg:githubactions`)**、**RubyGems (`Gemfile.lock` / `pkg:gem`)**、**.NET NuGet (`*.csproj` / `pkg:nuget`)**、**Go `go.sum`** 与 **PHP `composer.lock`（含 SPDX 许可证与传递边）** 解析器，生态支持由 7 个扩展至 **10 个**；
   - 顺带加固 `openguard/scanners/vuln_scanner.py` 中 `httpx.Client` 在 Windows `NO_PROXY=[::1]` 环境变量下的容错回退（`trust_env=False`）。
2. **Web 工作台与 API 全功能对齐（`openguard/web/app.py`、`openguard/web/static/index.html`、`app.js`）**：
   - 漏洞溯源面板升级为 **3 级 Call-Graph 可达性 + VEX 状态徽章**（`CALL REACHABLE · VEX: exploitable` / `IMPORT ONLY · VEX: in_triage` / `UNREACHABLE · VEX: not_affected`）并直指真实调用行或依赖清单；
   - 问题溯源视图新增 **`CI / 容器 / AI 安全`** 独立筛选标签，清晰区分 `OG-CI-*`、`OG-DOCKER-*`、`OG-AI-*` 与常规 SAST；
   - AutoFix API 与前端面板新增 **`fix_deps`（一键漏洞依赖最小安全升级 Diff 预览/应用）**；导出菜单新增 **`PR / MR 评审评论 Markdown`**；实时检测台新增 Go 与 `.cursorrules` 场景选项。

### 验证结果
- 新增单元测试 `tests/test_v13_ecosystems_and_web_ux.py` 并通过 `node --check openguard/web/static/app.js` 语法检查，全量单测增至 **80 / 80 通过**；
- 自身审计：**100.0/100 (A+)**，**Quality Gate: PASSED**（63 文件 / 13279 行，0 告警）。

---

## Round #4 — 2026-11-21 23:28–23:34

### 本轮重点对标产品
- **Semgrep Taint Mode / CodeQL / Bandit**：函数内跨语句污点传播（Intraprocedural Dataflow Taint Tracking），通过 `Sources -> Propagators -> Sanitizers -> Sinks` 精准捕获跨变量拼接的 SQL 注入、命令注入、SSRF 与目录穿越，同时自动识别 `int()`/`shlex.quote()`/`os.path.basename()`/`is_relative_to()` 等净化器压低误报。
- **SLSA v1.0 / in-toto Statement v1 / Sigstore / OpenSSF Scorecard**：将“供应链成分（SBOM）”延伸至“构建来源与产物防篡改证明（Provenance Attestation）”，通过 SHA-256 密码学摘要绑定清单文件、Git Commit 与解析后的 10 生态依赖图。

### 核心发现与已落地改进
1. **Python 跨语句 AST 污点传播引擎（`openguard/scanners/taint_analyzer.py`，接入 `CodeSecurityScanner`）**：
   - 支持追踪 `request.args/form/json/values/cookies/headers`、`input()`、`sys.argv` 等外部不可信源经变量赋值、f-string、字符串拼接与 `os.path.join` 传播至 4 大高危汇点：
     - `OG-TAINT-PY-001` (CRITICAL, CWE-89)：跨语句 SQL 注入；
     - `OG-TAINT-PY-002` (CRITICAL, CWE-78)：跨语句 OS 命令注入；
     - `OG-TAINT-PY-003` (HIGH, CWE-918)：服务端请求伪造（SSRF）；
     - `OG-TAINT-PY-004` (HIGH, CWE-22)：目录穿越 / 任意文件访问；
   - 内置 12+ 常见净化器（`int`/`float`/`shlex.quote`/`os.path.basename`/`Path.name`/`html.escape`/`is_relative_to`/`sanitize_*`）自动消除安全代码误报。
2. **SLSA v1.0 / in-toto 供应链证明与防篡改校验（`openguard/reporters/slsa_provenance.py`）**：
   - 新增 `--format slsa`（同步纳入 `--format all` 与 Web `/api/export/{scan_id}/slsa`），输出符合 `https://in-toto.io/Statement/v1` 与 `https://slsa.dev/provenance/v1` 规范的 JSON 证明，内置所有清单文件 SHA-256 摘要、Git Commit 与 SBOM `resolvedDependencies`；
   - 新增 CLI 命令 `openguard attest generate|verify`，可离线核验清单文件是否被篡改（Digest Mismatch 检测）。

### 验证结果
- 新增 `tests/test_v14_taint_and_slsa.py`，更新 `test_export_report_all_formats_to_disk`（9 类导出产物），全量单测增至 **83 / 83 通过**；
- 自身审计：**100.0/100 (A+)**，**Quality Gate: PASSED**。
