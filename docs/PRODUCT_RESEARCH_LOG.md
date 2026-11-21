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
  - ~~**EPSS / CISA KEV 真实利用优先级（对标 Dependency-Track / Wiz / Grype）**~~（已在 Round #5 落地 KEV/EPSS 情报库与 P0–P3 风险分级矩阵）
  - ~~**IaC 云原生配置审计（对标 Checkov / Trivy Misconfig / Terrascan）**~~（已在 Round #5 落地 `IaCScanner`：`docker-compose` / Kubernetes / Terraform）
  - ~~**Custom YAML Rule Engine（对标 Semgrep / Gitleaks 自定义规则包）**~~（已在 Round #6 落地 `PolicyEngine`）
  - ~~**Dependency License & Supply-Chain Policy Engine（对标 OPA / FOSSA / Socket Policy）**~~（已在 Round #6 落地 `policy.denied_licenses` / `allowed_licenses` / `denied_packages`）
  - ~~**HTML / PDF 报告同步升级**~~（已在 Round #6 落地 Quality Gate 门禁表与 P0–P3 KEV/EPSS/可达性徽章）
- **下一阶段新候选方向（v1.3.0 规划）**：
  - ~~**OpenSSF Scorecard / Supply-Chain 仓库健康度体检扩展**~~（已在 Round #7 落地锁文件防篡改/降级守卫 + `.github/dependabot.yml` + `.github/CODEOWNERS`）
  - ~~**多进程/线程池并发扫描加速**~~（已在 Round #7 落地 `ThreadPoolExecutor` 自适应并发扫描）
  - ~~**版本发布整理 (`v1.3.0`)**~~（已在 Round #7 打标发布 `v1.3.0`）
- **v1.4.0 下一阶段候选调研方向**：
  - **GitHub / GitLab / Gitee 真实开源仓库压测与误报微调**：在真实开源项目上批量实测 OpenGuard v1.3.0，收集边缘语法/误报案例反哺规则精度；
  - ~~**JavaScript / TypeScript 跨语句污点分析（对标 Semgrep JS / CodeQL）**~~（已在 Round #8 落地 `JSTaintAnalyzer`：`OG-TAINT-JS-001`–`005`）
  - ~~**增量文件哈希缓存（对标 Ruff `.ruff_cache` / ESLint `--cache` / Semgrep）**~~（已在 Round #8 落地 `IncrementalScanCache` + `--cache`）
  - **Rust / Java / C++ SAST 扩展（`unsafe` 审计、`Runtime.getRuntime().exec`、`strcpy`/`sprintf`）**；
  - **OpenTelemetry / JSONL 流式结构化日志与批量多仓组合审计（Portfolio / Org-Level Audit）**。

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

---

## Round #5 — 2026-11-22 00:28–00:34

### 本轮重点对标产品
- **OWASP Dependency-Track / Anchore Grype / Wiz（基于真实利用风险的 RBVM 分级）**：突破纯 CVSS 静态分数的告警疲劳，融合 **CISA KEV（已知在野利用漏洞）**、**EPSS（30 天在野利用概率）** 与 **源码函数级可达性**，将漏洞自动划分为 `P0`–`P3` 四个处置梯队（最高可压降 90% 无效整改排期）。
- **Checkov / Trivy `trivy config`（云原生 IaC 误配置审计）**：一站式静态审计 `docker-compose.yml`、Kubernetes 工作负载清单与 Terraform HCL，拦截特权容器、宿主机 `docker.sock` 挂载、公网 `0.0.0.0/0` 暴露与未加密存储。

### 核心发现与已落地改进
1. **CISA KEV & EPSS 风险优先级矩阵（`models.py` + `vuln_scanner.py` + `reachability_analyzer.py` + CycloneDX / PR Comment / Web UI）**：
   - 在 `VulnerabilityFinding` 新增 `in_cisa_kev`、`epss_score`、`priority_tier`（`P0`–`P3`）字段，内置高频开源漏洞离线 CISA KEV 与 EPSS 情报库；
   - 结合函数级可达性自动计算 `P0`（可达 + KEV / EPSS≥0.5 / Critical）至 `P3`（未导入且非 KEV，可 VEX 延后），并同步透出至 CycloneDX 1.5 `properties`、PR 评论 Markdown 与 Web 工作台徽章。
2. **云原生 IaC 静态安全审计器（`openguard/scanners/iac_scanner.py`，接入 `OpenGuardAuditor` 与 Web 工作台）**：
   - **Docker Compose**：`OG-IAC-001`（`privileged: true`）、`OG-IAC-002`（挂载 `/var/run/docker.sock`）、`OG-IAC-003`（`network_mode: host` 与敏感 DB 端口绑定 `0.0.0.0`）；
   - **Kubernetes YAML**：`OG-IAC-004`（特权容器/提权）、`OG-IAC-005`（`hostNetwork/hostPID/hostIPC`）、`OG-IAC-006`（`runAsUser: 0` / `runAsNonRoot: false`）；
   - **Terraform HCL (`*.tf`)**：`OG-IAC-007`（入站 `0.0.0.0/0`）、`OG-IAC-008`（公网 S3 Bucket）、`OG-IAC-009`（禁用加密 `encrypted = false`）。

### 验证结果
- 新增 `tests/test_v15_kev_epss_and_iac.py` 并通过 `node --check openguard/web/static/app.js`，全量单测增至 **85 / 85 通过**；
- 自身审计：**100.0/100 (A+)**，**Quality Gate: PASSED**。

---

## Round #6 — 2026-11-22 01:28–01:34

### 本轮重点对标产品
- **Semgrep YAML Rules / FOSSA / Open Policy Agent (OPA)**：声明式策略即代码（Policy-as-Code），让研发与法务团队无需修改扫描器源码即可通过 YAML 自定义企业内部代码规范、许可证黑白名单与禁用组件清单。
- **Snyk / FOSSA / SonarQube 合规报告交付标准**：面向管理层与评审专家的离线单文件 HTML/PDF 报告必须首屏给出确定性 Quality Gate 门禁判定、P0–P3 优先级（含 KEV/EPSS/可达性）与清晰的问题分类。

### 核心发现与已落地改进
1. **声明式 Policy-as-Code 与自定义 YAML 规则引擎（`openguard/scanners/policy_engine.py`，接入 `AuditConfig` 与 `OpenGuardAuditor`）**：
   - 自动加载仓库 `.openguard/rules/*.{yml,yaml}` 与 `.openguard.yml` 中的 `custom_sast_rules`，支持 `pattern`、`paths`、`exclude_paths`、`severity`、`cwe` 与行内 `openguard: ignore` 豁免；
   - 支持 `.openguard.yml` 中声明式 `policy:` 块：`denied_licenses`（许可证黑名单）、`allowed_licenses`（严格许可证白名单）与 `denied_packages`（禁用包 P0 强阻断）。
2. **离线 HTML 与中文 PDF 审计报告同步升级（`html_reporter.py` + `pdf_reporter.py`）**：
   - HTML 报告升级漏洞卡片呈现 `[P0-P3]` 优先级 + Call-Graph 可达性 + CISA KEV + EPSS %，并为 CI/CD、Dockerfile、IaC、AI 安全、污点追踪与自定义策略呈现独立分类徽章；
   - PDF 报告首屏新增 **Quality Gate 门禁判定汇总表**（5 项硬性门禁逐项展示），漏洞清单列升级为 `优先级 / 可达性 (P0-P3 / KEV)`。

### 验证结果
- 新增 `tests/test_v16_policy_and_reports.py`，全量单测增至 **86 / 86 通过**；
- 自身审计：**100.0/100 (A+)**，**Quality Gate: PASSED**。

---

## Round #7 — 2026-11-22 02:28–02:34（里程碑发布 `v1.3.0`）

### 本轮重点对标产品
- **OpenSSF Scorecard（`Dependency-Update-Tool` / `CODEOWNERS` / Lockfile `sha512` Integrity）**：自动化依赖更新工具配置、关键路径代码审查归属以及锁文件完整性哈希校验，防止注册表中间人降级与锁文件投毒攻击。
- **Semgrep / Gitleaks / TruffleHog 大仓并发架构**：采用进程内多线程（共享内存、避免 Windows 进程派生开销）在不破坏确定性排序的前提下加速大型单仓扫描。

### 核心发现与已落地改进（整合发布 `v1.3.0`）
1. **锁文件防篡改与降级守卫（`openguard/scanners/install_script_scanner.py`）+ OpenSSF 卫生加固**：
   - 新增 `OG-SUP-LOCK-001`（CRITICAL）：检出 `package-lock.json` 中被篡改降级为明文 `http://` 的包下载地址；
   - 新增 `OG-SUP-LOCK-002`（HIGH）：检出缺失 `integrity` 哈希或降级为弱 `sha1` 的远端依赖；
   - 为 OpenGuard 仓库自身补齐 `.github/dependabot.yml`（覆盖 `pip` 与 `github-actions`）与 `.github/CODEOWNERS`。
2. **自适应多线程并发扫描（`secret_scanner.py` + `code_security_scanner.py` + `config.py`）**：
   - 当扫描文件数 ≥ 16 时自动启用 `ThreadPoolExecutor`（支持 `.openguard.yml` `max_workers` 配置），保持与单线程完全一致的确定性结果顺序。
3. **正式整合发布 `OpenGuard v1.3.0`**：
   - 同步版本号至 `1.3.0`（`pyproject.toml`、`__init__.py`、`models.py`），汇总 Round #2–#7 全部能力更新至 `README.md`、`CHANGELOG.md` 并打标 `v1.3.0`。

### 验证结果
- 新增 `tests/test_v17_lockfile_integrity_and_perf.py`（含 24 文件多线程 vs 单线程确定性一致校验），全量单测增至 **89 / 89 通过**；
- 自身审计：**100.0/100 (A+)**，**Quality Gate: PASSED**，已打标 `v1.3.0` 并双仓同步。

---

## Round #8 — 2026-11-22 03:28–03:34

### 本轮重点对标产品
- **Semgrep JS / GitHub CodeQL（Express / Next.js / Node.js 跨语句污点追踪）**：针对前端/Node 全栈项目，追踪 `req.query` / `req.body` / `req.params` / 解构赋值流入 `child_process.exec`、`res.send`、`fetch`/`axios`、`fs.readFile` 与动态属性写入（原型链污染），并识别 `DOMPurify.sanitize`、`path.basename`、`__proto__` 守卫以压低误报。
- **Ruff `.ruff_cache` / ESLint `--cache`（内容哈希增量扫描缓存）**：突破易受 `git checkout` 影响的 `mtime` 缓存，以 `SHA-256(文件内容 + 配置指纹 + 工具版本)` 作为复合缓存键，实现零脏缓存的亚秒级增量二次扫描。

### 核心发现与已落地改进
1. **JavaScript / TypeScript 跨语句污点分析引擎（`openguard/scanners/js_taint_analyzer.py`，接入 `CodeSecurityScanner`）**：
   - 支持追踪 Express/Next.js 外部输入与解构变量，检出 5 类高危数据流漏洞：
     - `OG-TAINT-JS-001` (CRITICAL, CWE-78)：Node.js `child_process.exec/execSync` 命令注入；
     - `OG-TAINT-JS-002` (HIGH, CWE-79)：反射/DOM XSS；
     - `OG-TAINT-JS-003` (HIGH, CWE-918)：出站 `fetch`/`axios` SSRF；
     - `OG-TAINT-JS-004` (HIGH, CWE-22)：`fs` 目录穿越；
     - `OG-TAINT-JS-005` (HIGH, CWE-1321)：动态属性键原型链污染；
   - 自动识别 `DOMPurify.sanitize`、`escapeHtml`、`path.basename`、`startsWith` 与 `__proto__` 校验守卫。
2. **内容哈希增量文件扫描缓存（`openguard/utils/scan_cache.py` + `cli.py` `--cache`）**：
   - 在 `<repo>/.openguard_cache/scan_cache.json` 持久化每文件密钥与 SAST 扫描结果；内容变更、配置指纹变更或版本升级均自动失效重扫；同步将 `.openguard_cache/` 加入默认排除目录与 `.gitignore`。

### 验证结果
- 新增 `tests/test_v18_js_taint_and_cache.py`（3 项专项测试），全量单测增至 **92 / 92 通过**；
- 自身审计：**100.0/100 (A+)**，**Quality Gate: PASSED**。
