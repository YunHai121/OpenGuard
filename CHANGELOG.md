# Changelog

All notable changes to **OpenGuard (开源卫士)** are documented in this file following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and Semantic Versioning.

## [Unreleased]

### Fixed & Hardened
- **`--staged` 暂存区增量审计生效修复与 HTML 报告分类标签完善（Round #31）**：
  - 修复 `OpenGuardAuditor._audit_local_path()` 未消费 `cfg.staged_only` 导致 `openguard scan . --staged`（含 `pre-commit` 钩子）全量扫描工作区而非仅拦截暂存区变更的核心缺陷；
  - 为 `SecretScanner.scan_diff_lines()` 的 `git show` 补充 15 秒超时保护，并在 `html_reporter.py` 补全 `OG-ML-`（`ML 模型安全`）与 `OG-HYG-`（`敏感产物卫生`）分类徽章。
- **Git 历史幽灵密钥中文路径解析与超时保护、`.gitignore` 模板完善（Round #30）**：
  - 修复 `GitHistoryScanner.scan_history()` 缺少 `-c core.quotepath=false` 导致中文历史文件名被转义及 `+++ /dev/null` 未重置 `current_file` 的问题，并补充 60 秒子进程超时与异常兜底；
  - 完善 `DocGenerator.GITIGNORE_TEMPLATE` 覆盖 `.pypirc`、`.netrc`、`*.jks`、`*.keystore`、`*.ppk`、`*.ovpn`。
- **增量缓存中文路径编码崩溃修复与 `.mjs`/`.cjs` SAST 扩展（Round #29）**：
  - 修复 `scan_cache.compute_file_cache_key()` 使用 `.encode("ascii")` 导致开启 `--cache` 扫描含中文/Unicode 文件名仓库时抛出 `UnicodeEncodeError` 的崩溃缺陷（改为 UTF-8）；
  - 扩展 `CodeSecurityScanner` 覆盖 `.mjs` 与 `.cjs` 现代 Node.js 模块的 SAST 与跨语句污点扫描。
- **`openguard cloc` Python 三引号文档字符串与 `.github` 目录统计修复（Round #28）**：
  - 修复 `loc_counter.count_file_loc()` 因 `("'''", '"""')` 起始/结束符判定逻辑缺陷导致 `"""..."""` 文档字符串未计入注释行及 `'''...'''` 多行文档字符串无法闭合的统计错误；
  - 修复 `count_repository_loc()` 使用 `not d.startswith(".git")` 误跳过 `.github/workflows` 的问题（改为精确排除 `.git`）。
- **2025–2026 CVE Call-Graph 可达性映射与评分权重边界保护（Round #27）**：
  - 为 `ReachabilityAnalyzer.VULNERABLE_CVE_SYMBOLS` 补全 `CVE-2026-67319`/`CVE-2026-67313`（Axios）与 `CVE-2025-55182`/`CVE-2025-66478`（React RSC/Next.js）危险调用符号，精准触发函数级 `call_reachable` 与 CycloneDX VEX `exploitable` 研判；
  - 加固 `ScoringEngine` 权重归一化逻辑，支持部分维度覆盖并防止负数或全零权重导致总分失真。
- **Git Diff 增量行号解析与多仓批量审计配置继承修复（Round #26）**：
  - 修复 `baseline.get_git_diff_added_lines()` 在遇到已删除文件（`+++ /dev/null`）未重置 `current_file` 及 Windows 下中文路径八进制转义（补充 `-c core.quotepath=false`）的缺陷；
  - 修复 `PortfolioAuditor.audit_repositories()` 未加载各子仓库 `.openguard.yml` 完整配置（权重/阈值/策略）的问题。
- **PyPI PEP 503 仿冒误报消除、OSV 分批查询与依赖修复路径防穿越（Round #25）**：
  - 修复 `VulnScanner` 对 PyPI 等价命名（如 `python_dotenv` vs `python-dotenv`）误报为 1-编辑距离 Typosquatting 的问题，并将在线 `OSV.dev` 批量查询升级为按 60 组件自动分块遍历，避免大仓截断；
  - 为 `DependencyRemediator` 补充 `fpath.is_relative_to(root)` 路径穿越防护。
- **npm 内联/联动脚本链追踪与 Policy PEP 503 包名归一化（Round #24）**：
  - 扩展 `InstallScriptScanner` 支持拦截 `package.json` 生命周期钩子内的 `node -e` / `python -c` 高危内联执行，以及联动调用的本地 `.sh` / `.py` 窃密与 AI CLI 劫持脚本；
  - 修复 `PolicyEngine` `denied_packages` 未对 PyPI 包名执行 PEP 503（`-`/`_`/`.`）归一化导致策略绕过的边界缺陷。
- **自动脱敏重构 RHS 精确定位与敏感私钥文件卫生加固（Round #23）**：
  - 修复 `SecretRemediator` 处理 Python 字典/JSON 键值对（如 `"openai_api_key": "sk-..."`）时误将左侧键名当作密钥替换导致语法破坏的缺陷，并新增 `.env*` 未加引号凭据值的自动脱敏重构支持；
  - 扩展 `IaCScanner` 敏感提交物防线（`OG-HYG-001`）覆盖 `privkey.pem`、`private.pem`、`private.key`、`id_rsa.key` 与 `*.ovpn`（继续放行 `ca.pem` 等公共证书）。
- **多阶段 Dockerfile 审计、SQLite WAL 并发与 PDF 报告健壮性修复（Round #22）**：
  - 修复 `DockerfileScanner` 多阶段构建未在新 `FROM` 阶段重置 `USER` 导致最终 `root` 阶段漏报 `OG-DOCKER-002`、误报 `FROM <stage_alias>` 为未锁镜像以及带端口私有仓库（`registry:5000/org/app`）漏报 `OG-DOCKER-001` 的缺陷；
  - 为 `AuditHistoryStore` 启用 SQLite `WAL` 模式、`busy_timeout=5000` 与异常 `rollback()` 保护，提升 Web 并发读写稳定性；
  - 修复 `pdf_reporter.py` 在 `dimensions` 为空时 ReportLab 图表崩溃的边界隐患，并在中文 PDF 报告新增第 7 节 **EU CRA / NIST SSDF / OWASP SCVS 国际供应链合规映射表**。
- **CycloneDX `bom-ref` 一致性与 GitLab CI 安全规则加固（Round #21）**：
  - 修复 `render_cyclonedx()` 当组件缺少 `purl` 时 `dependencies[].dependsOn` / `vulnerabilities[].affects[].ref` 与 `components[].bom-ref` 不一致的缺陷，并更新 SARIF `informationUri` 为校内仓库地址；
  - 修复 `CIWorkflowScanner._scan_gitlab_ci()` 漏报未指定标签镜像（如 `image: python`，隐式等同 `:latest`）的问题，并补齐 GitLab CI `OG-CI-008`（`printenv | base64` / `env | base64` 日志凭据转储）检测。
- **ML Pickle 反序列化与 AIBOM 覆盖盲区修复（Round #20）**：
  - 修复 `MLModelScanner.inspect_pickle_bytes()` 未追踪 `MEMOIZE`/`BINPUT`/`BINGET` 备忘录操作码导致协议 4/5 备忘录混淆 `STACK_GLOBAL` 绕过的问题，并补充 `marshal.loads` / `types.FunctionType` 高危原语；
  - 修复 `aibom.py` 受默认 `*.bin` 排除规则影响跳过 `pytorch_model.bin` 等 PyTorch 二进制权重的问题，新增 PyTorch/Pickle `.bin` 头识别与 `grok-*` 模型支持。
- **跨 Python 版本（3.10–3.14）与校内 GitLab CI（`git.hust.edu.cn`）稳定性加固**：
  - 修复 `load_config()` / `load_ignore_patterns()` 传入 `str` 路径时报 `TypeError` 的边界缺陷；
  - 修复 `OpenGuardAuditor._audit_remote_repo()` 临时目录清理使用 Python 3.12 专属 `shutil.rmtree(..., onexc=...)` 导致 Python 3.11 CI 报错的兼容问题，改为 `_safe_rmtree()` 跨版本兼容；
  - 为 `dependency_parser.py` / `license_analyzer.py` 增加 Python 3.10 `tomli` 回退与守卫（同步更新 `pyproject.toml`）；
  - 修复 `OpenGuardAuditor._audit_local_path()` 在复用实例或通过 `MCP Server` / `Web AutoFix` / `cli sbom` / `cli compliance` 调用时忽略 `.openguard.yml` 策略配置或原地修改 `base_config` 的问题；
  - 修复 Windows 下 `mcp_server.run_stdio_server()` 与 `cli` stderr 的 UTF-8 编码兼容，并为 `autofix`/`baseline`/`attest`/`sbom`/`sbom-diff`/`sbom-score`/`cloc`/`batch` 补齐无效路径退出码 `2` 校验；
  - 清理 `requirements.txt` 中未使用的 `python-docx` 依赖以加速 `git.hust.edu.cn` `python:3.11-slim` CI 构建，升级 `.gitlab-ci.yml` 增加合规与态势体检门禁，并修复 `HookInstaller` 生成的 GitHub Actions 模板 40 位 SHA 锁定与 pre-commit 提示参数错误（移除不存在的 `--dry-run`）。

### Added
- **Web 工作台 AIBOM 资产台账与导出对齐（Round #20）**：Web 总览页新增 **CycloneDX 1.6 AIBOM 资产台账面板**，导出菜单与后端同步新增 `/api/export/{scan_id}/aibom`；
- **Web 工作台与导出接口对齐**：Web 导出菜单新增 `SLSA v1.0 完整度证明` 与 `EU CRA / NIST SSDF 合规报告 (JSON)`（`/api/export/{scan_id}/compliance`），`AutofixRequest` 支持 `allow_major` 开关并返回 `breaking_warnings`/`skipped_breaking`，修复版本徽章动态同步与 `OG-ML-`/`OG-HYG-`/`OG-TAINT-` 分类标签映射。
- **CycloneDX 1.6 AI 物料清单 (AIBOM / ML-BOM) 静态发现引擎 (`aibom.py` + `openguard aibom` + `/api/aibom`)**：对标 OWASP CycloneDX 1.6 与 `cdxgen aibom`，零执行静态发现仓库内 SafeTensors/GGUF/ONNX/PyTorch 本地模型权重（带 SHA-256 摘要与安全格式标识）、HuggingFace 模型/数据集调用（含 `revision` 锁定检查）与主流 LLM API 调用，输出标准 CycloneDX 1.6 ML-BOM JSON（含 `modelCard`）。
- **Web 工作台国际合规映射面板 (`index.html` + `app.js`)**：在总览页自动展示 EU CRA / NIST SSDF / OWASP SCVS 8 项合规控制项达标率与证据。
- **AI/ML 模型权重反序列化扫描器与 ML 框架 SAST（对标 Protect AI ModelScan / Fickling / OWASP LLM03）**：新增零依赖、零执行静态反汇编引擎 `MLModelScanner`（`OG-ML-001`，支持原始 Pickle 协议 0–5 与 PyTorch ZIP 权重内 `data.pkl`），以及 `torch.load` 缺 `weights_only=True`（`OG-SAST-ML-001`）、HuggingFace `trust_remote_code=True`（`OG-SAST-ML-002`）与 `np.load(allow_pickle=True)`（`OG-SAST-ML-003`）AST 审计规则。
- **MCP Server 扩展至 7 项工具**：新增 `evaluate_compliance`，向 AI 编程助手直接暴露 EU CRA / NIST SSDF / OWASP SCVS 合规评估能力。
- **EU CRA / NIST SSDF / OWASP SCVS 供应链合规映射引擎 (`compliance.py` + `openguard compliance` + `/api/compliance/{scan_id}`)**：对标 Endor Labs / Trivy 合规体系，自动将 SBOM NTIA 评分、Call-Graph VEX 研判、CISA KEV、`SECURITY.md`、零凭据泄露与 SAST/IaC 防线映射为 8 项国际监管控制项（`OG-CMP-01`–`08`），支持 `--json`、Markdown 导出、`--fail-on-noncompliant` 门禁及内嵌至审计报告第 9 节。
- **敏感提交产物与容器镜像凭据打包防线 (`OG-HYG-001` / `OG-HYG-002` / `OG-DOCKER-006`)**：拦截误提交的二进制证书库（`.p12`/`.pfx`/`.jks`/`.keystore`）、SSH 私钥、`.pypirc`/`.netrc`、运行时 `.env`（自动放行模板文件）以及 Dockerfile `COPY`/`ADD` 凭据打包进镜像层。
- **6 生态依赖自动安全升级与跨主版本保护 (`DependencyRemediator` + `openguard autofix --deps --no-major`)**：对标 OSV-Scanner V2 Guided Remediation 与 Renovate，在原有 PyPI/npm 基础上新增 `go.mod`、`Cargo.toml` 与 `pom.xml` 自动升级支持，内置 `[BREAKING MAJOR]` 破坏性主版本预警与 `--no-major` 跳过保护。
- **可复现密钥检测基准集扩容至 260 条 (`benchmarks/`)**：新增 OpenRouter/xAI 密钥、Supabase `service_role` vs 公开 `anon` JWT、真/假 Base62 CRC32 GitHub PAT 样本，实测保持 `F1 = 1.0000 / FPR = 0.0000`（纯正则基线 FPR 为 `67.86%`）。
- **GuardDog / Shai-Hulud / s1ngularity / tj-actions 2025–2026 供应链蠕虫行为防线 (`InstallScriptScanner` & `CIWorkflowScanner`)**：新增 Python `.pth` 启动持久化后门检测（`OG-SUP-PY-002`）、`setup.py` `cmdclass` 覆写与凭据外传关联检测（`OG-SUP-PY-003`）、npm `postinstall` 联动本地 JS 脚本追踪以拦截 s1ngularity/Nx 风格 AI CLI 越权劫持（`OG-SUP-NPM-004`）与凭据外发（`OG-SUP-NPM-005`），以及 `tj-actions`/`reviewdog` 可变标签投毒告警（`OG-CI-007`, `CRITICAL`）和 CI 日志凭据转储拦截（`OG-CI-008`）。

## [1.4.0] - 2026-11-22

### Added
- **2025–2026 AI 网关/云原生凭据检测扩容（46 → 54 条）与 Supabase JWT 角色智能判别（对标 GitHub Secret Scanning / TruffleHog / Kingfisher / GitGuardian）**：新增 OpenRouter (`OG-SEC-045`)、xAI Grok (`OG-SEC-046`)、Perplexity (`OG-SEC-047`)、Vercel Blob (`OG-SEC-048`)、LangSmith (`OG-SEC-049`)、Linear (`OG-SEC-050`)、Supabase Secret/PAT (`OG-SEC-044`) 与 Anthropic Admin/OAuth 扩展支持，扩展国产大模型上下文词表（豆包/火山方舟 Ark/混元/阶跃星辰/Mistral/Cohere）；解码 JWT 载荷精准区分 `service_role` 致命管理员泄露（`OG-SEC-043`, `CRITICAL`）与客户端公开 `anon` Key（零误报抑制）。
- **MCP Server 6 工具扩容与 Web 工作台态势/SBOM 质量面板（对标 Snyk/Semgrep MCP & Dependency-Track v5）**：`openguard mcp` 新增 `diagnose_repo_posture`（7 项仓库防线自检）与 `evaluate_sbom_quality`（NTIA 7 要素质量评分）工具；Web 后端新增 `GET /api/doctor` 与 `GET /api/sbom-quality/{scan_id}`，并在前端总览页与 SBOM 页同屏展示实时诊断与合规评分；同步刷新 `docs/INSTALLATION_AND_USAGE.md` 与 `README.md`。
- **开发者体验与 CLI 机器可读契约升级 (`dx.py` + `openguard init` / `openguard doctor` / `scan --json --audit-mode`)**：对标 Biome / Ruff / Snyk / Trivy，新增自动技术栈探测与幂等仓库初始化（`openguard init`）、7 项环境与供应链就绪度诊断（`openguard doctor`）、纯净 stdout JSON 输出（`--json`，错误/通知分流 stderr）、非阻塞观察模式（`--audit-mode`）以及标准 `0/1/2/3` 分级退出码协议；同步刷新 `docs/ARCHITECTURE.md` 至 v1.3+ 全景架构。
- **SBOM Diff 供应链漂移检测 & NTIA 质量评分器 (`sbom_tools.py` + `openguard sbom-diff` / `openguard sbom-score`)**：对标 GitHub Dependency Review Action 与 `sbomqs`，支持对比两份 CycloneDX SBOM 的组件变更、Copyleft 许可证漂移与新增漏洞（`--fail-on-drift`），并依据 7 项 NTIA/CISA 最小要素对 SBOM 进行 0–10.0 质量打分（`--min-score`）。
- **2025–2026 离线高危 CVE & CISA KEV 情报扩容**：新增 React RSC (`CVE-2025-55182`)、Next.js (`CVE-2025-66478`)、Brotli HTTP2Shell (`CVE-2026-111497`) 与 Axios (`CVE-2026-67313`/`CVE-2026-67319`) 检测及 KEV/EPSS 评分。
- **7 语言系统级 SAST 扩展（对标 CodeQL / SpotBugs / Cppcheck / Clippy）**：新增 Java（`OG-SAST-JAVA-001`–`003`：反序列化/`Runtime.exec`/XXE）、C/C++（`OG-SAST-CPP-001`–`002`：`gets`/`strcpy`/`system`）与 Rust（`OG-SAST-RS-001`–`003`：`transmute`/Shell 命令/缺 `// SAFETY:` 的 `unsafe` 块）静态规则。
- **组织/竞赛级多仓组合审计与 JSONL 流式输出 (`PortfolioAuditor` + `openguard batch`)**：一键批量扫描目录下多个仓库，支持流式 JSONL 导出（`--jsonl-out`）、Portfolio 排行榜 Markdown（`--md-out`）与 `--fail-on-gate` 门禁。
- **JavaScript / TypeScript 跨语句污点分析引擎 (`JSTaintAnalyzer`)**：对标 Semgrep JS / CodeQL，追踪 Express/Next.js/Node.js 外部输入与对象解构变量流入 `child_process.exec`（`OG-TAINT-JS-001`）、XSS（`OG-TAINT-JS-002`）、SSRF（`OG-TAINT-JS-003`）、`fs` 路径穿越（`OG-TAINT-JS-004`）与原型链污染（`OG-TAINT-JS-005`），自动识别常见净化器与守卫。
- **基于 SHA-256 内容哈希的增量文件扫描缓存 (`IncrementalScanCache` + `--cache`)**：对标 Ruff `.ruff_cache` / ESLint `--cache`，采用 `文件内容 + 配置指纹 + 工具版本` 复合键跳过未变更文件并保证零脏缓存。

## [1.3.0] - 2026-11-22

### Added
- **锁文件防篡改/降级守卫 (`InstallScriptScanner`) & OpenSSF Scorecard 仓库卫生**：检测 `package-lock.json` 中明文 `http://` 源降级（`OG-SUP-LOCK-001`）及缺失/弱 `sha1` 完整性哈希（`OG-SUP-LOCK-002`）；本仓库新增 `.github/dependabot.yml` 与 `.github/CODEOWNERS` 对齐 OpenSSF Scorecard 最佳实践。
- **自适应多线程并发扫描 (`ThreadPoolExecutor`)**：`SecretScanner` 与 `CodeSecurityScanner` 在文件数 ≥ 16 时自动启用线程池并发扫描（可通过 `.openguard.yml` `max_workers` 配置），兼顾大仓性能与结果确定性顺序。
- **声明式 Policy-as-Code 与自定义 YAML 规则引擎 (`PolicyEngine`，对标 Semgrep / FOSSA / OPA)**：支持自动加载 `.openguard/rules/*.yml` 与 `.openguard.yml` 中的 `custom_sast_rules`，并支持声明式 `policy.denied_licenses`、`policy.allowed_licenses` 与 `policy.denied_packages` 合规门禁。
- **HTML / PDF 离线报告同步升级**：HTML 报告新增 `[P0-P3]` KEV/EPSS/Call-Graph 徽章及 CI/Dockerfile/IaC/AI/污点/策略独立标签；中文 PDF 报告首屏新增 Quality Gate 门禁执行摘要表与优先级/可达性列。
- **CISA KEV & EPSS 风险优先级分级（对标 Dependency-Track / Wiz / Grype）**：新增 `in_cisa_kev`、`epss_score` 与 `P0`–`P3` 风险分级矩阵（融合 CISA KEV、EPSS 概率与 Call-Graph 可达性），并透出至 CycloneDX 1.5、PR 评审评论与 Web 工作台。
- **云原生 IaC 安全审计器 (`IaCScanner`，对标 Checkov / Trivy Config)**：新增 9 项静态规则（`OG-IAC-001`–`OG-IAC-009`），覆盖 `docker-compose.yml`、Kubernetes YAML 与 Terraform `*.tf` 常见高危误配置。
- **Python 跨语句 AST 污点传播分析引擎 (`PythonTaintAnalyzer`)**：对标 Semgrep Taint Mode，在函数与模块作用域内追踪外部用户输入（`request.args/form/json/values`、`sys.argv`、`input`）经变量赋值/拼接流入 SQL 注入（`OG-TAINT-PY-001`）、命令注入（`OG-TAINT-PY-002`）、SSRF（`OG-TAINT-PY-003`）与路径穿越（`OG-TAINT-PY-004`），并内置 `int`/`shlex.quote`/`os.path.basename`/`is_relative_to` 等净化器降噪。
- **SLSA v1.0 Provenance & in-toto v1 证明导出与防篡改校验 (`slsa_provenance.py`)**：支持 `--format slsa`、Web `/api/export/{scan_id}/slsa` 与 `openguard attest generate|verify`，自动对仓库清单文件生成 SHA-256 密码学摘要并嵌入 SBOM `resolvedDependencies`。
- **10 生态 SBOM 扩展（对标 Syft / OSV-SCALIBR）**：新增 GitHub Actions 工作流（`pkg:githubactions`）、`go.sum`、`Gemfile.lock`（RubyGems）、`composer.lock`（含许可证与传递边）及 `.NET *.csproj`（NuGet）解析器。
- **Web 工作台与 API 对齐（对标 Socket / Dependency-Track / Snyk）**：新增 3 级 Call-Graph/VEX 状态徽章、`CI / 容器 / AI 安全` 独立筛选标签、Web 端一键依赖升级（`fix_deps` Diff 预览/应用）、`PR / MR 评审评论` 导出以及实时检测台 Go/`.cursorrules` 场景支持；同步修复 Windows `NO_PROXY=[::1]` 下 OSV 客户端初始化兼容性。
- **AI 供应链安全审计器 (`AIConfigSecurityScanner`)**：检测隐藏 Unicode Tag Block (`U+E0000–U+E007F`) 隐写并自动解码载荷预览（`OG-AI-001`）、Trojan Source 双向控制符与零宽字符混淆（`OG-AI-002`）、`.cursorrules`/`CLAUDE.md`/`AGENTS.md` 间接提示词注入后门（`OG-AI-003`）以及 `.mcp.json` 配置投毒与未锁版本 `npx`/`uvx` Rug-Pull 风险（`OG-AI-004`）。
- **离线 CRC32 凭据校验与 GitLab Routable Token 支持**：新增 GitHub (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`) 与 npm (`npm_`) Token 的 Base62 CRC32 离线校验（真实凭据置信度跃升并标记 `verified_crc32_checksum`，测试/文档中的伪造 Token 自动降噪过滤），并修复 GitLab 17+ 多段式 Routable Token（含 `.01.`）匹配截断问题。

## [1.2.0] - 2026-11-21

### Added
- **CI/CD 供应链安全审计器 (`CIWorkflowScanner`)**：对标 OpenSSF Scorecard / Zizmor，静态审计 `.github/workflows/*.yml` 与 `.gitlab-ci.yml`，检出未锁定 40 位 Commit SHA 的第三方 Action、过宽/缺失的 `GITHUB_TOKEN permissions`、`pull_request_target` 不受控 PR 检出、`${{ github.event.* }}` 脚本注入与 `curl | sh` 管道执行；同时完成 OpenGuard 自家工作流 SHA 锁定与 GitHub Code Scanning SARIF 上传加固。
- **函数调用级可达性与自动 CycloneDX VEX (`ReachabilityAnalyzer` + `sarif_sbom_reporter`)**：在导入级基础上增加 AST 别名追踪与危险符号调用点分析（区分为 `call_reachable` / `import_only` / `unreachable` 三档，并精准识别 `yaml.safe_load` / `Loader=SafeLoader`），自动在 CycloneDX 1.5 中生成 VEX `analysis` 声明（`exploitable` / `in_triage` / `not_affected` + `code_not_reachable`），并修复 SARIF 漏洞定位到真实依赖清单文件。
- **现代锁文件解析与容器安全扫描 (`DockerfileScanner`)**：新增 `uv.lock`、`poetry.lock`、`yarn.lock`、`pnpm-lock.yaml` 精确传递依赖解析；新增 `Dockerfile` 安全审计（`:latest` / 未锁标签、root 运行、构建期 `curl | sh`、`ENV/ARG` 硬编码密钥、`ADD http`）以及 Go SAST 规则（`InsecureSkipVerify`、`exec.Command("sh", "-c")`、弱哈希）。
- **Diff-Aware PR 增量扫描、基线管理与 PR 评论导出**：支持 `--diff <base_ref>` 增量审计、`openguard baseline create` + `--baseline` 存量债务静默机制、`--format pr-comment` 紧凑 PR 评审 Markdown；同步修复 `--staged` 模式下保留全文件 AST 上下文过滤。
- **漏洞依赖一键安全升级 (`openguard autofix --deps`)**：自动针对 `requirements.txt` / `pyproject.toml` / `package.json` 生成最小安全版本升级 Diff 并支持 `--apply` 写入与 `.openguard_backup` 备份。
- **面向 AI 编程助手的内置 MCP Server (`openguard mcp`) 与 `.pre-commit-hooks.yaml`**：零额外依赖实现 JSON-RPC 2.0 stdio MCP 服务，暴露 `audit_repository`、`audit_code_snippet`、`check_package_safety`（含 AI 幻觉包 Slopsquatting 防护）与 `generate_pr_comment`；新增 `.pre-commit-hooks.yaml` 实现全网 GitHub 仓库 10 秒零配置接入。

## [1.1.0] - 2026-11-20

### Added
- **CVE 源码级可达性分析 (`ReachabilityAnalyzer`)**：跨 Python AST / JS / Go 静态追踪包导入与别名映射（如 `PyYAML -> yaml`），区分“源码实际可达漏洞”与“未直接引用依赖噪音”。
- **安装脚本供应链投毒拦截 (`InstallScriptScanner`)**：静态审计 `package.json` 生命周期钩子（`postinstall`/`preinstall`）及 `setup.py` AST 中的远端下载管道执行、Base64 混淆载荷与系统命令调用。
- **确定性质量门禁引擎 (`QualityGate`)**：基于 5 项硬性门禁条件（工作区零密钥、历史零密钥、零可达高危 CVE、零强传染冲突、零投毒脚本）输出明确的 `PASSED / FAILED` 发布准入判定。
- **应急响应 Runbook 与在线 Triage 闭环**：每条秘密告警均附 3 步处置剧本；新增 `/api/file-context`（带路径穿越防御与凭据自动掩码）及 `/api/triage/ignore` 一键标记行内豁免。
- **全新极简工程风 Web 工作台**：采用 Light-First 浅色默认设计（含 Linear Zinc 深色模式切换）、SonarQube 风格质量门禁横幅、Socket.dev 风格分段指标条、GitHub 安全风格 Master-Detail 分栏代码溯源器与全局 `Ctrl+K` 命令面板。

## [1.0.0] - 2026-11-20

### Added
- **FastAPI 可视化 Web 审计工作台 (`openguard serve`)**：内置评分仪表盘、五维合规雷达图、SVG 依赖拓扑图、Live Snippet 实时代码检测台、AutoFix Diff 预览/应用、SQLite 历史台账与 Before/After 整改前后对比视图。
- **可复现 Benchmark 基准测试套件 (`benchmarks/`)**：构建 220 条标注测试集（100 正例 + 120 误报诱饵），量化对比纯正则、纯信息熵与 OpenGuard 三阶混合引擎。
- **跨平台报告导出一键全覆盖**：支持交互式单文件 HTML、中文排版 PDF（ReportLab）、SARIF 2.1.0、CycloneDX 1.5 SBOM、SPDX 2.3、Markdown 与 SVG 状态徽章。
- **内置代码统计命令 (`openguard cloc`)**：支持多语言有效代码行数统计与排除口径审计。

## [0.8.0] - 2026-11-16

### Added
- **自动化脱敏重构与治理生成 (`openguard autofix`)**：支持 Python/JS/YAML/ENV 硬编码密钥剥离至 `.env.example`，并支持 MIT / Apache-2.0 / 木兰宽松许可证（MulanPSL-2.0）等 6 类工程文档生成。
- **Git 防线与 CI 模板生成 (`openguard hook`)**：支持本地 `pre-commit` 提交拦截钩子、适配 `git.hust.edu.cn` 的 `.gitlab-ci.yml` 及 GitHub Actions 工作流。

## [0.5.0] - 2026-11-12

### Added
- **多生态依赖解析与许可证传染性推导**：覆盖 PyPI / npm / Go / Maven / Rust / C++ / PHP 7 大生态，基于 `NetworkX` 构建依赖有向图并支持 GPL/AGPL/LGPL 传播路径溯源。
- **供应链漏洞与投毒检测**：整合离线高频 CVE 知识库、OSV.dev 批量接口及 Levenshtein 仿冒包（Typosquatting）启发式识别。
- **Python AST SAST 与工程治理评分**：覆盖 `CWE-95/502/78/89/295/327/489/732/79` 高危模式及 12 项开源工程治理检查。

## [0.1.0] - 2026-11-08

### Added
- **三阶混合敏感信息检测引擎**：实现 46 条高危凭据规则 + Shannon 信息熵与占位符过滤 + Python AST 语义上下文降噪，支持 Git 历史 Commit 幽灵密钥回溯与暂存区增量扫描。
