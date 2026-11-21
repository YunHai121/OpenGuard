# Changelog

All notable changes to **OpenGuard (开源卫士)** are documented in this file following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and Semantic Versioning.

## [Unreleased]

### Added
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
