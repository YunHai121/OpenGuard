# Changelog

All notable changes to **OpenGuard (开源卫士)** are documented in this file following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and Semantic Versioning.

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
