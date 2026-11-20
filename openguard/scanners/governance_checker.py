"""Open-source repository governance, engineering maturity, and documentation completeness checker."""

from __future__ import annotations

import os
from pathlib import Path
from typing import List

from openguard.config import DEFAULT_EXCLUDE_DIRS
from openguard.models import DependencyComponent, GovernanceCheckItem


class GovernanceChecker:
    """Evaluates 12 open-source governance criteria aligned with competition evaluation standards."""

    def check_repository(
        self,
        root_path: Path,
        project_license: str,
        components: List[DependencyComponent],
    ) -> List[GovernanceCheckItem]:
        root = Path(root_path).resolve()
        if root.is_file():
            root = root.parent

        items: List[GovernanceCheckItem] = []

        # 1. README completeness
        readme = next((root / f for f in ("README.md", "README.rst", "README.txt", "README") if (root / f).is_file()), None)
        if readme:
            txt = readme.read_text(encoding="utf-8", errors="replace").lower()
            has_install = any(k in txt for k in ("install", "安装", "快速开始", "quick start", "pip ", "npm "))
            has_usage = any(k in txt for k in ("usage", "使用", "example", "示例", "```"))
            passed = len(txt) >= 300 and (has_install or has_usage)
            items.append(
                GovernanceCheckItem(
                    check_id="OG-GOV-001",
                    name="README 主文档完备性",
                    category="开源文档",
                    passed=passed,
                    score=12.0 if passed else 6.0,
                    max_score=12.0,
                    details=(
                        f"已提供 `{readme.name}`（含安装与使用说明，{len(txt)} 字符）。"
                        if passed
                        else f"存在 `{readme.name}`，但内容较简略或缺少安装/使用示例。"
                    ),
                    remediation="补充项目简介、架构图、快速安装步骤与核心功能使用示例。",
                )
            )
        else:
            items.append(
                GovernanceCheckItem(
                    check_id="OG-GOV-001",
                    name="README 主文档完备性",
                    category="开源文档",
                    passed=False,
                    score=0.0,
                    max_score=12.0,
                    details="仓库根目录缺失 README 文档。",
                    remediation="创建完整的 `README.md`。",
                )
            )

        # 2. LICENSE presence & SPDX clarity
        has_lic = project_license != "UNKNOWN"
        items.append(
            GovernanceCheckItem(
                check_id="OG-GOV-002",
                name="标准开源许可证 (LICENSE)",
                category="合规授权",
                passed=has_lic,
                score=12.0 if has_lic else 0.0,
                max_score=12.0,
                details=f"已声明标准 SPDX 许可证: `{project_license}`。" if has_lic else "未检测到明确的标准开源许可证文本。",
                remediation="使用 `openguard autofix . --docs --license MIT --apply` 一键生成规范 `LICENSE`。",
                autofixable=True,
            )
        )

        # 3. CONTRIBUTING.md
        has_contrib = any((root / f).is_file() for f in ("CONTRIBUTING.md", "CONTRIBUTING.rst", ".github/CONTRIBUTING.md"))
        items.append(
            GovernanceCheckItem(
                check_id="OG-GOV-003",
                name="开源贡献指南 (CONTRIBUTING.md)",
                category="社区协作",
                passed=has_contrib,
                score=8.0 if has_contrib else 0.0,
                max_score=8.0,
                details="已包含社区贡献指南文档。" if has_contrib else "缺少 `CONTRIBUTING.md`，外部贡献者难以了解开发流程与 PR 规范。",
                remediation="通过 `openguard autofix . --docs --apply` 自动生成 `CONTRIBUTING.md`。",
                autofixable=True,
            )
        )

        # 4. CHANGELOG.md
        has_changelog = any((root / f).is_file() for f in ("CHANGELOG.md", "HISTORY.md", "RELEASES.md"))
        items.append(
            GovernanceCheckItem(
                check_id="OG-GOV-004",
                name="版本迭代记录 (CHANGELOG.md)",
                category="版本治理",
                passed=has_changelog,
                score=8.0 if has_changelog else 0.0,
                max_score=8.0,
                details="已维护版本变更记录。" if has_changelog else "缺少 `CHANGELOG.md` 版本演进说明。",
                remediation="通过 `openguard autofix . --docs --apply` 生成标准 Keep-a-Changelog 版本记录。",
                autofixable=True,
            )
        )

        # 5. SECURITY.md
        has_sec = any((root / f).is_file() for f in ("SECURITY.md", ".github/SECURITY.md"))
        items.append(
            GovernanceCheckItem(
                check_id="OG-GOV-005",
                name="漏洞披露安全策略 (SECURITY.md)",
                category="安全治理",
                passed=has_sec,
                score=8.0 if has_sec else 0.0,
                max_score=8.0,
                details="已制定安全漏洞响应与披露政策。" if has_sec else "缺少 `SECURITY.md`，安全研究者发现漏洞后缺少私密上报指引。",
                remediation="通过 `openguard autofix . --docs --apply` 生成 `SECURITY.md`。",
                autofixable=True,
            )
        )

        # 6. .gitignore & sensitive rules
        gitignore = root / ".gitignore"
        if gitignore.is_file():
            gi_txt = gitignore.read_text(encoding="utf-8", errors="replace").lower()
            covers_env = ".env" in gi_txt
            covers_keys = any(k in gi_txt for k in ("*.pem", "*.key", "secret"))
            passed = covers_env and covers_keys
            items.append(
                GovernanceCheckItem(
                    check_id="OG-GOV-006",
                    name=".gitignore 敏感文件屏蔽配置",
                    category="安全防线",
                    passed=passed,
                    score=10.0 if passed else 5.0,
                    max_score=10.0,
                    details=(
                        "`.gitignore` 已屏蔽 `.env` 与私钥文件。"
                        if passed
                        else "存在 `.gitignore`，但未显式忽略 `.env` 或 `*.pem`/`*.key` 凭据文件。"
                    ),
                    remediation="在 `.gitignore` 追加 `.env`、`.env.*`、`*.pem`、`*.key`。",
                    autofixable=True,
                )
            )
        else:
            items.append(
                GovernanceCheckItem(
                    check_id="OG-GOV-006",
                    name=".gitignore 敏感文件屏蔽配置",
                    category="安全防线",
                    passed=False,
                    score=0.0,
                    max_score=10.0,
                    details="未找到 `.gitignore`，极易误提交缓存、密钥或临时环境文件。",
                    remediation="使用 `openguard autofix . --docs --apply` 生成防泄密 `.gitignore`。",
                    autofixable=True,
                )
            )

        # 7. Dependency manifest & version pinning
        if components:
            pinned = sum(1 for c in components if c.version not in ("unspecified", "*", "latest", ""))
            ratio = pinned / len(components)
            passed = ratio >= 0.7
            items.append(
                GovernanceCheckItem(
                    check_id="OG-GOV-007",
                    name="依赖版本锁定与可复现构建",
                    category="供应链管理",
                    passed=passed,
                    score=8.0 if passed else 4.0,
                    max_score=8.0,
                    details=f"共解析 {len(components)} 个依赖，版本明确率 {ratio * 100:.0f}%。",
                    remediation="锁定所有核心依赖版本号并提交 lock 文件或精确版本清单。",
                )
            )
        else:
            items.append(
                GovernanceCheckItem(
                    check_id="OG-GOV-007",
                    name="依赖版本锁定与可复现构建",
                    category="供应链管理",
                    passed=True,
                    score=8.0,
                    max_score=8.0,
                    details="零外部依赖或暂未检测到独立依赖清单。",
                    remediation="如引入第三方库，请维护清晰的 `requirements.txt` / `pyproject.toml` / `package.json`。",
                )
            )

        # 8. Automated tests
        has_tests = (root / "tests").is_dir() or (root / "test").is_dir() or any(
            p.name.startswith("test_") or p.name.endswith(("_test.py", ".test.js", ".spec.ts"))
            for p in root.rglob("*")
            if p.is_file() and not any(ex in p.parts for ex in DEFAULT_EXCLUDE_DIRS)
        )
        items.append(
            GovernanceCheckItem(
                check_id="OG-GOV-008",
                name="自动化单元测试套件",
                category="质量保障",
                passed=has_tests,
                score=10.0 if has_tests else 0.0,
                max_score=10.0,
                details="已配备自动化测试目录/用例。" if has_tests else "未检测到单元测试用例，项目回归验证依赖手工操作。",
                remediation="创建 `tests/` 目录并编写核心模块自动化测试用例。",
            )
        )

        # 9. CI/CD pipeline
        has_ci = (
            (root / ".github" / "workflows").is_dir()
            or (root / ".gitlab-ci.yml").is_file()
            or (root / ".gitee").is_dir()
        )
        items.append(
            GovernanceCheckItem(
                check_id="OG-GOV-009",
                name="CI/CD 自动化流水线配置",
                category="工程化",
                passed=has_ci,
                score=8.0 if has_ci else 0.0,
                max_score=8.0,
                details="已配置自动化 CI 流水线。" if has_ci else "未检测到 GitLab CI / GitHub Actions 流水线配置。",
                remediation="使用 `openguard hook ci . --ci-platform gitlab` 一键生成校内 `git.hust.edu.cn` 流水线。",
                autofixable=True,
            )
        )

        # 10. Git VCS & large blob check
        has_git = (root / ".git").exists()
        large_files: List[str] = []
        for dp, dns, fns in os.walk(root):
            dns[:] = [d for d in dns if d not in DEFAULT_EXCLUDE_DIRS]
            for fn in fns:
                fp = Path(dp) / fn
                try:
                    if fp.stat().st_size > 5 * 1024 * 1024:
                        large_files.append(fp.relative_to(root).as_posix())
                except OSError:
                    continue
        vcs_ok = has_git and not large_files
        items.append(
            GovernanceCheckItem(
                check_id="OG-GOV-010",
                name="Git 版本控制与仓库瘦身",
                category="工程化",
                passed=vcs_ok,
                score=6.0 if vcs_ok else (3.0 if has_git or not large_files else 0.0),
                max_score=6.0,
                details=(
                    "已启用 Git 版本控制且无 >5MB 超大二进制文件。"
                    if vcs_ok
                    else f"Git 状态: {'已初始化' if has_git else '未初始化'}；超大文件(>5MB): {large_files or '无'}。"
                ),
                remediation="初始化 Git 仓库并将模型权重/编译产物/压缩包加入 `.gitignore`。",
            )
        )

        # 11. Extended engineering docs / issue logs
        has_docs_dir = (root / "docs").is_dir() or (root / ".github" / "ISSUE_TEMPLATE").is_dir()
        items.append(
            GovernanceCheckItem(
                check_id="OG-GOV-011",
                name="架构安装文档与问题处理记录 (docs/)",
                category="开源文档",
                passed=has_docs_dir,
                score=5.0 if has_docs_dir else 0.0,
                max_score=5.0,
                details="已建有 `docs/` 详细文档或 Issue 模板。" if has_docs_dir else "建议补充 `docs/` 安装文档、架构说明及 Issue 处理记录。",
                remediation="新建 `docs/` 目录沉淀安装说明、系统架构及常见问题修复记录。",
            )
        )

        # 12. OpenGuard Policy / Pre-commit protection
        has_policy = (
            (root / ".openguard.yml").is_file()
            or (root / ".openguard.yaml").is_file()
            or (root / ".git" / "hooks" / "pre-commit").is_file()
        )
        items.append(
            GovernanceCheckItem(
                check_id="OG-GOV-012",
                name="OpenGuard 门禁策略与 Pre-commit 防线",
                category="安全防线",
                passed=has_policy,
                score=5.0 if has_policy else 0.0,
                max_score=5.0,
                details="已启用 `.openguard.yml` 或本地 `pre-commit` 提交拦截防线。" if has_policy else "未配置自动化提交前密钥防泄露钩子。",
                remediation="运行 `openguard hook install .` 启用提交前自动拦截防护。",
                autofixable=True,
            )
        )

        return items
