"""Developer Experience (DX) utilities: Auto-Discovery `init` & Proactive `doctor` Diagnostics.

Inspired by modern security/linter CLI leaders (Biome, Ruff, Snyk, Trivy, Homebrew):
- `detect_repo_stack`: inspects target repository manifests, ecosystems, CI/CD, and AI configs.
- `init_repository`: idempotently scaffolds tailored `.openguard.yml`, `.openguardignore`, and
  `.openguard/rules/starter_policy.yml` without clobbering existing files unless `force=True`.
- `run_doctor`: performs 7 actionable environment & repository security-readiness checks with
  deterministic status levels (`OK` / `WARN` / `ERROR`) and copy-pasteable `fix_hint` commands.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

import yaml

from openguard import __version__
from openguard.config import DEFAULT_EXCLUDE_DIRS, load_config
from openguard.scanners.license_analyzer import LicenseAnalyzer

# Exit code contract shared across OpenGuard CLI commands
EXIT_OK = 0
EXIT_POLICY_VIOLATION = 1
EXIT_USER_ERROR = 2
EXIT_RUNTIME_ERROR = 3


def detect_repo_stack(repo_root: Path) -> Dict[str, Any]:
    """Inspect repository manifests, ecosystems, CI/CD, and AI agent configurations."""
    root = Path(repo_root).resolve()
    ecosystems: List[str] = []
    manifests: List[str] = []

    def _add_eco(name: str) -> None:
        if name not in ecosystems:
            ecosystems.append(name)

    manifest_map = {
        "pyproject.toml": "PyPI",
        "requirements.txt": "PyPI",
        "requirements-dev.txt": "PyPI",
        "uv.lock": "PyPI",
        "poetry.lock": "PyPI",
        "package.json": "npm",
        "package-lock.json": "npm",
        "yarn.lock": "npm",
        "pnpm-lock.yaml": "npm",
        "go.mod": "Go",
        "go.sum": "Go",
        "Cargo.toml": "Cargo",
        "Cargo.lock": "Cargo",
        "pom.xml": "Maven",
        "Gemfile": "RubyGems",
        "Gemfile.lock": "RubyGems",
        "composer.json": "Composer",
        "composer.lock": "Composer",
        "Dockerfile": "Docker",
        "docker-compose.yml": "IaC/DockerCompose",
        "docker-compose.yaml": "IaC/DockerCompose",
        "compose.yml": "IaC/DockerCompose",
    }

    # Check top-level and immediate child directories (depth <= 2) quickly
    candidates: List[Path] = []
    if root.is_dir():
        for item in sorted(root.iterdir()):
            if item.name in DEFAULT_EXCLUDE_DIRS:
                continue
            if item.is_file():
                candidates.append(item)
            elif item.is_dir():
                for sub in sorted(item.iterdir()):
                    if sub.is_file() and sub.name not in DEFAULT_EXCLUDE_DIRS:
                        candidates.append(sub)

    has_ai_configs = False
    has_iac = False
    for fpath in candidates:
        rel = fpath.relative_to(root).as_posix()
        fname = fpath.name
        if fname in manifest_map:
            _add_eco(manifest_map[fname])
            manifests.append(rel)
            if manifest_map[fname].startswith("IaC"):
                has_iac = True
        elif fname.endswith(".csproj"):
            _add_eco("NuGet")
            manifests.append(rel)
        elif fname.endswith(".tf"):
            _add_eco("IaC/Terraform")
            manifests.append(rel)
            has_iac = True
        elif fname in (".cursorrules", "CLAUDE.md", "AGENTS.md", ".mcp.json", "mcp.json"):
            _add_eco("AI Coding Rules")
            manifests.append(rel)
            has_ai_configs = True

    gh_workflows_dir = root / ".github" / "workflows"
    has_github_ci = gh_workflows_dir.is_dir() and any(
        p.suffix.lower() in (".yml", ".yaml") for p in gh_workflows_dir.iterdir() if p.is_file()
    )
    has_gitlab_ci = (root / ".gitlab-ci.yml").is_file()
    if has_github_ci:
        _add_eco("GitHub Actions")

    has_git = (root / ".git").exists()
    pre_commit_hook = root / ".git" / "hooks" / "pre-commit"
    has_openguard_hook = (
        pre_commit_hook.is_file()
        and "openguard" in pre_commit_hook.read_text(encoding="utf-8", errors="replace").lower()
    )
    has_precommit_yaml = (root / ".pre-commit-config.yaml").is_file()

    project_license = LicenseAnalyzer().detect_project_license(root) if root.is_dir() else "UNKNOWN"

    return {
        "repo_name": root.name,
        "ecosystems": ecosystems,
        "manifests": manifests[:30],
        "project_license": project_license,
        "has_git": has_git,
        "has_github_ci": has_github_ci,
        "has_gitlab_ci": has_gitlab_ci,
        "has_ci": has_github_ci or has_gitlab_ci,
        "has_precommit": has_openguard_hook or has_precommit_yaml,
        "has_ai_configs": has_ai_configs,
        "has_iac": has_iac,
    }


def _render_tailored_config_yaml(stack: Dict[str, Any]) -> str:
    ecos = ", ".join(stack.get("ecosystems") or ["Generic"])
    lic = stack.get("project_license") or "UNKNOWN"
    return (
        f"# OpenGuard (开源卫士) v{__version__} 仓库审计配置\n"
        f"# 自动探测生态: {ecos} | 主许可证: {lic}\n"
        "offline: false\n"
        "use_cache: true\n"
        "max_workers: 4\n"
        "min_confidence: 0.45\n"
        "entropy_threshold: 3.3\n"
        "\n"
        "# 五维评分权重（总和为 1.0）\n"
        "weights:\n"
        "  secret_security: 0.30\n"
        "  supply_chain_vuln: 0.20\n"
        "  license_compliance: 0.20\n"
        "  code_security: 0.15\n"
        "  governance: 0.15\n"
        "\n"
        "# 声明式供应链与许可证合规策略 (Policy-as-Code)\n"
        "policy:\n"
        "  # 按需取消注释以在 CI 中强阻断特定高传染许可证或禁用组件\n"
        "  denied_licenses: []\n"
        "  # - AGPL-3.0\n"
        "  # - SSPL-1.0\n"
        "  denied_packages: []\n"
        "  # - event-stream\n"
    )


def _render_tailored_ignore(stack: Dict[str, Any]) -> str:
    ecos = set(stack.get("ecosystems") or [])
    lines = [
        "# OpenGuard 扫描忽略规则 (.openguardignore)",
        ".openguard_cache/",
        ".openguard_backup/",
        "dist/",
        "build/",
        "*.min.js",
        "*.min.css",
    ]
    if "PyPI" in ecos:
        lines.extend([".venv/", "venv/", "__pycache__/", "*.egg-info/"])
    if "npm" in ecos:
        lines.extend(["node_modules/", ".next/", "coverage/"])
    if "Cargo" in ecos or "Maven" in ecos:
        lines.append("target/")
    if "Go" in ecos or "Composer" in ecos:
        lines.append("vendor/")
    if "NuGet" in ecos:
        lines.extend(["bin/", "obj/"])
    return "\n".join(dict.fromkeys(lines)) + "\n"


def _render_starter_policy_yaml() -> str:
    return (
        "# OpenGuard 自定义 Policy-as-Code 规则模板 (.openguard/rules/*.yml)\n"
        "# 取消下方注释即可启用团队专属零代码正则 SAST 规则：\n"
        "rules: []\n"
        "# - id: TEAM-SEC-001\n"
        "#   name: 禁止使用明文内网测试域名\n"
        "#   severity: MEDIUM\n"
        "#   cwe: CWE-200\n"
        "#   pattern: 'http://internal-staging\\.corp\\.local'\n"
        "#   paths: ['src/*', '*.py', '*.ts']\n"
        "#   exclude_paths: ['tests/*']\n"
        "#   message: 检测到硬编码内网测试地址，请改为环境变量配置。\n"
        "#   remediation: 使用 os.getenv('INTERNAL_API_BASE') 注入地址。\n"
    )


def init_repository(repo_root: Path, force: bool = False) -> Dict[str, Any]:
    """Idempotently scaffold tailored OpenGuard configuration files for a repository."""
    root = Path(repo_root).resolve()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"初始化目标目录不存在: {root}")

    stack = detect_repo_stack(root)
    targets: Dict[str, str] = {
        ".openguard.yml": _render_tailored_config_yaml(stack),
        ".openguardignore": _render_tailored_ignore(stack),
        ".openguard/rules/starter_policy.yml": _render_starter_policy_yaml(),
    }

    file_statuses: Dict[str, str] = {}
    for rel_path, content in targets.items():
        fpath = root / rel_path
        if fpath.exists() and not force:
            file_statuses[rel_path] = "skipped (already exists)"
            continue
        status = "overwritten" if fpath.exists() else "created"
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(content, encoding="utf-8")
        file_statuses[rel_path] = status

    return {
        "repo_root": str(root),
        "stack": stack,
        "files": file_statuses,
    }


def run_doctor(repo_root: Path) -> Dict[str, Any]:
    """Run proactive environment & repository security-readiness diagnostics."""
    root = Path(repo_root).resolve()
    if not root.exists():
        raise FileNotFoundError(f"诊断目标路径不存在: {root}")
    target_dir = root.parent if root.is_file() else root

    checks: List[Dict[str, str]] = []

    def _record(cid: str, name: str, status: str, details: str, fix_hint: str = "") -> None:
        checks.append(
            {
                "id": cid,
                "name": name,
                "status": status,
                "details": details,
                "fix_hint": fix_hint,
            }
        )

    # 1. Python runtime check
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 10):
        _record("OG-DOC-01", "Python 运行时版本", "OK", f"Python {py_ver} (OpenGuard v{__version__})")
    else:
        _record(
            "OG-DOC-01",
            "Python 运行时版本",
            "ERROR",
            f"当前版本 Python {py_ver} 低于最低要求 3.10",
            "请升级至 Python >= 3.10",
        )

    # 2. Git CLI & repository availability
    git_bin = shutil.which("git")
    if not git_bin:
        _record(
            "OG-DOC-02",
            "Git 工具链与仓库状态",
            "WARN",
            "未在 PATH 中找到 git 可执行文件（--git-history / --staged / --diff 将不可用）",
            "安装 Git 并确保 git 位于系统 PATH 中",
        )
    else:
        try:
            ver_res = subprocess.run(
                [git_bin, "--version"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
            )
            git_ver = ver_res.stdout.strip() or "git detected"
        except Exception:
            git_ver = "git detected"
        if (target_dir / ".git").exists():
            _record("OG-DOC-02", "Git 工具链与仓库状态", "OK", f"{git_ver} · 已初始化 Git 仓库")
        else:
            _record(
                "OG-DOC-02",
                "Git 工具链与仓库状态",
                "WARN",
                f"{git_ver} · 目标目录尚未初始化 .git 仓库",
                "git init",
            )

    # 3. .openguard.yml configuration validation
    cfg_path = next(
        (p for p in (target_dir / ".openguard.yml", target_dir / ".openguard.yaml") if p.is_file()),
        None,
    )
    if cfg_path is None:
        _record(
            "OG-DOC-03",
            "OpenGuard 配置文件 (.openguard.yml)",
            "WARN",
            "未发现 .openguard.yml，当前将使用内置默认参数",
            f"openguard init {target_dir.name}",
        )
    else:
        try:
            raw_yaml = yaml.safe_load(cfg_path.read_text(encoding="utf-8", errors="replace"))
            if raw_yaml is not None and not isinstance(raw_yaml, dict):
                raise ValueError("顶层 YAML 结构必须为映射对象 (dict)")
            cfg = load_config(target_dir, config_path=cfg_path)
            _record(
                "OG-DOC-03",
                "OpenGuard 配置文件 (.openguard.yml)",
                "OK",
                f"解析有效 ({cfg_path.name} · workers={cfg.max_workers} · cache={cfg.use_cache})",
            )
        except Exception as exc:
            _record(
                "OG-DOC-03",
                "OpenGuard 配置文件 (.openguard.yml)",
                "ERROR",
                f"{cfg_path.name} 语法或结构错误: {exc}",
                f"修正 {cfg_path.name} 或执行 openguard init --force",
            )

    # 4. Pre-commit hook / local shift-left guard
    stack = detect_repo_stack(target_dir)
    if stack["has_precommit"]:
        _record("OG-DOC-04", "本地提交前密钥拦截 (Pre-commit)", "OK", "已配置 OpenGuard pre-commit 钩子或 .pre-commit-config.yaml")
    else:
        _record(
            "OG-DOC-04",
            "本地提交前密钥拦截 (Pre-commit)",
            "WARN",
            "尚未安装本地 pre-commit 拦截钩子（密钥可能在 push 前未拦截）",
            "openguard hook install .",
        )

    # 5. CI/CD & supply-chain governance hygiene
    has_dependabot = (target_dir / ".github" / "dependabot.yml").is_file() or (
        target_dir / ".github" / "dependabot.yaml"
    ).is_file()
    has_codeowners = (target_dir / ".github" / "CODEOWNERS").is_file() or (target_dir / "CODEOWNERS").is_file()
    if stack["has_ci"]:
        extras = []
        if has_dependabot:
            extras.append("Dependabot")
        if has_codeowners:
            extras.append("CODEOWNERS")
        extra_str = f" + {'/'.join(extras)}" if extras else " (建议补充 dependabot.yml / CODEOWNERS)"
        _record("OG-DOC-05", "CI/CD 与供应链治理流水线", "OK", f"已接入 CI 流水线{extra_str}")
    else:
        _record(
            "OG-DOC-05",
            "CI/CD 与供应链治理流水线",
            "WARN",
            "未检测到 .github/workflows 或 .gitlab-ci.yml 安全门禁配置",
            "openguard hook ci . --ci-platform github",
        )

    # 6. MCP Server readiness
    try:
        from openguard.mcp_server import MCP_TOOLS

        _record(
            "OG-DOC-06",
            "AI 编程助手 MCP Server 就绪度",
            "OK",
            f"JSON-RPC 2.0 MCP Server 就绪（已注册 {len(MCP_TOOLS)} 项工具，可执行 openguard mcp）",
        )
    except Exception as exc:
        _record(
            "OG-DOC-06",
            "AI 编程助手 MCP Server 就绪度",
            "ERROR",
            f"MCP Server 模块加载失败: {exc}",
            "检查 OpenGuard 安装完整性: pip install -e .",
        )

    # 7. Custom Policy YAML & Ecosystem Manifest readiness
    rules_dir = target_dir / ".openguard" / "rules"
    bad_rules: List[str] = []
    valid_rule_files = 0
    if rules_dir.is_dir():
        for rf in sorted(rules_dir.iterdir()):
            if rf.is_file() and rf.suffix.lower() in (".yml", ".yaml"):
                try:
                    yaml.safe_load(rf.read_text(encoding="utf-8", errors="replace"))
                    valid_rule_files += 1
                except Exception:
                    bad_rules.append(rf.name)

    if bad_rules:
        _record(
            "OG-DOC-07",
            "策略规则与依赖清单就绪度",
            "ERROR",
            f"自定义策略 YAML 无法解析: {', '.join(bad_rules)}",
            "修复 .openguard/rules/ 下的 YAML 语法错误",
        )
    elif stack["ecosystems"]:
        eco_str = ", ".join(stack["ecosystems"][:6])
        _record(
            "OG-DOC-07",
            "策略规则与依赖清单就绪度",
            "OK",
            f"探测到 {len(stack['ecosystems'])} 类生态 ({eco_str}) · 自定义策略文件 {valid_rule_files} 份",
        )
    else:
        _record(
            "OG-DOC-07",
            "策略规则与依赖清单就绪度",
            "WARN",
            "未探测到标准包管理清单文件（将执行纯代码/密钥/AI配置扫描）",
            "确认目标路径是否为项目根目录",
        )

    ok_count = sum(1 for c in checks if c["status"] == "OK")
    warn_count = sum(1 for c in checks if c["status"] == "WARN")
    error_count = sum(1 for c in checks if c["status"] == "ERROR")
    overall_status = "ERROR" if error_count > 0 else ("DEGRADED" if warn_count > 0 else "HEALTHY")

    return {
        "repo_root": str(target_dir),
        "openguard_version": __version__,
        "status": overall_status,
        "healthy": error_count == 0,
        "ok_count": ok_count,
        "warn_count": warn_count,
        "error_count": error_count,
        "ecosystems": stack["ecosystems"],
        "checks": checks,
    }
