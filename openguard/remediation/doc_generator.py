"""Automated generation of missing open-source governance documents (LICENSE, CONTRIBUTING, SECURITY, CHANGELOG)."""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Dict, List

MIT_TEMPLATE = """MIT License

Copyright (c) {year} {project_name} Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

APACHE_TEMPLATE = """                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   Copyright {year} {project_name} Contributors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""

MULAN_V2_TEMPLATE = """                     Mulan Permissive Software License, Version 2
                            木兰宽松许可证，第2版

   Copyright (c) {year} {project_name} Contributors

   您可依据“木兰宽松许可证，第2版”使用本软件。本软件按“现状”提供，不附带任何明示或暗示的担保。
   有关“木兰宽松许可证，第2版”的完整条款，请参阅：
   http://license.coscl.org.cn/MulanPSL2
"""

CONTRIBUTING_TEMPLATE = """# Contributing to {project_name}

感谢关注并参与 `{project_name}` 开源项目建设！欢迎通过 Issue 和 Pull Request 共同完善本项目。

## 开发与提交流程

1. Fork 本仓库并从主分支创建特性分支：`git checkout -b feat/your-feature`
2. 保持代码风格统一并补充对应的自动化单元测试
3. 提交代码前请务必运行安全基线与密钥防泄露检查：
   ```bash
   openguard scan . --offline --fail-on high
   ```
4. 遵循约定式提交规范（Conventional Commits）：
   - `feat:` 新增功能
   - `fix:` 缺陷修复
   - `docs:` 文档完善
   - `test:` 测试用例补充
5. 提交 Pull Request 并附上测试运行结果说明。
"""

SECURITY_TEMPLATE = """# Security Policy

## 支持的版本

| 版本 | 是否支持安全更新 |
| :--- | :--- |
| main / 最新发行版 | 是 |

## 安全漏洞上报流程

为了保障开源社区与用户安全，若您发现疑似安全漏洞或敏感信息暴露问题，**请勿直接提交公开 Issue**，请通过项目维护者邮箱或私有安全通道私密上报：

- **响应时间**：我们将在收到报告后 **48 小时** 内确认受理，并在 **7 个工作日** 内评估并发布修复补丁。
- **提交前自检**：所有贡献者需确保不向代码仓库上传真实 API Key、私钥或个人隐私数据。
"""

CHANGELOG_TEMPLATE = """# Changelog

All notable changes to `{project_name}` will be documented in this file.

## [Unreleased]

### Added
- 补充标准开源工程规范文档与安全基线防线。

## [0.1.0] - {today}

### Added
- 初始版本发布：包含核心功能模块与基础文档。
"""

GITIGNORE_TEMPLATE = """# Sensitive credentials & keys (OpenGuard Recommended)
.env
.env.*
!.env.example
*.pem
*.key
*.p12
*.pfx
*secret*.json
.openguard_backup/

# Python
__pycache__/
*.py[cod]
*.egg-info/
.venv/
venv/
dist/
build/

# Node.js
node_modules/
npm-debug.log*

# IDEs & OS
.idea/
.vscode/
.DS_Store
Thumbs.db
"""

OPENGUARD_YML_TEMPLATE = """# OpenGuard 开源安全与合规门禁配置
include_git_history: false
max_git_commits: 100
offline: false
min_confidence: 0.45
entropy_threshold: 3.3
weights:
  secret_security: 0.30
  supply_chain_vuln: 0.20
  license_compliance: 0.20
  code_security: 0.15
  governance: 0.15
"""


class DocGenerator:
    """Generates standardized open-source governance & security hygiene files."""

    def generate(
        self,
        root_path: Path,
        license_id: str = "MIT",
        apply: bool = False,
        force: bool = False,
    ) -> Dict[str, str]:
        root = Path(root_path).resolve()
        if root.is_file():
            root = root.parent
        project_name = root.name
        year = date.today().year
        today = date.today().isoformat()

        lic_upper = license_id.upper()
        if "APACHE" in lic_upper:
            lic_text = APACHE_TEMPLATE.format(year=year, project_name=project_name)
        elif "MULAN" in lic_upper:
            lic_text = MULAN_V2_TEMPLATE.format(year=year, project_name=project_name)
        else:
            lic_text = MIT_TEMPLATE.format(year=year, project_name=project_name)

        candidates: Dict[str, str] = {
            "LICENSE": lic_text,
            "CONTRIBUTING.md": CONTRIBUTING_TEMPLATE.format(project_name=project_name),
            "SECURITY.md": SECURITY_TEMPLATE,
            "CHANGELOG.md": CHANGELOG_TEMPLATE.format(project_name=project_name, today=today),
            ".gitignore": GITIGNORE_TEMPLATE,
            ".openguard.yml": OPENGUARD_YML_TEMPLATE,
        }

        actions: Dict[str, str] = {}
        for rel_name, content in candidates.items():
            target = root / rel_name
            if target.exists() and not force:
                actions[rel_name] = "skipped (already exists)"
                continue
            status = "overwritten" if target.exists() else "created"
            if apply:
                target.write_text(content, encoding="utf-8")
                actions[rel_name] = status
            else:
                actions[rel_name] = f"would_{status}"
        return actions
