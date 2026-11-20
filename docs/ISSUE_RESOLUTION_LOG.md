# 问题处理与缺陷修复记录 (Issue & Defect Resolution Log)

本记录梳理了 OpenGuard 在研发与自测过程中发现并关闭的典型工程与技术缺陷，体现完整的缺陷溯源与回归验证闭环。

| 编号 | 发现阶段 | 问题描述 | 根因分析 | 修复方案与回归验证 | 状态 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ISS-001** | 跨平台测试 | Windows 下 `SQLite` 历史数据库测试结束后删除临时目录报 `PermissionError [WinError 32]` | Python `with sqlite3.connect(...) as conn:` 仅管理事务提交/回滚而不自动关闭文件句柄 | 在 `AuditHistoryStore._connect()` 中改用 `contextlib.closing` / `try-finally conn.close()`，所有句柄测试通过后立即释放 | 已修复 |
| **ISS-002** | 自动脱敏回归 | 执行 `autofix --secrets --apply` 后复扫仍提示 `.openguard_backup/` 目录内的备份源码含密钥 | `is_path_excluded()` 规范化相对路径时误用了 `.lstrip("./")`，导致 `.openguard_backup` 开头的点号 `.` 被剥离而逃逸 `DEFAULT_EXCLUDE_DIRS` | 改为精确剥离 `./` 前缀（`_strip_dot_slash`），恢复后 `.openguard_backup/` 100% 被跳过，脱敏后密钥数量稳定降为 0 | 已修复 |
| **ISS-003** | 许可证识别 | 中文版“木兰宽松许可证，第2版”或全称 `GNU General Public License v3` 识别为 `UNKNOWN` | 签名匹配采用全条件 `all()` 要求同时出现中英文简称且 `normalize_spdx_id` 未覆盖全称拼写 | 升级为多变体特征组匹配 `any(all(...))` 并补充全称规范化映射，`test_detects_mulan_psl_and_mit_licenses` 与 `test_normalize_spdx_variants` 通过 | 已修复 |
| **ISS-004** | 数据库凭据规则 | 密码中包含 `@` 字符（如包含 `@` 的数据库口令）时无法命中 `OG-SEC-038` | 正则密码分组使用 `[^@\s]+` 过早截断含 `@` 符号的强口令 | 改用允许密码含 `@` 并锚定末尾 `@hostname` 边界的正则模式，兼容各类复杂数据库密码 | 已修复 |
| **ISS-005** | 仓库管理规范 | 示例靶场若直接保留嵌套 `.git` 目录会导致主仓库误识别为 Git Submodule | Git 对嵌套 `.git` 目录默认按未跟踪子模块处理，不利于校内 `git.hust.edu.cn` 克隆复现 | 将源码靶场 `examples/vulnerable_demo_repo` 与独立历史构建脚本 `examples/setup_demo_git_history.py` 解耦，既无嵌套子模块污染，又可一键复现历史幽灵密钥扫描 | 已修复 |
