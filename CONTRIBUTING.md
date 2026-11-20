# Contributing to OpenGuard (开源卫士)

感谢你对 **OpenGuard** 开源项目的关注与支持！我们欢迎任何形式的贡献，包括新规则提交、语言解析器扩展、漏洞/许可证知识库完善、UI 优化以及文档改进。

---

## 1. 开发环境搭建

```bash
git clone <repository-url> OpenGuard
cd OpenGuard
pip install -r requirements.txt
pip install -e . --no-build-isolation --no-deps
```

## 2. 运行测试与基准实验

提交 PR 前请务必运行完整测试集与基准对比实验，确保所有测试通过：

```bash
# 运行完整自动化测试套件 (unittest)
python -m unittest discover -s tests -v

# 运行三阶混合引擎 vs 基线对比实验
python benchmarks/run_benchmark.py

# 使用 OpenGuard 对自身仓库执行自审计
openguard scan . --offline --fail-on high
```

## 3. 代码规范与防泄密门禁

1. **UTF-8 跨平台安全**：所有文件读写与 `subprocess.run` 必须显式传入 `encoding="utf-8"`，确保 Windows 与 Linux 表现一致。
2. **禁止真实凭据入库**：新增测试用例、靶场或 Benchmark 中的测试密钥必须为随机生成的伪造合成字符串，且应放置于 `.openguardignore` 覆盖的测试目录或使用 `# openguard: ignore` 显式标记。
3. **安装提交前防御钩子**：
   ```bash
   openguard hook install .
   ```

## 4. Commit 规范

采用约定式提交（Conventional Commits）：
- `feat:` 新增检测规则、生态解析器或可视化功能
- `fix:` 修复误报、跨平台兼容性或安全缺陷
- `perf:` 性能优化与算法加速
- `docs:` 文档与模板说明更新
- `test:` 单元测试与 Benchmark 补充
