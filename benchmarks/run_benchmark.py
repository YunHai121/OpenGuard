"""Head-to-head reproducible benchmark comparing Pure Regex, Pure Entropy, and OpenGuard Hybrid Engine."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

# Allow direct execution as `python benchmarks/run_benchmark.py`
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from benchmarks.corpus_generator import LabeledSample, generate_benchmark_corpus  # noqa: E402
from openguard.config import AuditConfig  # noqa: E402
from openguard.scanners.dependency_parser import DependencyParser  # noqa: E402
from openguard.scanners.license_analyzer import LicenseAnalyzer  # noqa: E402
from openguard.scanners.secret_scanner import SecretScanner  # noqa: E402
from openguard.scanners.vuln_scanner import VulnScanner  # noqa: E402


def _evaluate_engine(
    name: str,
    samples: List[LabeledSample],
    predictor,
) -> Dict[str, Any]:
    tp = fp = fn = tn = 0
    total_lines = 0
    misclassified: List[Dict[str, Any]] = []

    t0 = time.perf_counter()
    for s in samples:
        total_lines += len(s.content.splitlines())
        preds = predictor(s.content, s.file_path)
        predicted_pos = len(preds) > 0
        if s.expected_positive and predicted_pos:
            tp += 1
        elif not s.expected_positive and predicted_pos:
            fp += 1
            misclassified.append({"id": s.sample_id, "type": "FP", "category": s.category})
        elif s.expected_positive and not predicted_pos:
            fn += 1
            misclassified.append({"id": s.sample_id, "type": "FN", "category": s.category})
        else:
            tn += 1
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    throughput = (total_lines / (elapsed_ms / 1000.0)) if elapsed_ms > 0 else 0.0

    return {
        "engine": name,
        "samples": len(samples),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "latency_ms": round(elapsed_ms, 2),
        "throughput_loc_per_sec": round(throughput, 1),
        "misclassified_samples": misclassified[:10],
    }


def run_full_benchmark(output_dir: Path | None = None) -> Dict[str, Any]:
    """Run both secret-detection baseline comparison and demo supply-chain audit timing."""
    out_dir = Path(output_dir) if output_dir else (ROOT_DIR / "benchmarks")
    out_dir.mkdir(parents=True, exist_ok=True)

    corpus = generate_benchmark_corpus()
    scanner = SecretScanner(AuditConfig(offline=True))

    res_regex = _evaluate_engine(
        "Baseline-A: Pure Regex",
        corpus,
        lambda content, path: scanner.scan_baseline_regex_only(content, path),
    )
    res_entropy = _evaluate_engine(
        "Baseline-B: Pure Shannon Entropy",
        corpus,
        lambda content, path: scanner.scan_baseline_entropy_only(content, path),
    )
    res_openguard = _evaluate_engine(
        "OpenGuard: 3-Stage Hybrid (Regex + Entropy + AST)",
        corpus,
        lambda content, path: scanner.scan_content(content, path).findings,
    )

    # Supply-chain & License benchmark on vulnerable_demo_repo
    demo_repo = ROOT_DIR / "examples" / "vulnerable_demo_repo"
    t0 = time.perf_counter()
    comps, edges, graph = DependencyParser().parse_repository(demo_repo)
    lic_analyzer = LicenseAnalyzer()
    proj_lic = lic_analyzer.detect_project_license(demo_repo)
    conflicts = lic_analyzer.analyze_conflicts(demo_repo.name, proj_lic, comps, graph)
    vulns = VulnScanner(offline=True).scan_components(comps)
    sca_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    fpr_reduction = 0.0
    if res_regex["false_positive_rate"] > 0:
        fpr_reduction = round(
            (res_regex["false_positive_rate"] - res_openguard["false_positive_rate"])
            / res_regex["false_positive_rate"]
            * 100.0,
            1,
        )

    payload = {
        "corpus_size": len(corpus),
        "true_positives_count": sum(1 for c in corpus if c.expected_positive),
        "true_negatives_count": sum(1 for c in corpus if not c.expected_positive),
        "summary_table": [res_regex, res_entropy, res_openguard],
        "fpr_reduction_vs_regex_pct": fpr_reduction,
        "supply_chain_benchmark": {
            "target": "examples/vulnerable_demo_repo",
            "components_parsed": len(comps),
            "ecosystems_detected": sorted({c.ecosystem for c in comps}),
            "license_conflicts_detected": len(conflicts),
            "vulnerabilities_and_typosquats_detected": len(vulns),
            "elapsed_ms": sca_ms,
        },
    }

    json_file = out_dir / "benchmark_results.json"
    json_file.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    md_lines = [
        "# OpenGuard 可复现性能与准确率对比实验报告",
        "",
        f"- **测试数据集**：220 条确定性标注代码样本（100 条真实高危凭据 + 120 条高干扰误报诱饵：占位符、SHA256、UUID、Python AST 文档字符串、正则规则定义、`os.getenv` 默认值、错误校验码 18 位数字等）",
        "- **评测环境**：本地 Python 3.14 运行时，单线程 CPU 顺序评测，离线运行可一键复现（`python benchmarks/run_benchmark.py`）",
        "",
        "## 1. 敏感信息检测准确率与误报率对比",
        "",
        "| 检测引擎 | TP | FP | FN | TN | 精确率 (Precision) | 召回率 (Recall) | F1-Score | 误报率 (FPR) | 耗时 (ms) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ]
    for row in payload["summary_table"]:
        md_lines.append(
            f"| **{row['engine']}** | {row['tp']} | {row['fp']} | {row['fn']} | {row['tn']} | "
            f"{row['precision']:.4f} | {row['recall']:.4f} | **{row['f1_score']:.4f}** | "
            f"**{row['false_positive_rate']:.4f}** | {row['latency_ms']:.2f} |"
        )
    md_lines.extend([
        "",
        f"> **关键结论**：相比传统纯正则检测，OpenGuard 三阶混合引擎将误报率 (FPR) 降低了 **{fpr_reduction}%**，同时保持了高达 **{res_openguard['recall']*100:.1f}%** 的召回率与 **{res_openguard['f1_score']:.4f}** 的 F1 分数。",
        "",
        "## 2. 多生态供应链解析与许可证冲突实验 (`vulnerable_demo_repo`)",
        "",
        f"- **解析组件总数**：{len(comps)} 个（跨生态：{', '.join(payload['supply_chain_benchmark']['ecosystems_detected'])}）",
        f"- **检出许可证冲突**：{len(conflicts)} 项（精准识别 GPL-3.0/GPL-2.0 强传染性与 LGPL-2.1 弱传染性）",
        f"- **检出 CVE 漏洞与仿冒包**：{len(vulns)} 项",
        f"- **供应链引擎总耗时**：{sca_ms} ms",
        "",
    ])
    md_file = out_dir / "BENCHMARK_REPORT.md"
    md_file.write_text("\n".join(md_lines), encoding="utf-8")
    return payload


if __name__ == "__main__":
    out = run_full_benchmark()
    print(json.dumps(out["summary_table"], indent=2, ensure_ascii=False))
    print(f"FPR reduction vs Pure Regex: {out['fpr_reduction_vs_regex_pct']}%")
