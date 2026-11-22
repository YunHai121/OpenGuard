"""OWASP CycloneDX 1.6 ML-BOM / AIBOM Static Discovery & Generator (cdxgen-inspired).

Statically discovers AI/ML supply-chain assets without executing repository code:
1. Local model weight artifacts (`*.safetensors`, `*.gguf`, `*.onnx`, `*.pt`, `*.ckpt`, `*.pkl`, `*.h5`)
   with SHA-256 digests and format safety classification (`safe` vs `pickle_risk`).
2. Open-weight models & datasets invoked in code (`from_pretrained("org/model")`, `load_dataset(...)`)
   with `pkg:huggingface/...` PURLs and revision-pinning status.
3. Managed / proprietary LLM API invocations (`model="gpt-4o"`, `claude-*`, `gemini-*`, `deepseek-*`, `qwen*`, etc.).

Outputs a CycloneDX 1.6 ML-BOM JSON document (`specVersion: "1.6"`) with `machine-learning-model`
and `data` components plus `modelCard` metadata.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from openguard import __version__
from openguard.config import DEFAULT_EXCLUDE_DIRS, is_path_excluded

MODEL_WEIGHT_FORMATS: Dict[str, Tuple[str, bool]] = {
    ".safetensors": ("SafeTensors", True),
    ".gguf": ("GGUF", True),
    ".onnx": ("ONNX", True),
    ".tflite": ("TFLite", True),
    ".mlmodel": ("CoreML", True),
    ".pt": ("PyTorch/Pickle", False),
    ".ckpt": ("PyTorch Checkpoint", False),
    ".pkl": ("Pickle", False),
    ".pickle": ("Pickle", False),
    ".h5": ("HDF5/Keras", False),
    ".joblib": ("Joblib/Pickle", False),
}

# Known managed / open-weight LLM model identifier prefixes
LLM_MODEL_ID_RE = re.compile(
    r"^(?:gpt-[345][a-z0-9.\-]*|o[134](?:-[a-z0-9.\-]+)?|claude-(?:[234]|sonnet|opus|haiku)[a-z0-9.\-]*|"
    r"gemini-[123][a-z0-9.\-]*|deepseek-[a-z0-9.\-]+|qwen[0-9.\-]*-[a-z0-9.\-]+|"
    r"glm-[345][a-z0-9.\-]*|moonshot-v[0-9a-z.\-]+|kimi-[a-z0-9.\-]+|doubao-[a-z0-9.\-]+|"
    r"llama-[234][a-z0-9.\-]*|mistral-[a-z0-9.\-]+|command-r[a-z0-9.\-]*)$",
    re.I,
)

JS_MODEL_ARG_RE = re.compile(r"""\bmodel\s*:\s*['"]([A-Za-z0-9._/\-]{4,80})['"]""")
HF_REPO_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]*/[A-Za-z0-9._\-]+$")


def _infer_provider(model_id: str) -> str:
    low = model_id.lower()
    if low.startswith(("gpt-", "o1", "o3", "o4")):
        return "OpenAI"
    if low.startswith("claude-"):
        return "Anthropic"
    if low.startswith("gemini-"):
        return "Google"
    if low.startswith("deepseek-"):
        return "DeepSeek"
    if low.startswith("qwen"):
        return "Alibaba Cloud (Qwen)"
    if low.startswith("glm-"):
        return "Zhipu AI"
    if low.startswith(("moonshot-", "kimi-")):
        return "Moonshot AI"
    if low.startswith("doubao-"):
        return "ByteDance (Volcengine)"
    if low.startswith("llama-"):
        return "Meta"
    if low.startswith("mistral-"):
        return "Mistral AI"
    if "/" in model_id:
        return model_id.split("/", 1)[0]
    return "Unknown"


def _sha256_file(path: Path, max_bytes: int = 64 * 1024 * 1024) -> Optional[str]:
    try:
        if path.stat().st_size > max_bytes:
            return None
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


@dataclass
class AIAsset:
    """Single discovered AI model, dataset, or weight artifact."""

    name: str
    asset_type: str  # "machine-learning-model" | "data"
    provider: str
    source_kind: str  # "local_weight" | "huggingface_model" | "huggingface_dataset" | "llm_api"
    source_file: str
    line_number: int = 1
    version: str = "unspecified"
    format_name: str = ""
    safe_format: Optional[bool] = None
    sha256: Optional[str] = None
    purl: str = ""
    pinned: bool = False


@dataclass
class AIBOMReport:
    """Aggregated AI Bill of Materials discovery result."""

    target_name: str
    assets: List[AIAsset] = field(default_factory=list)

    @property
    def model_count(self) -> int:
        return sum(1 for a in self.assets if a.asset_type == "machine-learning-model")

    @property
    def dataset_count(self) -> int:
        return sum(1 for a in self.assets if a.asset_type == "data")


def _extract_python_ai_assets(content: str, rel: str) -> List[AIAsset]:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []

    found: List[AIAsset] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # Resolve dotted call name
        fn_name = ""
        if isinstance(node.func, ast.Name):
            fn_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            fn_name = node.func.attr

        # 1. HuggingFace *.from_pretrained("org/model", revision="...")
        if fn_name == "from_pretrained" and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                model_id = first.value.strip()
                if model_id and (HF_REPO_ID_RE.match(model_id) or len(model_id) >= 4):
                    rev = "unspecified"
                    for kw in node.keywords:
                        if kw.arg == "revision" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                            rev = kw.value.value.strip()
                    purl = f"pkg:huggingface/{model_id}" + (f"@{rev}" if rev != "unspecified" else "")
                    found.append(
                        AIAsset(
                            name=model_id,
                            asset_type="machine-learning-model",
                            provider=_infer_provider(model_id),
                            source_kind="huggingface_model",
                            source_file=rel,
                            line_number=node.lineno,
                            version=rev,
                            format_name="HuggingFace Hub",
                            purl=purl,
                            pinned=rev != "unspecified" and rev.lower() != "main",
                        )
                    )

        # 2. HuggingFace load_dataset("org/dataset")
        elif fn_name == "load_dataset" and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                ds_id = first.value.strip()
                if ds_id and ds_id.lower() not in ("json", "csv", "parquet", "text", "arrow"):
                    rev = "unspecified"
                    for kw in node.keywords:
                        if kw.arg == "revision" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                            rev = kw.value.value.strip()
                    found.append(
                        AIAsset(
                            name=ds_id,
                            asset_type="data",
                            provider=_infer_provider(ds_id) if "/" in ds_id else "HuggingFace Datasets",
                            source_kind="huggingface_dataset",
                            source_file=rel,
                            line_number=node.lineno,
                            version=rev,
                            format_name="HuggingFace Dataset",
                            purl=f"pkg:huggingface-dataset/{ds_id}" + (f"@{rev}" if rev != "unspecified" else ""),
                            pinned=rev != "unspecified",
                        )
                    )

        # 3. Managed LLM API calls passing keyword `model="gpt-4o"` / `claude-*` / `gemini-*` / `deepseek-*`
        for kw in node.keywords:
            if kw.arg == "model" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                mid = kw.value.value.strip()
                if LLM_MODEL_ID_RE.match(mid):
                    found.append(
                        AIAsset(
                            name=mid,
                            asset_type="machine-learning-model",
                            provider=_infer_provider(mid),
                            source_kind="llm_api",
                            source_file=rel,
                            line_number=node.lineno,
                            version="api-managed",
                            format_name="Managed LLM API",
                            safe_format=True,
                            purl=f"pkg:ai-model/{_infer_provider(mid).lower().replace(' ', '-')}/{mid}",
                            pinned=True,
                        )
                    )
    return found


def _extract_js_ai_assets(content: str, rel: str) -> List[AIAsset]:
    found: List[AIAsset] = []
    for idx, line in enumerate(content.splitlines(), start=1):
        for m in JS_MODEL_ARG_RE.finditer(line):
            mid = m.group(1).strip()
            if LLM_MODEL_ID_RE.match(mid):
                found.append(
                    AIAsset(
                        name=mid,
                        asset_type="machine-learning-model",
                        provider=_infer_provider(mid),
                        source_kind="llm_api",
                        source_file=rel,
                        line_number=idx,
                        version="api-managed",
                        format_name="Managed LLM API",
                        safe_format=True,
                        purl=f"pkg:ai-model/{_infer_provider(mid).lower().replace(' ', '-')}/{mid}",
                        pinned=True,
                    )
                )
    return found


def discover_ai_assets(root_path: Path, exclude_patterns: Optional[List[str]] = None) -> AIBOMReport:
    """Statically scan a repository to build its AI Bill of Materials (AIBOM)."""
    root = Path(root_path).resolve()
    if root.is_file():
        root = root.parent
    excludes = exclude_patterns or []

    assets: List[AIAsset] = []
    seen_keys: Set[Tuple[str, str, str]] = set()

    def _add(asset: AIAsset) -> None:
        key = (asset.source_kind, asset.name.lower(), asset.source_file)
        if key not in seen_keys:
            seen_keys.add(key)
            assets.append(asset)

    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).resolve().relative_to(root).as_posix()
        dirnames[:] = [
            d
            for d in sorted(dirnames)
            if d not in DEFAULT_EXCLUDE_DIRS
            and not is_path_excluded(f"{rel_dir}/{d}/" if rel_dir != "." else f"{d}/", excludes)
        ]
        for fname in sorted(filenames):
            fpath = Path(dirpath) / fname
            rel = fpath.relative_to(root).as_posix()
            if is_path_excluded(rel, excludes):
                continue
            ext = fpath.suffix.lower()

            if ext in MODEL_WEIGHT_FORMATS:
                fmt_name, is_safe = MODEL_WEIGHT_FORMATS[ext]
                digest = _sha256_file(fpath)
                _add(
                    AIAsset(
                        name=fname,
                        asset_type="machine-learning-model",
                        provider="Local Artifact",
                        source_kind="local_weight",
                        source_file=rel,
                        version=digest[:12] if digest else "local",
                        format_name=fmt_name,
                        safe_format=is_safe,
                        sha256=digest,
                        purl=f"pkg:generic/{fname}" + (f"@{digest[:12]}" if digest else ""),
                        pinned=bool(digest),
                    )
                )
            elif ext == ".py":
                try:
                    if fpath.stat().st_size <= 1024 * 1024:
                        txt = fpath.read_text(encoding="utf-8", errors="replace")
                        for a in _extract_python_ai_assets(txt, rel):
                            _add(a)
                except OSError:
                    continue
            elif ext in (".js", ".ts", ".jsx", ".tsx", ".mjs"):
                try:
                    if fpath.stat().st_size <= 1024 * 1024:
                        txt = fpath.read_text(encoding="utf-8", errors="replace")
                        for a in _extract_js_ai_assets(txt, rel):
                            _add(a)
                except OSError:
                    continue

    return AIBOMReport(target_name=root.name, assets=assets)


def render_cyclonedx_aibom(aibom: AIBOMReport) -> Dict[str, Any]:
    """Render an AIBOMReport into a standard OWASP CycloneDX 1.6 ML-BOM JSON document."""
    components: List[Dict[str, Any]] = []
    for idx, a in enumerate(aibom.assets, start=1):
        comp: Dict[str, Any] = {
            "type": a.asset_type,
            "bom-ref": a.purl or f"ai-asset-{idx}-{a.name}",
            "name": a.name,
            "version": a.version,
            "supplier": {"name": a.provider},
            "properties": [
                {"name": "openguard:ai_source_kind", "value": a.source_kind},
                {"name": "openguard:source_file", "value": f"{a.source_file}:{a.line_number}"},
                {"name": "openguard:format", "value": a.format_name},
                {"name": "openguard:version_pinned", "value": str(a.pinned).lower()},
            ],
        }
        if a.purl:
            comp["purl"] = a.purl
        if a.sha256:
            comp["hashes"] = [{"alg": "SHA-256", "content": a.sha256}]
        if a.safe_format is not None:
            comp["properties"].append({"name": "openguard:format_execution_safe", "value": str(a.safe_format).lower()})
        if a.asset_type == "machine-learning-model":
            comp["modelCard"] = {
                "modelParameters": {
                    "approach": {"type": "generative" if a.source_kind == "llm_api" else "supervised-or-foundation"},
                    "architectureFamily": a.format_name or "ML Model",
                }
            }
        components.append(comp)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "OpenGuard",
                        "version": __version__,
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": aibom.target_name,
            },
        },
        "components": components,
    }
