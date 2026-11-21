"""Core Pydantic v2 data models for OpenGuard audit reports and findings."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    """Unified risk severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_ORDER: Dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class FindingCategory(str, Enum):
    """High-level audit finding classification."""

    SECRET = "SECRET"
    GIT_HISTORY_SECRET = "GIT_HISTORY_SECRET"
    VULNERABILITY = "VULNERABILITY"
    TYPOSQUATTING = "TYPOSQUATTING"
    SUPPLY_CHAIN_SCRIPT = "SUPPLY_CHAIN_SCRIPT"
    LICENSE_CONFLICT = "LICENSE_CONFLICT"
    CODE_SECURITY = "CODE_SECURITY"
    GOVERNANCE = "GOVERNANCE"


class LicenseCompatibility(str, Enum):
    """SPDX license compatibility judgment relative to project license."""

    COMPATIBLE = "COMPATIBLE"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    INCOMPATIBLE = "INCOMPATIBLE"
    UNKNOWN = "UNKNOWN"


class SecretFinding(BaseModel):
    """Detected hardcoded secret, token, private key, or sensitive PII."""

    model_config = ConfigDict(use_enum_values=True)

    id: str = Field(default_factory=lambda: f"SEC-{uuid4().hex[:8].upper()}")
    rule_id: str
    rule_name: str
    category: FindingCategory = FindingCategory.SECRET
    severity: Severity
    file_path: str
    line_number: int
    column: int = 1
    matched_masked: str
    raw_hash: str
    snippet: str = ""
    entropy: float = 0.0
    confidence: float = 1.0
    ast_context: str = "generic"
    filter_notes: List[str] = Field(default_factory=list)
    remediation: str = ""
    runbook_steps: List[str] = Field(default_factory=list)
    cwe_id: str = "CWE-798"
    commit_hash: Optional[str] = None
    commit_author: Optional[str] = None
    commit_date: Optional[str] = None
    is_historical_only: bool = False


class DependencyComponent(BaseModel):
    """Parsed third-party software dependency component (SBOM node)."""

    model_config = ConfigDict(use_enum_values=True)

    name: str
    version: str = "unspecified"
    ecosystem: str
    source_file: str
    direct: bool = True
    license_id: str = "UNKNOWN"
    license_source: str = "unknown"
    dependencies: List[str] = Field(default_factory=list)
    purl: str = ""
    used_in_code: bool = False
    import_locations: List[str] = Field(default_factory=list)


class LicenseConflict(BaseModel):
    """Open-source license incompatibility or copyleft propagation risk."""

    model_config = ConfigDict(use_enum_values=True)

    id: str = Field(default_factory=lambda: f"LIC-{uuid4().hex[:8].upper()}")
    component_name: str
    component_version: str
    component_license: str
    project_license: str
    compatibility: LicenseCompatibility
    severity: Severity
    dependency_path: List[str] = Field(default_factory=list)
    explanation: str
    remediation: str


class VulnerabilityFinding(BaseModel):
    """Supply-chain vulnerability or typosquatting finding."""

    model_config = ConfigDict(use_enum_values=True)

    id: str
    component_name: str
    component_version: str
    ecosystem: str
    severity: Severity
    cvss_score: float = 0.0
    summary: str
    fixed_version: str = "Check upstream release"
    references: List[str] = Field(default_factory=list)
    source: str = "offline_db"
    category: FindingCategory = FindingCategory.VULNERABILITY
    remediation: str = ""
    source_file: str = ""
    reachable: Optional[bool] = None
    reachability_level: str = "unknown"  # "call_reachable" | "import_only" | "unreachable" | "unknown"
    import_locations: List[str] = Field(default_factory=list)
    call_locations: List[str] = Field(default_factory=list)


class CodeSecurityFinding(BaseModel):
    """Static Application Security Testing (SAST) finding."""

    model_config = ConfigDict(use_enum_values=True)

    id: str = Field(default_factory=lambda: f"SAST-{uuid4().hex[:8].upper()}")
    rule_id: str
    rule_name: str
    cwe_id: str
    severity: Severity
    file_path: str
    line_number: int
    snippet: str
    description: str
    remediation: str


class GovernanceCheckItem(BaseModel):
    """Open-source engineering governance and documentation check."""

    check_id: str
    name: str
    category: str
    passed: bool
    score: float
    max_score: float
    details: str
    remediation: str
    autofixable: bool = False


class DimensionScore(BaseModel):
    """Score breakdown for a single audit dimension."""

    name: str
    key: str
    score: float
    weight: float
    weighted_score: float
    issue_count: int
    summary: str


class QualityGateCondition(BaseModel):
    """Single deterministic SonarQube-style quality gate condition."""

    metric: str
    label: str
    actual: int
    threshold: str
    passed: bool


class QualityGate(BaseModel):
    """Overall release readiness decision across security & compliance gates."""

    status: str  # "PASSED" | "FAILED"
    conditions: List[QualityGateCondition] = Field(default_factory=list)


class AuditSummary(BaseModel):
    """Top-level quantified audit metrics and prioritization roadmap."""

    total_score: float
    grade: str
    dimensions: List[DimensionScore] = Field(default_factory=list)
    severity_counts: Dict[str, int] = Field(default_factory=dict)
    files_scanned: int = 0
    lines_scanned: int = 0
    scan_duration_ms: float = 0.0
    roadmap: List[Dict[str, Any]] = Field(default_factory=list)
    quality_gate: Optional[QualityGate] = None


class AuditReport(BaseModel):
    """Complete OpenGuard audit report artifact."""

    model_config = ConfigDict(use_enum_values=True)

    tool_version: str = "1.2.0"
    scan_id: str = Field(default_factory=lambda: f"OG-{uuid4().hex[:10].upper()}")
    scanned_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    )
    target_path: str
    target_name: str
    project_license: str = "UNKNOWN"
    git_branch: Optional[str] = None
    git_commit: Optional[str] = None
    diff_base_ref: Optional[str] = None
    summary: AuditSummary
    secrets: List[SecretFinding] = Field(default_factory=list)
    git_history_secrets: List[SecretFinding] = Field(default_factory=list)
    components: List[DependencyComponent] = Field(default_factory=list)
    dependency_edges: List[Tuple[str, str]] = Field(default_factory=list)
    license_conflicts: List[LicenseConflict] = Field(default_factory=list)
    vulnerabilities: List[VulnerabilityFinding] = Field(default_factory=list)
    code_security_findings: List[CodeSecurityFinding] = Field(default_factory=list)
    governance_checks: List[GovernanceCheckItem] = Field(default_factory=list)
    suppressed_count: int = 0
    suppressed_samples: List[Dict[str, Any]] = Field(default_factory=list)
    baseline_suppressed_count: int = 0
