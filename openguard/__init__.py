"""OpenGuard (开源卫士) — Open-Source Supply-Chain Security, License Compliance & Governance Auditor."""

from openguard.auditor import OpenGuardAuditor
from openguard.config import AuditConfig
from openguard.models import AuditReport, Severity

__version__ = "1.5.0"

__all__ = [
    "AuditConfig",
    "AuditReport",
    "OpenGuardAuditor",
    "Severity",
    "__version__",
]
