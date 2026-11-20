"""Automated remediation modules for secret extraction, doc generation, and Git hook setup."""

from openguard.remediation.doc_generator import DocGenerator
from openguard.remediation.hook_installer import HookInstaller
from openguard.remediation.secret_remediator import SecretRemediator

__all__ = ["DocGenerator", "HookInstaller", "SecretRemediator"]
