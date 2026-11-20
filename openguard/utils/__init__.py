"""Utility helpers for entropy calculation, AST context extraction, and LOC counting."""

from openguard.utils.ast_analyzer import CodeLineContext, analyze_generic_context, analyze_python_source
from openguard.utils.entropy import (
    character_class_diversity,
    is_likely_placeholder,
    mask_secret,
    normalized_entropy,
    shannon_entropy,
)
from openguard.utils.loc_counter import count_repository_loc

__all__ = [
    "CodeLineContext",
    "analyze_generic_context",
    "analyze_python_source",
    "character_class_diversity",
    "count_repository_loc",
    "is_likely_placeholder",
    "mask_secret",
    "normalized_entropy",
    "shannon_entropy",
]
