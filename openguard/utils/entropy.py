"""Shannon information entropy, placeholder filtering, and secret masking utilities."""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Tuple

PLACEHOLDER_KEYWORDS = (
    "example",
    "sample",
    "dummy",
    "placeholder",
    "changeme",
    "change_me",
    "replace_me",
    "replace-with",
    "your_api_key",
    "your-api-key",
    "your_token",
    "your-token",
    "your_secret",
    "your-secret",
    "your_key",
    "your-key",
    "insert_here",
    "put_your",
    "test_key",
    "test_token",
    "test_secret",
    "fake_key",
    "fake_token",
    "fake_secret",
    "mock_key",
    "mock_token",
    "dummy_secret",
    "not_a_secret",
    "redacted",
    "masked",
    "...",
    "<your",
    "<password",
    "<secret",
    "<token",
    "@host",
    "${",
    "{{",
)

HEX_ONLY_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def shannon_entropy(data: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def normalized_entropy(data: str) -> float:
    """Compute entropy normalized to [0.0, 1.0] against log2(min(len, alphabet))."""
    if len(data) <= 1:
        return 0.0
    max_ent = math.log2(min(len(data), 64))
    if max_ent == 0:
        return 0.0
    return round(min(1.0, shannon_entropy(data) / max_ent), 4)


def character_class_diversity(data: str) -> int:
    """Count distinct character classes present in `data` (1 to 4)."""
    classes = 0
    if any(c.isdigit() for c in data):
        classes += 1
    if any(c.islower() for c in data):
        classes += 1
    if any(c.isupper() for c in data):
        classes += 1
    if any(not c.isalnum() for c in data):
        classes += 1
    return classes


def is_likely_placeholder(value: str) -> Tuple[bool, str]:
    """Identify obvious placeholders, repeated tokens, sequential strings, or UUIDs."""
    if not value:
        return True, "empty_value"

    stripped = value.strip().strip("\"'`")
    lower = stripped.lower()

    if len(stripped) < 6:
        return True, "too_short"

    for kw in PLACEHOLDER_KEYWORDS:
        if kw in lower:
            return True, f"placeholder_keyword:{kw}"

    # Repeated single character or tiny period (e.g. xxxxxxxxxx, 00000000, abababab)
    if len(set(lower)) <= 2:
        return True, "low_unique_chars"

    if "xxxx" in lower or "000000" in lower or "111111" in lower or "******" in stripped:
        return True, "repeated_filler_pattern"

    # Common sequential patterns
    if any(seq in lower for seq in ("12345678", "87654321", "abcdefgh", "qwertyui")):
        return True, "sequential_pattern"

    if UUID_RE.match(stripped):
        return True, "uuid_identifier"

    # Check if string is an all-caps placeholder with underscores like YOUR_ACCESS_TOKEN_HERE
    if re.fullmatch(r"[A-Z0-9_]{8,}", stripped) and "_" in stripped and any(
        w in lower for w in ("your", "here", "enter", "secret", "token", "key", "password", "demo")
    ):
        return True, "symbolic_placeholder"

    return False, ""


def is_pure_hex_hash(value: str) -> bool:
    """Return True if value looks like a pure hex checksum/git-sha rather than prefixed token."""
    return bool(HEX_ONLY_RE.match(value.strip()))


def mask_secret(value: str, prefix_keep: int = 4, suffix_keep: int = 3) -> str:
    """Safely mask sensitive values before placing them into reports or logs."""
    cleaned = value.strip()
    if len(cleaned) <= 8:
        return cleaned[:2] + "****" if len(cleaned) > 2 else "****"
    if len(cleaned) <= prefix_keep + suffix_keep + 2:
        return cleaned[:2] + "****" + cleaned[-2:]
    return f"{cleaned[:prefix_keep]}****{cleaned[-suffix_keep:]}"
