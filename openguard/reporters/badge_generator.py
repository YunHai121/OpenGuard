"""Shields.io-style SVG badge generator for OpenGuard audit scores."""

from __future__ import annotations

from openguard.models import AuditReport


def render_badge_svg(report: AuditReport) -> str:
    """Render a crisp, standalone flat SVG badge reflecting OpenGuard grade and score."""
    grade = report.summary.grade
    score = report.summary.total_score

    if score >= 90:
        color = "#10b981"  # emerald
    elif score >= 80:
        color = "#3b82f6"  # blue
    elif score >= 70:
        color = "#f59e0b"  # amber
    else:
        color = "#ef4444"  # red

    left_text = "OpenGuard"
    right_text = f"{grade} ({score:.0f}/100)"

    left_w = 78
    right_w = max(84, len(right_text) * 7 + 16)
    total_w = left_w + right_w

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="22" role="img" aria-label="{left_text}: {right_text}">
  <linearGradient id="og-b" x2="0" y2="100%">
    <stop offset="0" stop-color="#fff" stop-opacity=".12"/>
    <stop offset="1" stop-opacity=".14"/>
  </linearGradient>
  <clipPath id="og-r">
    <rect width="{total_w}" height="22" rx="4" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#og-r)">
    <rect width="{left_w}" height="22" fill="#1e293b"/>
    <rect x="{left_w}" width="{right_w}" height="22" fill="{color}"/>
    <rect width="{total_w}" height="22" fill="url(#og-b)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11" font-weight="600">
    <text x="{left_w / 2:.1f}" y="15">{left_text}</text>
    <text x="{left_w + right_w / 2:.1f}" y="15">{right_text}</text>
  </g>
</svg>
"""
