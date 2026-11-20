"""Formal Chinese/English PDF audit report generator built on ReportLab."""

from __future__ import annotations

import os
from io import BytesIO
from pathlib import Path
from typing import List
from xml.sax.saxutils import escape

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from openguard.models import AuditReport

_REGISTERED_FONT: str | None = None


def _ensure_cjk_font() -> str:
    """Register a reliable CJK font with Windows TTF priority and built-in CID fallback."""
    global _REGISTERED_FONT
    if _REGISTERED_FONT:
        return _REGISTERED_FONT

    ttf_candidates = [
        r"C:\Windows\Fonts\simhei.ttf",
        r"C:\Windows\Fonts\Deng.ttf",
        r"C:\Windows\Fonts\msyh.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/System/Library/Fonts/PingFang.ttc",
    ]
    for path in ttf_candidates:
        if os.path.isfile(path):
            try:
                font_name = "OpenGuardCJK"
                pdfmetrics.registerFont(TTFont(font_name, path))
                _REGISTERED_FONT = font_name
                return font_name
            except Exception:
                continue

    # Cross-platform built-in ReportLab CID fallback
    pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
    _REGISTERED_FONT = "STSong-Light"
    return _REGISTERED_FONT


def _make_dimension_chart(report: AuditReport, font_name: str) -> Drawing:
    drawing = Drawing(460, 150)
    bc = VerticalBarChart()
    bc.x = 38
    bc.y = 28
    bc.height = 105
    bc.width = 400
    bc.data = [[d.score for d in report.summary.dimensions]]
    bc.valueAxis.valueMin = 0
    bc.valueAxis.valueMax = 100
    bc.valueAxis.valueStep = 25
    bc.categoryAxis.categoryNames = [
        "密钥安全",
        "供应链漏洞",
        "许可证合规",
        "代码安全",
        "工程治理",
    ]
    bc.categoryAxis.labels.fontName = font_name
    bc.categoryAxis.labels.fontSize = 8
    bc.bars[0].fillColor = colors.HexColor("#4f46e5")
    bc.bars[0].strokeColor = colors.HexColor("#312e81")
    drawing.add(bc)
    return drawing


def render_pdf_bytes(report: AuditReport) -> bytes:
    """Generate a formatted PDF audit report and return raw PDF bytes."""
    font_name = _ensure_cjk_font()
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"OpenGuard Audit Report - {report.target_name}",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "OGTitle",
        parent=styles["Title"],
        fontName=font_name,
        fontSize=18,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6,
    )
    h2_style = ParagraphStyle(
        "OGH2",
        parent=styles["Heading2"],
        fontName=font_name,
        fontSize=12.5,
        leading=17,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "OGBody",
        parent=styles["Normal"],
        fontName=font_name,
        fontSize=9,
        leading=13.5,
        textColor=colors.HexColor("#334155"),
    )
    cell_style = ParagraphStyle(
        "OGCell",
        parent=styles["Normal"],
        fontName=font_name,
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#1e293b"),
    )

    def p(text: str, style: ParagraphStyle = cell_style) -> Paragraph:
        return Paragraph(escape(str(text)), style)

    s = report.summary
    story: List[object] = []

    story.append(p(f"OpenGuard 开源供应链安全与合规审计报告", title_style))
    story.append(
        p(
            f"目标项目：{report.target_name}  |  综合评分：{s.total_score:.1f}/100（等级 {s.grade}）  |  "
            f"项目许可证：{report.project_license}  |  扫描编号：{report.scan_id}",
            body_style,
        )
    )
    story.append(
        p(
            f"扫描时间：{report.scanned_at}  |  扫描文件数：{s.files_scanned}  |  "
            f"代码行数：{s.lines_scanned}  |  已智能过滤误报：{report.suppressed_count} 条",
            body_style,
        )
    )
    story.append(Spacer(1, 8))

    # Dimension Chart
    story.append(p("一、五维量化评分可视化概览", h2_style))
    story.append(_make_dimension_chart(report, font_name))

    dim_rows = [[p("评估维度"), p("得分"), p("权重"), p("问题数"), p("诊断摘要")]]
    for d in s.dimensions:
        dim_rows.append(
            [
                p(d.name),
                p(f"{d.score:.1f}"),
                p(f"{int(d.weight * 100)}%"),
                p(str(d.issue_count)),
                p(d.summary),
            ]
        )
    dim_table = Table(dim_rows, colWidths=[42 * mm, 16 * mm, 16 * mm, 16 * mm, 88 * mm])
    dim_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ]
        )
    )
    story.append(dim_table)

    # Secrets & Git History
    all_secrets = [*report.secrets, *report.git_history_secrets]
    story.append(p(f"二、敏感信息与 Git 历史泄露检测 ({len(all_secrets)} 项)", h2_style))
    if all_secrets:
        sec_rows = [[p("级别"), p("规则名称"), p("位置"), p("脱敏凭据"), p("上下文 / 历史")]]
        for f in all_secrets[:35]:
            ctx_txt = f"历史 {f.commit_hash}" if f.is_historical_only else f"{f.confidence:.2f} ({f.ast_context})"
            sec_rows.append(
                [
                    p(str(f.severity)),
                    p(f.rule_name),
                    p(f"{f.file_path}:{f.line_number}"),
                    p(f.matched_masked),
                    p(ctx_txt),
                ]
            )
        t = Table(sec_rows, colWidths=[18 * mm, 44 * mm, 48 * mm, 32 * mm, 36 * mm])
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#991b1b")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(t)
    else:
        story.append(p("未发现高置信度敏感信息硬编码或 Git 历史泄密。", body_style))

    # License Conflicts
    story.append(p(f"三、开源许可证传染性与兼容性分析 ({len(report.license_conflicts)} 项)", h2_style))
    if report.license_conflicts:
        lic_rows = [[p("组件"), p("组件许可证"), p("判定"), p("依赖传播路径")]]
        for lc in report.license_conflicts[:25]:
            lic_rows.append(
                [
                    p(f"{lc.component_name}@{lc.component_version}"),
                    p(lc.component_license),
                    p(f"{lc.compatibility} ({lc.severity})"),
                    p(" -> ".join(lc.dependency_path)),
                ]
            )
        lt = Table(lic_rows, colWidths=[45 * mm, 30 * mm, 38 * mm, 65 * mm])
        lt.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#92400e")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(lt)
    else:
        story.append(p("所有已识别依赖许可证与项目主许可证均兼容。", body_style))

    # Vulnerabilities & Typosquatting
    story.append(p(f"四、供应链漏洞与仿冒包告警 ({len(report.vulnerabilities)} 项)", h2_style))
    if report.vulnerabilities:
        v_rows = [[p("编号"), p("组件与版本"), p("级别 / CVSS"), p("安全版本"), p("漏洞摘要")]]
        for v in report.vulnerabilities[:25]:
            v_rows.append(
                [
                    p(v.id),
                    p(f"{v.component_name}@{v.component_version}"),
                    p(f"{v.severity} ({v.cvss_score})"),
                    p(v.fixed_version),
                    p(v.summary),
                ]
            )
        vt = Table(v_rows, colWidths=[32 * mm, 36 * mm, 24 * mm, 22 * mm, 64 * mm])
        vt.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3730a3")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(vt)
    else:
        story.append(p("未命中已知高危 CVE 漏洞或拼写仿冒包。", body_style))

    # Code Security (SAST)
    if report.code_security_findings:
        story.append(p(f"五、静态代码安全缺陷 SAST ({len(report.code_security_findings)} 项)", h2_style))
        s_rows = [[p("CWE"), p("级别"), p("位置"), p("问题描述与修复建议")]]
        for cs in report.code_security_findings[:25]:
            s_rows.append(
                [
                    p(cs.cwe_id),
                    p(str(cs.severity)),
                    p(f"{cs.file_path}:{cs.line_number}"),
                    p(f"{cs.description} 建议：{cs.remediation}"),
                ]
            )
        st = Table(s_rows, colWidths=[20 * mm, 18 * mm, 45 * mm, 95 * mm])
        st.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(st)

    # Governance
    story.append(p("六、开源工程规范与治理检查清单", h2_style))
    g_rows = [[p("检查项"), p("状态"), p("得分"), p("检查说明")]]
    for g in report.governance_checks:
        g_rows.append(
            [
                p(g.name),
                p("通过" if g.passed else "待完善"),
                p(f"{g.score:.0f}/{g.max_score:.0f}"),
                p(g.details),
            ]
        )
    gt = Table(g_rows, colWidths=[46 * mm, 18 * mm, 18 * mm, 96 * mm])
    gt.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#065f46")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(gt)

    doc.build(story)
    return buf.getvalue()
