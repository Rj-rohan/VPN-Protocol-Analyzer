"""Shared ReportLab building blocks for executive and technical reports."""
from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

INK = colors.HexColor("#14171f")
MUTED = colors.HexColor("#5b6272")
RULE = colors.HexColor("#d7dbe3")
ACCENT = colors.HexColor("#1f4fd1")
SEVERITY_COLORS = {
    "Critical": colors.HexColor("#b3261e"), "High": colors.HexColor("#d9480f"),
    "Medium": colors.HexColor("#b08900"), "Low": colors.HexColor("#2f6f4f"),
}

_base = getSampleStyleSheet()
STYLES = {
    "title": ParagraphStyle("title", parent=_base["Title"], fontName="Helvetica-Bold", fontSize=20, leading=24, textColor=INK, alignment=TA_LEFT, spaceAfter=2),
    "subtitle": ParagraphStyle("subtitle", parent=_base["Normal"], fontSize=9.5, leading=13, textColor=MUTED),
    "h1": ParagraphStyle("h1", parent=_base["Heading2"], fontName="Helvetica-Bold", fontSize=13, leading=16, textColor=INK, spaceBefore=12, spaceAfter=5),
    "h2": ParagraphStyle("h2", parent=_base["Heading3"], fontName="Helvetica-Bold", fontSize=10.5, leading=13, textColor=INK, spaceBefore=8, spaceAfter=3),
    "body": ParagraphStyle("body", parent=_base["Normal"], fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=INK, spaceAfter=5),
    "small": ParagraphStyle("small", parent=_base["Normal"], fontName="Helvetica", fontSize=8, leading=10.5, textColor=MUTED),
    "cell": ParagraphStyle("cell", parent=_base["Normal"], fontName="Helvetica", fontSize=8.5, leading=11, textColor=INK),
    "cellbold": ParagraphStyle("cellbold", parent=_base["Normal"], fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=INK),
    "bullet": ParagraphStyle("bullet", parent=_base["Normal"], fontName="Helvetica", fontSize=9.5, leading=13, leftIndent=10, bulletIndent=0, textColor=INK, spaceAfter=3),
}


def p(text: object, style: str = "body") -> Paragraph:
    return Paragraph(escape(str(text)).replace("\n", "<br/>"), STYLES[style])


def bullets(items: list[str]) -> list[Paragraph]:
    return [Paragraph(escape(item), STYLES["bullet"], bulletText="•") for item in items]


def table(rows: list[list[object]], widths: list[float], header: bool = True) -> Table:
    cells = [[p(value, "cellbold" if header and index == 0 else "cell") for value in row] for index, row in enumerate(rows)]
    result = Table(cells, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
    ]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f6")), ("LINEBELOW", (0, 0), (-1, 0), 0.8, INK)]
    result.setStyle(TableStyle(style))
    return result


def key_values(pairs: list[tuple[str, object]], widths: tuple[float, float] = (48 * mm, 122 * mm)) -> Table:
    return table([[key, value] for key, value in pairs], list(widths), header=False)


def score_block(score: object, risk: object) -> Table:
    color = SEVERITY_COLORS.get(str(risk), ACCENT)
    cells = [[Paragraph(f'<font size="26"><b>{escape(str(score))}</b></font><font size="11" color="#5b6272"> / 100</font>', STYLES["body"]),
              Paragraph(f'<font color="#{color.hexval()[2:]}" size="14"><b>{escape(str(risk)).upper()} RISK</b></font><br/>'
                        '<font size="8" color="#5b6272">Project Security Assessment Score: a transparent project heuristic, not an official rating.</font>',
                        STYLES["body"])]]
    block = Table(cells, colWidths=[45 * mm, 125 * mm])
    block.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("BOX", (0, 0), (-1, -1), 0.8, RULE),
                               ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8), ("LEFTPADDING", (0, 0), (-1, -1), 8)]))
    return block


def bar_chart(labels: list[str], values: list[float], title: str) -> KeepTogether:
    drawing = Drawing(170 * mm, 55 * mm)
    chart = VerticalBarChart()
    chart.x, chart.y, chart.width, chart.height = 12 * mm, 8 * mm, 150 * mm, 42 * mm
    chart.data = [values or [0]]
    chart.categoryAxis.categoryNames = labels or [""]
    chart.categoryAxis.labels.fontSize = 7
    chart.valueAxis.labels.fontSize = 7
    chart.valueAxis.valueMin = 0
    chart.bars[0].fillColor = ACCENT
    chart.bars[0].strokeColor = None
    drawing.add(chart)
    return KeepTogether([p(title, "h2"), drawing])


def render(title: str, subtitle_lines: list[str], story: list) -> bytes:
    buffer = BytesIO()
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(20 * mm, 12 * mm, f"IPsec Analyzer  |  generated {generated}")
        canvas.drawRightString(190 * mm, 12 * mm, f"CONFIDENTIAL  |  Page {document.page}")
        canvas.restoreState()

    document = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm, topMargin=18 * mm, bottomMargin=20 * mm,
                                 title=title, author="IPsec Analyzer")
    header = [p(title, "title"), *[p(line, "subtitle") for line in subtitle_lines], Spacer(1, 6)]
    document.build(header + story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
