"""Build the beginner study guide PDF with ReportLab."""
from __future__ import annotations

from html import escape
from pathlib import Path
import re

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "SecureMailScope-M1-Beginner-Guide.md"
OUTPUT = ROOT / "SecureMailScope-M1-Beginner-Guide.pdf"


def make_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="GuideTitle", parent=styles["Title"], fontName="Helvetica-Bold",
        fontSize=25, leading=31, alignment=TA_CENTER, textColor=colors.HexColor("#17324D"),
        spaceAfter=16,
    ))
    styles.add(ParagraphStyle(
        name="GuideSubtitle", parent=styles["Normal"], fontName="Helvetica",
        fontSize=12, leading=17, alignment=TA_CENTER, textColor=colors.HexColor("#4B6478"),
        spaceAfter=24,
    ))
    styles.add(ParagraphStyle(
        name="GuideH1", parent=styles["Heading1"], fontName="Helvetica-Bold",
        fontSize=18, leading=22, textColor=colors.HexColor("#17324D"),
        spaceBefore=15, spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="GuideH2", parent=styles["Heading2"], fontName="Helvetica-Bold",
        fontSize=13, leading=17, textColor=colors.HexColor("#236B8E"),
        spaceBefore=11, spaceAfter=5,
    ))
    styles.add(ParagraphStyle(
        name="GuideBody", parent=styles["BodyText"], fontName="Helvetica",
        fontSize=9.5, leading=13.5, spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="GuideBullet", parent=styles["BodyText"], fontName="Helvetica",
        fontSize=9.5, leading=13.5, leftIndent=14, firstLineIndent=-8, spaceAfter=3,
    ))
    styles.add(ParagraphStyle(
        name="GuideCode", parent=styles["Code"], fontName="Courier",
        fontSize=7.5, leading=10, leftIndent=8, rightIndent=8,
        backColor=colors.HexColor("#F1F5F7"), borderColor=colors.HexColor("#D7E0E5"),
        borderWidth=0.5, borderPadding=7, spaceBefore=4, spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="GuideNote", parent=styles["BodyText"], fontName="Helvetica-Oblique",
        fontSize=9.5, leading=13.5, leftIndent=12, textColor=colors.HexColor("#385466"),
        borderColor=colors.HexColor("#8BB7C8"), borderWidth=0.5, borderPadding=7,
        spaceBefore=5, spaceAfter=8,
    ))
    return styles


def footer(canvas, document):
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#D7E0E5"))
    canvas.line(18 * mm, 14 * mm, 192 * mm, 14 * mm)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#607582"))
    canvas.drawString(18 * mm, 9 * mm, "SecureMailScope M1 Beginner Guide")
    canvas.drawRightString(192 * mm, 9 * mm, f"Page {document.page}")
    canvas.restoreState()


def inline_markup(text: str) -> str:
    text = escape(text, quote=False)
    text = re.sub(r"`([^`]+)`", r"<font name='Courier'>\1</font>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    return text


def build_story(styles):
    lines = SOURCE.read_text(encoding="utf-8").splitlines()
    story = []
    in_code = False
    code_lines = []
    table_rows = []

    def flush_table():
        nonlocal table_rows
        if not table_rows:
            return
        data = [[Paragraph(inline_markup(cell.strip()), styles["GuideBody"]) for cell in row] for row in table_rows]
        table = Table(data, colWidths=[45 * mm, 125 * mm], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DDECF2")),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#B8CBD3")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(table)
        story.append(Spacer(1, 6))
        table_rows = []

    for line in lines:
        if line.startswith("```"):
            if in_code:
                story.append(Preformatted("\n".join(code_lines), styles["GuideCode"]))
                code_lines = []
                in_code = False
            else:
                flush_table()
                in_code = True
            continue
        if in_code:
            code_lines.append(line)
            continue
        if line.startswith("|") and line.endswith("|"):
            cells = [cell for cell in line.strip("|").split("|")]
            if all(set(cell.strip()) <= {"-", ":", " "} for cell in cells):
                continue
            table_rows.append(cells)
            continue
        flush_table()
        if not line.strip():
            continue
        if line.startswith("# "):
            story.append(Paragraph(inline_markup(line[2:]), styles["GuideTitle"]))
            story.append(HRFlowable(width="65%", thickness=1.2, color=colors.HexColor("#5C9BB0"), spaceAfter=10))
        elif line.startswith("## "):
            story.append(Paragraph(inline_markup(line[3:]), styles["GuideH1"]))
        elif line.startswith("### "):
            story.append(Paragraph(inline_markup(line[4:]), styles["GuideH2"]))
        elif line.startswith("- "):
            story.append(Paragraph("&#8226; " + inline_markup(line[2:]), styles["GuideBullet"]))
        elif line.startswith("> "):
            story.append(Paragraph(inline_markup(line[2:]), styles["GuideNote"]))
        else:
            story.append(Paragraph(inline_markup(line), styles["GuideBody"]))
    flush_table()
    return story


def main() -> None:
    styles = make_styles()
    document = SimpleDocTemplate(
        str(OUTPUT), pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=20 * mm,
        title="SecureMailScope M1 Beginner Guide",
        author="SecureMailScope M1",
    )
    document.build(build_story(styles), onFirstPage=footer, onLaterPages=footer)
    print(OUTPUT)


if __name__ == "__main__":
    main()