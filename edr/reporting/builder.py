"""Report builder: Jinja2 text rendered to Word (python-docx) or PDF (ReportLab)."""
from __future__ import annotations

import io
from collections import Counter
from datetime import timedelta
from pathlib import Path

from django.db.models import Count
from django.utils import timezone
from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from edr.models import Alert, Connection, Host, Process

TEMPLATES = Path(__file__).resolve().parent / "templates"
_env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=select_autoescape([]),
                   undefined=StrictUndefined, trim_blocks=True, lstrip_blocks=True)
SEV_ORDER = ["critical", "high", "medium", "low"]
SEV_COLORS = {"critical": "B91C1C", "high": "EA580C", "medium": "CA8A04", "low": "2563EB"}


def build_report_data(hours: int = 24, host_id: int | None = None) -> dict:
    now = timezone.now()
    since = now - timedelta(hours=hours)
    alerts = Alert.objects.filter(last_seen__gte=since).select_related("host")
    procs = Process.objects.filter(started_at__gte=since)
    hosts = Host.objects.all()
    if host_id:
        alerts, procs, hosts = alerts.filter(host_id=host_id), procs.filter(host_id=host_id), hosts.filter(pk=host_id)
    alerts = list(alerts.order_by("-score", "-id")[:500])
    sev = Counter(a.severity for a in alerts)
    host_counts = Counter(a.host.hostname for a in alerts if a.severity in ("critical", "high"))
    risky = list(procs.filter(risk_score__gte=40).select_related("host").order_by("-risk_score")[:15])
    conns = (Connection.objects.filter(first_seen__gte=since, direction="outbound", scope="public")
             .values("raddr", "country", "as_org").annotate(n=Count("id")).order_by("-n")[:10])
    summary = {
        "hosts": hosts.count(), "processes_seen": procs.count() or Process.objects.filter(ended_at__isnull=True).count(),
        "total_alerts": len(alerts), "critical": sev["critical"], "high": sev["high"], "medium": sev["medium"],
        "low": sev["low"], "open_alerts": sum(1 for a in alerts if a.status == "open"),
        "memory_alerts": sum(1 for a in alerts if a.memory_flag),
        "yara_matches": sum(1 for a in alerts if a.rule_id.startswith("YARA")),
    }
    window = f"{hours}-hour period" if hours != 24 else "24-hour period"
    generated = now.strftime("%Y-%m-%d %H:%M UTC")
    narrative = _env.get_template("executive_summary.txt.j2").render(
        s=summary, window=window, generated=generated, top_hosts=[h for h, _ in host_counts.most_common(3)]).strip()
    rec = _env.get_template("recommendation.txt.j2")
    findings = []
    for a in alerts[:25]:
        findings.append({
            "severity": a.severity, "score": a.score, "title": a.title, "host": a.host.hostname,
            "process": f"{a.process_name} (PID {a.pid})" if a.pid else a.process_name, "path": a.process_path,
            "remote": a.remote_ip, "technique": a.technique, "tactic": a.tactic, "status": a.status,
            "seen": a.last_seen.strftime("%Y-%m-%d %H:%M"), "description": a.description,
            "recommendation": rec.render(a=a).strip(), "memory": a.memory_flag,
        })
    return {
        "title": "AetherEDR Security Audit Report", "generated": generated, "window": window, "summary": summary,
        "paragraphs": [p.strip() for p in narrative.split("\n\n") if p.strip()],
        "findings": findings,
        "risky_processes": [{"name": p.basename, "pid": p.pid, "host": p.host.hostname, "score": p.risk_score,
                             "top": p.findings[0]["title"] if p.findings else "", "path": p.exe} for p in risky],
        "destinations": [{"ip": c["raddr"], "country": c["country"] or "?", "org": c["as_org"] or "-", "count": c["n"]} for c in conns],
        "hosts": [{"name": h.hostname, "os": h.os_version or h.os_name, "last_seen": h.last_seen.strftime("%Y-%m-%d %H:%M"),
                   "admin": h.is_admin, "memory": bool(h.capabilities.get("memory_introspection"))} for h in hosts[:50]],
        "limitations": [
            "Telemetry is collected by polling; processes that start and exit between polls can be missed.",
            "Memory introspection requires elevated privileges. Hosts running without them have reduced visibility.",
            "Risk scores are heuristic and unsupervised baselines learn existing behaviour. Validate findings before acting.",
        ],
    }


# --- DOCX ---------------------------------------------------------------------------------
def render_docx(data: dict) -> bytes:
    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Pt, RGBColor

    doc = Document()
    doc.styles["Normal"].font.name = "Calibri"
    doc.styles["Normal"].font.size = Pt(10.5)

    def shade(cell, hex_fill):
        tcPr = cell._tc.get_or_add_tcPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), hex_fill)
        tcPr.append(shd)

    def table(headers, rows, widths=None):
        t = doc.add_table(rows=1, cols=len(headers))
        t.style = "Light Grid Accent 1"
        for i, h in enumerate(headers):
            c = t.rows[0].cells[i]
            c.text = ""
            r = c.paragraphs[0].add_run(h)
            r.bold = True
        for row in rows:
            cells = t.add_row().cells
            for i, v in enumerate(row):
                cells[i].text = str(v)
                for p in cells[i].paragraphs:
                    for run in p.runs:
                        run.font.size = Pt(9)
        return t

    title = doc.add_heading(data["title"], 0)
    title.alignment = WD_ALIGN_PARAGRAPH.LEFT
    doc.add_paragraph(f"Generated {data['generated']} · Window: {data['window']}")

    doc.add_heading("Executive summary", 1)
    for para in data["paragraphs"]:
        doc.add_paragraph(para)

    s = data["summary"]
    t = doc.add_table(rows=2, cols=5)
    for i, sev in enumerate(["critical", "high", "medium", "low"]):
        t.rows[0].cells[i].text = sev.upper()
        t.rows[1].cells[i].text = str(s[sev])
        shade(t.rows[0].cells[i], SEV_COLORS[sev])
        for run in t.rows[0].cells[i].paragraphs[0].runs:
            run.font.color.rgb = RGBColor(255, 255, 255)
            run.bold = True
    t.rows[0].cells[4].text = "OPEN"
    t.rows[1].cells[4].text = str(s["open_alerts"])

    if data["findings"]:
        doc.add_heading("Key findings", 1)
        for f in data["findings"][:10]:
            p = doc.add_paragraph()
            r = p.add_run(f"[{f['severity'].upper()} · {f['score']}] {f['title']}")
            r.bold = True
            r.font.color.rgb = RGBColor.from_string(SEV_COLORS[f["severity"]])
            meta = f"{f['host']} · {f['process']}"
            if f["remote"]:
                meta += f" · remote {f['remote']}"
            if f["technique"]:
                meta += f" · MITRE {f['technique']}"
            doc.add_paragraph(meta).runs[0].font.size = Pt(9)
            if f["description"]:
                doc.add_paragraph(f["description"])
            rp = doc.add_paragraph()
            rp.add_run("Recommended action: ").bold = True
            rp.add_run(f["recommendation"])

    if data["risky_processes"]:
        doc.add_heading("Highest-risk processes", 1)
        table(["Process", "PID", "Host", "Score", "Top finding"],
              [[p["name"], p["pid"], p["host"], p["score"], p["top"]] for p in data["risky_processes"]])
    if data["destinations"]:
        doc.add_heading("Top external destinations", 1)
        table(["IP", "Country", "Organisation", "Connections"],
              [[d["ip"], d["country"], d["org"], d["count"]] for d in data["destinations"]])
    doc.add_heading("Monitored endpoints", 1)
    table(["Host", "OS", "Last seen", "Elevated", "Memory introspection"],
          [[h["name"], h["os"], h["last_seen"], "yes" if h["admin"] else "no", "yes" if h["memory"] else "no"] for h in data["hosts"]])
    doc.add_heading("Limitations", 1)
    for l in data["limitations"]:
        doc.add_paragraph(l, style="List Bullet")
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


# --- PDF ----------------------------------------------------------------------------------
def render_pdf(data: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    from xml.sax.saxutils import escape

    ss = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=ss["BodyText"], fontSize=9.5, leading=13)
    small = ParagraphStyle("small", parent=body, fontSize=8, textColor=colors.HexColor("#555555"))
    cell = ParagraphStyle("cell", parent=body, fontSize=8, leading=10)
    h1 = ParagraphStyle("h1", parent=ss["Heading2"], textColor=colors.HexColor("#111827"), spaceBefore=10)

    def P(t, st=body):
        return Paragraph(escape(str(t)), st)

    def tbl(headers, rows, widths):
        data_ = [[P(h, ParagraphStyle("th", parent=cell, textColor=colors.white, fontName="Helvetica-Bold")) for h in headers]]
        data_ += [[P(c, cell) for c in r] for r in rows]
        t = Table(data_, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F3F4F6")]),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D1D5DB")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        return t

    out = io.BytesIO()
    doc = SimpleDocTemplate(out, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title=data["title"], author="AetherEDR")
    W = A4[0] - 36 * mm
    el = [Paragraph(escape(data["title"]), ss["Title"]), P(f"Generated {data['generated']} · Window: {data['window']}", small),
          Spacer(1, 6), Paragraph("Executive summary", h1)]
    for para in data["paragraphs"]:
        el += [P(para), Spacer(1, 4)]
    s = data["summary"]
    sev_row = [[P(k.upper(), ParagraphStyle("k", parent=cell, textColor=colors.white, fontName="Helvetica-Bold", alignment=1))
                for k in ("critical", "high", "medium", "low")] + [P("OPEN", cell)],
               [P(s[k], ParagraphStyle("v", parent=body, fontSize=14, alignment=1)) for k in ("critical", "high", "medium", "low")]
               + [P(s["open_alerts"], ParagraphStyle("v", parent=body, fontSize=14, alignment=1))]]
    t = Table(sev_row, colWidths=[W / 5] * 5)
    style = [("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D1D5DB"))]
    for i, k in enumerate(("critical", "high", "medium", "low")):
        style.append(("BACKGROUND", (i, 0), (i, 0), colors.HexColor("#" + SEV_COLORS[k])))
    t.setStyle(TableStyle(style))
    el += [Spacer(1, 6), t]
    if data["findings"]:
        el.append(Paragraph("Key findings", h1))
        for f in data["findings"][:10]:
            col = SEV_COLORS[f["severity"]]
            el.append(Paragraph(f'<font color="#{col}"><b>[{f["severity"].upper()} · {f["score"]}]</b></font> <b>{escape(f["title"])}</b>', body))
            meta = f"{f['host']} · {f['process']}" + (f" · remote {f['remote']}" if f["remote"] else "") + (f" · MITRE {f['technique']}" if f["technique"] else "")
            el += [P(meta, small), P(f["description"]) if f["description"] else Spacer(1, 0),
                   Paragraph(f"<b>Recommended action:</b> {escape(f['recommendation'])}", body), Spacer(1, 6)]
    if data["risky_processes"]:
        el += [Paragraph("Highest-risk processes", h1),
               tbl(["Process", "PID", "Host", "Score", "Top finding"],
                   [[p["name"], p["pid"], p["host"], p["score"], p["top"]] for p in data["risky_processes"]],
                   [W * .2, W * .08, W * .17, W * .08, W * .47])]
    if data["destinations"]:
        el += [Paragraph("Top external destinations", h1),
               tbl(["IP", "Country", "Organisation", "Connections"],
                   [[d["ip"], d["country"], d["org"], d["count"]] for d in data["destinations"]], [W * .3, W * .15, W * .4, W * .15])]
    el += [Paragraph("Monitored endpoints", h1),
           tbl(["Host", "OS", "Last seen", "Elevated", "Memory"],
               [[h["name"], h["os"], h["last_seen"], "yes" if h["admin"] else "no", "yes" if h["memory"] else "no"] for h in data["hosts"]],
               [W * .2, W * .4, W * .17, W * .11, W * .12]),
           Paragraph("Limitations", h1)]
    for l in data["limitations"]:
        el.append(P("• " + l))

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#6B7280"))
        canvas.drawString(18 * mm, 9 * mm, "AetherEDR · confidential")
        canvas.drawRightString(A4[0] - 18 * mm, 9 * mm, f"Page {d.page}")
        canvas.restoreState()

    doc.build(el, onFirstPage=footer, onLaterPages=footer)
    return out.getvalue()
