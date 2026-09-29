from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from vstacklens.resources import report_template_dir
from vstacklens.reports.report_model import ReportData


class HtmlReportEngine:
    def render(self, report: ReportData, output_path: Path) -> None:
        template_dir = report_template_dir()
        env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(enabled_extensions=("html", "htm", "xml", "j2")),
        )
        html = env.get_template("report_v2.html.j2").render(**report.model_dump())
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")
