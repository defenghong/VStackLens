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
        from vstacklens.reports.customer_view import get_customer_problem_view, shared_passed_checks, customer_vsan_summary, customer_environment_name, customer_display_facts
        view = get_customer_problem_view(report)
        payload = report.model_dump()
        payload["customer_problems"] = [entry.display for entry in view.categories]
        payload["customer_display_facts"] = customer_display_facts(report)
        from vstacklens.reports.presentation import customer_check_statistics
        payload["customer_check_statistics"] = customer_check_statistics(report)
        payload["customer_passed_checks"] = shared_passed_checks(report, report.appendix.get("rule_checklist", []), customer_vsan_summary(report))
        payload["report_info"]["report_title"] = customer_environment_name(report.report_info.report_title) or "虚拟化巡检报告"
        html = env.get_template("report_v2.html.j2").render(**payload)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        from vstacklens.application.artifact_publish import staged_file
        with staged_file(output_path) as stage:
            stage.write_text(html, encoding="utf-8")
