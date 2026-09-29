from __future__ import annotations

from pathlib import Path

from vstacklens.reports.docx_report import DocxReportEngine
from vstacklens.reports.html_report import HtmlReportEngine
from vstacklens.reports.report_model import ReportData


class ReportExportEngine:
    def render(self, report: ReportData, output_path: Path) -> tuple[Path, str, str]:
        suffix = output_path.suffix.lower()
        if suffix == ".json":
            report.write_json(output_path)
            return output_path, "json", "Inspection Result JSON"
        if suffix == ".html":
            HtmlReportEngine().render(report, output_path)
            return output_path, "html", "VStackLens HTML Preview Report"
        if suffix in {".pdf", ".pptx"}:
            raise ValueError("不支持的导出格式，请使用 HTML 或 Word 报告。")
        if suffix in {"", ".docx"}:
            output_path = output_path.with_suffix(".docx") if suffix == "" else output_path
            DocxReportEngine().render(report, output_path)
            return output_path, "docx", "VStackLens Word Report"
        raise ValueError(f"不支持的导出格式，请使用 HTML 或 Word 报告：{suffix}")
