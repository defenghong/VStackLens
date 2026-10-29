"""Static guards for the print-only fix; actual ink QA is recorded separately."""
import re

from vstacklens.reports.html_assets import SINGLE_PAGE_REPORT_JS
from vstacklens.reports.html_package import HtmlReportPackageBuilder


def print_style():
    return re.search(r'style\.textContent = `(@media print \{.*?)`;', SINGLE_PAGE_REPORT_JS, re.S).group(1)


def test_product_evidence_print_wrap_is_scoped_without_hiding_or_font_changes():
    css = print_style()
    assert '.product-detail-table .product-evidence-id {' in css
    assert 'white-space: normal !important;' in css
    assert 'overflow-wrap: anywhere;' in css
    assert 'word-break: break-all;' in css
    assert 'max-width: 100%;' in css
    assert 'font-size' not in css
    assert all(value not in css for value in ('overflow: hidden', 'ellipsis', 'display: none', 'visibility:', 'transform:'))


def test_screen_span_and_vc_column_rule_remain_unchanged():
    assert 'class="product-evidence-id" style="display:inline-block;white-space:nowrap"' in SINGLE_PAGE_REPORT_JS
    assert '.object-evidence-table th:first-child { width:55%; }' in HtmlReportPackageBuilder()._single_page_css()
    assert 'product-evidence-id' not in HtmlReportPackageBuilder()._single_page_css()


def test_print_style_is_only_installed_for_products_and_id_text_is_not_shortened():
    section = SINGLE_PAGE_REPORT_JS.split('function renderProductSections()', 1)[1]
    assert section.index('if (!view) return;') < section.index('style.id = "product-evidence-print-style"')
    assert 'document.getElementById("product-evidence-print-style")' in section
    evidence = SINGLE_PAGE_REPORT_JS.split('const content = headers[index] === "证据"', 1)[1].split(': esc(value)', 1)[0]
    assert '${esc(ref)}' in evidence and 'split("、")' in evidence
    assert all(value not in evidence for value in ('.slice(', '.substring(', '.substr(', 'ellipsis'))
