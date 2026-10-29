"""Actual product PDF text geometry, in addition to character completeness."""
from copy import deepcopy
import json

import pymupdf

from vstacklens.products.model import TargetRef, finish_module, make_check, new_module
from vstacklens.products.reporting import build_integrated_report, product_report_view
from vstacklens.reports.pdf_report import PdfReportEngine


def test_long_target_name_stays_inside_scope_and_normal_object_columns(tmp_path):
    name = '长名称管理目标_' + 'ABCDEFGHIJK_' * 4
    target = TargetRef('wrapping-target', 'nsx', 'customer', 'site', name, '192.0.2.44')
    module = new_module(target)
    module['checks'] = [make_check('scope-check', '原生状态', 'normal', object_name=name,
        values={'state': 'STABLE'}, sources=[{'method': 'GET', 'path': '/api/offline-sample',
            'collected_at': '2026-10-17T01:00:00Z', 'version_basis': '离线合成样本'}])]
    report = build_integrated_report('wrap-fixture', [target], [finish_module(module)], '长名称排版离线验证')
    original = deepcopy(report.model_dump())
    pure = product_report_view(report)
    derived = PdfReportEngine()._pdf_product_view(report)
    assert derived['targets'][0]['name'].replace('\u200b', '') == name
    normal = next(t for t in derived['sections'][0]['body']['tables'] if t['title'] == '正常读取摘要')
    assert normal['rows'][0][1].replace('\u200b', '') == name
    assert product_report_view(report) == pure
    path = PdfReportEngine().render(report, tmp_path / 'long-target.pdf')
    with pymupdf.open(stream=path.read_bytes(), filetype='pdf') as document:
        scope_header = document[0].search_for('产品与目标')[0]
        normal_header = document[0].search_for('读取值摘要')[0]
        words = document[0].get_text('words')
        # Name ASCII fragments are unique in this fixture. Check both actual
        # text regions, using the next column's left inset as the safe edge.
        scope_y_end = document[0].search_for('报告章节')[0].y0
        target_words = [w for w in words if 'ABC' in w[4] or 'GHI' in w[4]]
        scope_words = [w for w in target_words if scope_header.y1 < w[1] < scope_y_end]
        summary_words = [w for w in target_words if w[1] > normal_header.y1]
        assert scope_words and summary_words
        available_width = document[0].rect.width - 20 * 72 / 25.4
        scope_edge = 10 * 72 / 25.4 + available_width / 4
        summary_edge = normal_header.x0 - 5
        assert all(w[2] <= scope_edge + 0.5 for w in scope_words)
        assert all(w[2] <= summary_edge + 0.5 for w in summary_words)
        text = ''.join(page.get_text().replace('\u200b', '') for page in document)
    assert ''.join(name.split()) in ''.join(text.split())
    assert report.model_dump() == original
    (tmp_path / 'geometry.json').write_text(json.dumps({'scope_right_edge': scope_edge,
        'normal_object_right_edge': summary_edge, 'scope_max_x': max(w[2] for w in scope_words),
        'normal_max_x': max(w[2] for w in summary_words), 'original_model_unchanged': True}, indent=2), encoding='utf-8')
