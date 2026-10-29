"""Desktop layouts for phase 3a. Inspection handlers remain in app.py."""
from pathlib import Path
from PySide6.QtCore import Qt, QSize
from PySide6.QtWidgets import (QApplication, QCheckBox, QDialog, QFormLayout, QFrame, QHBoxLayout, QLabel,
    QLineEdit, QListWidget, QListWidgetItem, QPushButton, QProgressBar, QStackedWidget, QTableWidget, QComboBox,
    QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget, QHeaderView)
from PySide6.QtWidgets import QSizePolicy
from vstacklens.desktop.widgets import (EmptyState, MetricValueLabel, NumberSummary, NoWheelComboBox, PageHeader,
    PathLineEdit, RiskTrendChart, SectionCard, muted_label, risk_badge, status_badge)
from vstacklens.desktop.presentation import local_time, object_name, ui_text, task_numbers, current_sentence
from vstacklens.desktop.theme import COLORS, SIZES, TYPOGRAPHY

def button(text, callback, *, primary=False, quiet=False):
    item = QPushButton(text)
    item.setObjectName("primaryButton" if primary else "quietButton" if quiet else "outlineButton")
    if not quiet: item.setFixedHeight(SIZES["primary_button" if primary else "secondary_button"])
    item.clicked.connect(callback)
    return item

class FoldSection(QWidget):
    def __init__(self, title, body):
        super().__init__()
        layout = QVBoxLayout(self); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(6)
        self.toggle = button("▸ " + title, self._toggle, quiet=True)
        self.title = title; self.body = body; self.body.hide()
        layout.addWidget(self.toggle, alignment=Qt.AlignLeft); layout.addWidget(body)
    def _toggle(self):
        self.body.setVisible(self.body.isHidden())
        if getattr(self,"external_toggle",False): self.setVisible(not self.body.isHidden())
        self.toggle.setText(("▾ " if not self.body.isHidden() else "▸ ") + self.title)

def table(window, headers):
    widget = QTableWidget(0, len(headers)); widget.setHorizontalHeaderLabels(headers)
    window._prepare_table(widget); widget.setWordWrap(True)
    widget.setProperty("cardTable", True)
    widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
    return widget

def badge_cell(level):
    body = QWidget(); body.setObjectName("badgeCell"); body.setAttribute(Qt.WA_TranslucentBackground); body.setAttribute(Qt.WA_TransparentForMouseEvents)
    # The table item style already supplies the 16px cell inset.
    layout = QHBoxLayout(body); layout.setContentsMargins(0, 0, 0, 0)
    layout.addWidget(risk_badge(level), alignment=Qt.AlignLeft | Qt.AlignVCenter); layout.addStretch(1)
    return body

def fill_table(widget, rows):
    widget.setRowCount(len(rows))
    for i, row in enumerate(rows):
        for j, value in enumerate(row):
            cell = QTableWidgetItem(ui_text(value))
            numeric = widget.horizontalHeaderItem(j).text() in {"涉及对象", "对象数", "问题数量", "数量"}
            cell.setTextAlignment((Qt.AlignRight if numeric else Qt.AlignLeft) | Qt.AlignVCenter)
            widget.horizontalHeaderItem(j).setTextAlignment((Qt.AlignRight if numeric else Qt.AlignLeft) | Qt.AlignVCenter)
            widget.setItem(i, j, cell)
    widget.resizeRowsToContents()
    widget.setMinimumHeight(SIZES["table_header"] + sum(widget.rowHeight(i) for i in range(len(rows))) + widget.frameWidth()*2)
    widget.setMaximumHeight(widget.minimumHeight())

def page_layout(title):
    page = QWidget(); layout = QVBoxLayout(page)
    layout.setContentsMargins(SIZES["page_margin"], SIZES["page_top"], SIZES["page_margin"], SIZES["card_padding"]); layout.setSpacing(SIZES["card_gap"])
    layout.addWidget(PageHeader(title)); return page, layout

class Layout3aMixin:
    def _short_task(self, run_id):
        label = getattr(self, "_task_numbers", {}).get(run_id)
        if label:
            return label
        product_label = self._product_task_label(run_id) if hasattr(self, "_product_task_label") else None
        return product_label or ("编号待确认" if run_id else "—")

    def _arrange_page_actions(self):
        for card in self.pages.findChildren(QFrame):
            if card.objectName() not in {"sectionCard", "moduleCard", "pageCard", "infoCard"}: continue
            layout = QWidget.layout(card)
            if layout is None: continue
            card.ensurePolished()
            if card.minimumHeight() == card.maximumHeight():
                card.setMaximumHeight(16777215)
                card.setMinimumHeight(layout.minimumSize().height())
        for page in self.pages.findChildren(QWidget):
            headers = page.findChildren(PageHeader, options=Qt.FindDirectChildrenOnly)
            if not headers: continue
            actions = [b for b in page.findChildren(QPushButton) if b.objectName() == "primaryButton" and not b.property("keepInPanel")]
            if actions:
                headers[0].add_action(actions[0]); actions[0].setFixedHeight(SIZES["primary_button"])

    def _dashboard_page(self):
        page, layout = page_layout("环境概览")
        layout.setContentsMargins(SIZES["page_margin"], SIZES["page_top"], SIZES["page_margin"], SIZES["home_bottom"])
        layout.setSpacing(SIZES["card_gap"] + 4)
        header = layout.itemAt(0).widget()
        header.add_action(button("开始标准巡检", self._open_standard_inspection, primary=True))
        self.dashboard_stack = QStackedWidget()
        empty = QWidget(); empty_layout = QVBoxLayout(empty)
        empty_layout.setContentsMargins(0, 0, 0, 0)
        empty_card = SectionCard("从一次标准巡检开始")
        empty_card.layout.addWidget(muted_label("选择客户环境，完成标准巡检后，这里会展示本次结论、资产与重点问题。"))
        empty_layout.addWidget(empty_card); empty_layout.addStretch(1)
        self.dashboard_stack.addWidget(empty)
        data = QWidget(); content = QVBoxLayout(data)
        content.setContentsMargins(0, 0, 0, 0); content.setSpacing(SIZES["card_gap"] + 4)

        self.conclusion_card = SectionCard()
        main = QHBoxLayout(); main.setSpacing(12)
        self.conclusion_strip = QFrame(); self.conclusion_strip.setFixedWidth(4); main.addWidget(self.conclusion_strip)
        conclusion = QVBoxLayout(); conclusion.setSpacing(8)
        heading = QHBoxLayout(); heading.setSpacing(16)
        self.dashboard_health_value = QLabel(); self.dashboard_health_value.setObjectName("dashboardHealthValue")
        self.dashboard_scope_label = muted_label("", word_wrap=False)
        self.dashboard_health_badge = status_badge("unknown"); self.dashboard_health_badge.hide()
        heading.addWidget(self.dashboard_health_value); heading.addStretch(1); heading.addWidget(self.dashboard_scope_label)
        conclusion.addLayout(heading)
        self.dashboard_metric_row = QHBoxLayout(); self.dashboard_metric_row.setSpacing(24)
        totals = QVBoxLayout(); totals.setSpacing(4)
        self.dashboard_problem_total = NumberSummary(); totals.addWidget(self.dashboard_problem_total)
        self.dashboard_non_reported = button("", self._open_non_reported, quiet=True)
        totals.addWidget(self.dashboard_non_reported, alignment=Qt.AlignLeft)
        self.dashboard_metric_row.addLayout(totals, 3)
        self.dashboard_summary_divider = QFrame(); self.dashboard_summary_divider.setObjectName("conclusionDivider")
        self.dashboard_summary_divider.setFixedSize(1, 52); self.dashboard_metric_row.addWidget(self.dashboard_summary_divider)
        priorities = QVBoxLayout(); priorities.setSpacing(4); priority_columns = QHBoxLayout(); priority_columns.setSpacing(24)
        self.risk_metric_labels = {}
        for level in ("P1", "P2", "P3"):
            column = QHBoxLayout(); column.setSpacing(8)
            column.addWidget(risk_badge(level))
            number = MetricValueLabel("—"); number.setObjectName("metricValue")
            column.addWidget(number); column.addStretch(1)
            self.risk_metric_labels[level] = number; priority_columns.addLayout(column)
        priorities.addLayout(priority_columns)
        priorities.addWidget(muted_label("结论针对本次实际检查范围"))
        self.dashboard_metric_row.addLayout(priorities, 3); conclusion.addLayout(self.dashboard_metric_row)
        main.addLayout(conclusion, 1); self.conclusion_card.layout.addLayout(main); content.addWidget(self.conclusion_card)

        task = SectionCard(); task.setObjectName("homeCompactCard")
        task_heading = QHBoxLayout(); task_heading.setSpacing(8)
        from vstacklens.desktop.navigation_icons import navigation_icon
        # Retain this public icon for theme refresh, without giving the compact summary an oversized decoration.
        self.standard_task_icon = QLabel(task); self.standard_task_icon.hide()
        self.standard_task_icon.setPixmap(navigation_icon("vcenter_management", size=SIZES["task_icon"]).pixmap(SIZES["task_icon"], SIZES["task_icon"]))
        task_title = QLabel("标准巡检"); task_title.setObjectName("sectionTitle")
        self.dashboard_task_state = status_badge("unknown", "等待开始")
        task_heading.addWidget(task_title); task_heading.addWidget(self.dashboard_task_state); task_heading.addStretch(1)
        self.dashboard_standard_report = button("查看标准报告", self._show_latest_standard_report)
        task_heading.addWidget(self.dashboard_standard_report); task.layout.addLayout(task_heading)
        self.dashboard_task_hint = muted_label("本次任务的基础结果与报告", word_wrap=False)
        task.layout.addWidget(self.dashboard_task_hint)

        asset_strip = SectionCard("资产概览"); asset_strip.setObjectName("homeCompactCard")
        asset_layout = QHBoxLayout(); asset_layout.setSpacing(SIZES["asset_group_gap"])
        asset_strip.layout.setSpacing(4); asset_strip.layout.addLayout(asset_layout)
        self.asset_values = {}; self.asset_groups = []; self.asset_captions = []
        for key, title in (("Cluster", "集群"), ("ESXi Host", "ESXi 主机"), ("VM", "虚拟机"), ("Datastore", "存储")):
            wrapper = QWidget(); wrapper.setObjectName("inlineNumberGroup"); wrapper.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Preferred)
            group = QHBoxLayout(wrapper); group.setContentsMargins(0, 0, 0, 0); group.setSpacing(SIZES["asset_pair_gap"])
            value = QLabel(); value.setObjectName("assetCount"); label = muted_label(title, word_wrap=False)
            value.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Preferred); label.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Preferred)
            group.addWidget(value, alignment=Qt.AlignBaseline); group.addWidget(label, alignment=Qt.AlignBaseline)
            asset_layout.addWidget(wrapper); self.asset_values[key] = value; self.asset_groups.append(wrapper); self.asset_captions.append(label)
        asset_layout.addStretch(1)
        self.dashboard_assets = asset_strip; self.dashboard_task_row = QHBoxLayout()
        self.dashboard_task_row.setSpacing(SIZES["card_gap"] + 4)
        self.dashboard_task_row.addWidget(task, 2); self.dashboard_task_row.addWidget(asset_strip, 3)
        content.addLayout(self.dashboard_task_row)

        important = SectionCard(); important.layout.setSpacing(6)
        issue_heading = QHBoxLayout(); issue_title = QLabel("重点问题"); issue_title.setObjectName("sectionTitle")
        issue_heading.addWidget(issue_title); issue_heading.addStretch(1)
        self.dashboard_all_risks = button("查看问题详情 ›", lambda: self._open_risk_center(), quiet=True)
        issue_heading.addWidget(self.dashboard_all_risks); important.layout.addLayout(issue_heading)
        self.dashboard_issues_card = important
        self.dashboard_issues = table(self, ["等级", "问题", "涉及对象", "建议"])
        self.dashboard_issues.cellDoubleClicked.connect(lambda *_: self._open_risk_center())
        important.layout.addWidget(self.dashboard_issues)
        self.dashboard_issues_empty = muted_label(""); important.layout.addWidget(self.dashboard_issues_empty)
        content.addWidget(important)

        recent = SectionCard(); recent.layout.setSpacing(6)
        recent_heading = QHBoxLayout(); recent_title = QLabel("最近报告"); recent_title.setObjectName("sectionTitle")
        recent_heading.addWidget(recent_title); recent_heading.addStretch(1); recent.layout.addLayout(recent_heading)
        self.dashboard_recent_card = recent
        self.dashboard_reports_table = table(self, ["时间", "类型", "任务", "可用格式", "操作"])
        for column, width in ((0, SIZES["recent_time_width"]), (1, 110), (3, 180), (4, 120)):
            self.dashboard_reports_table.horizontalHeader().setSectionResizeMode(column, QHeaderView.Fixed)
            self.dashboard_reports_table.setColumnWidth(column, width)
        recent.layout.addWidget(self.dashboard_reports_table)
        self.dashboard_reports_empty = muted_label("当前环境尚无生成成功的报告。")
        recent.layout.addWidget(self.dashboard_reports_empty); content.addWidget(recent)

        self.trend_card = SectionCard(); self.trend_chart = RiskTrendChart(); self.trend_text = muted_label("")
        self.trend_card.layout.addWidget(self.trend_chart); self.trend_card.layout.addWidget(self.trend_text)
        self.trend_fold = FoldSection("风险趋势", self.trend_card); content.addWidget(self.trend_fold)
        self.certificate_summary_card = SectionCard()
        self.certificate_summary_card.layout.addWidget(muted_label("证书有效期与授权有效期分别核验，详情以本次记录为准。"))
        self.dashboard_certificate_summary = muted_label("")
        self.dashboard_certificate_list = QListWidget(); self.dashboard_certificate_list.setMaximumHeight(160)
        self.dashboard_certificate_detail = QTextEdit(); self.dashboard_certificate_detail.setReadOnly(True)
        self.dashboard_certificate_detail.setMaximumHeight(150); self.dashboard_certificate_detail.hide()
        self.dashboard_certificate_toggle = button("查看核验明细", self._toggle_certificate_detail, quiet=True)
        for child in (self.dashboard_certificate_summary, self.dashboard_certificate_list, self.dashboard_certificate_toggle, self.dashboard_certificate_detail):
            self.certificate_summary_card.layout.addWidget(child)
        self.certificate_fold = FoldSection("证书与授权核验", self.certificate_summary_card); content.addWidget(self.certificate_fold)
        content.addStretch(1); self.dashboard_stack.addWidget(data); layout.addWidget(self.dashboard_stack)
        return self._scroll_page(page)

    def _populate_dashboard(self, data):
        self._task_numbers = task_numbers(self._db_path())
        self._overview = data; self.dashboard_stack.setCurrentIndex(1 if data.has_data else 0)
        caliber = data.customer_caliber or {}; counts = caliber.get("counts", {})
        self.dashboard_health_value.setText(data.health_status)
        health_key = self._dashboard_health_status_key(data.health_status)
        color = {"danger": COLORS["danger"], "warning": COLORS["warning"], "success": COLORS["success"]}.get(health_key, COLORS["subtext"])
        self.conclusion_strip.setStyleSheet(f"background: {color}; border: none;")
        self.dashboard_scope_label.setText(f"{local_time(data.finished_at)} · {self._short_task(data.run_id)}")
        self.dashboard_scope_label.setToolTip(f"标准巡检\n完整任务 ID：{data.run_id or '—'}")
        self.dashboard_problem_total.set_counts(caliber.get('problem_count', '—'), caliber.get('affected_total', '—'))
        for key, number in self.risk_metric_labels.items():
            value = counts.get(key) if data.has_data else None
            number.setText("—" if value is None else str(value))
        n = caliber.get("non_report_total")
        self.dashboard_non_reported.setText(f"另有 {n} 项不进入客户报告 ›" if n is not None else "当次资料不足，未重算问题数量")
        self.dashboard_non_reported.setEnabled(bool(n))
        formats = self.service.desktop_report_formats(self._db_path(), data.run_id) if data.run_id else {}
        self.dashboard_standard_report.setEnabled(bool(formats))
        task_status = {"success": "已完成", "running": "进行中", "failed": "失败", "cancelled": "已取消"}.get(data.run_status, "已有基础结果" if data.has_data else "等待开始")
        status_key = data.run_status if data.run_status in {"success", "running", "failed", "cancelled"} else "unknown"
        self.dashboard_task_state.setText(task_status); self.dashboard_task_state.setProperty("status", status_key)
        self.dashboard_task_hint.setText("可直接查看已生成的标准报告" if formats else "本次已有基础结果，尚无生成成功的报告")
        rows = caliber.get("categories", [])
        fill_table(self.dashboard_issues, [(r["priority"], r["title"], self._category_objects(r), r.get("remediation_zh") or "请查看问题详情") for r in rows[:5]])
        self.dashboard_issues.setVisible(bool(rows)); self.dashboard_issues_empty.setVisible(not rows)
        self.dashboard_issues_empty.setText("本次实际检查范围内未发现进入客户报告的问题。" if caliber.get("problem_count") == 0 else "本次资料不足以形成完整问题清单，不能据此判断正常。")
        for i, category in enumerate(rows[:5]):
            self.dashboard_issues.setCellWidget(i, 0, badge_cell(category["priority"]))
            for column in range(self.dashboard_issues.columnCount()):
                item = self.dashboard_issues.item(i, column)
                if item is not None: item.setToolTip(item.text())
        self.dashboard_all_risks.setVisible(bool(rows))
        assets = data.asset_summary
        for key, label in self.asset_values.items():
            value = assets.get(key)
            label.setText("—" if value is None else str(value))
        trend_available = len(data.risk_trend) >= 2
        self.trend_fold.toggle.setVisible(trend_available); self.trend_fold.setVisible(trend_available)
        self.trend_chart.set_data(data.risk_trend if trend_available else [])
        self.trend_text.setText(f"最近 {len(data.risk_trend)} 次有效巡检，按统一口径展示问题类别数量。")
        self._populate_desktop_tasks(self.dashboard_reports_table, data.recent_reports[:5], reports_only=True)
        # The scope is already shown above the page; short task numbers stay distinct and full identities remain in tooltips.
        for row in range(self.dashboard_reports_table.rowCount()):
            cell = self.dashboard_reports_table.item(row, 2)
            if cell is not None: cell.setText(cell.text().split("\n", 1)[0])
        reports_available = bool(self.dashboard_reports_table.rowCount())
        self.dashboard_reports_table.setVisible(reports_available); self.dashboard_reports_empty.setVisible(not reports_available)

    def _populate_desktop_tasks(self, target, rows, *, reports_only=False):
        if reports_only: rows = [r for r in rows if self.service.desktop_report_formats(self._db_path(), r.run_id)][:5]
        else: rows = rows[:5]
        values = []
        for r in rows:
            row = [local_time(r.finished_at or r.updated_at, compact=True), "标准巡检", f"{self._short_task(r.run_id)}\n{r.customer_name} · {r.vcenter}" if reports_only else self._short_task(r.run_id)]
            if not reports_only: row.append(ui_text(r.run_status))
            row += [" · ".join(self.service.desktop_report_formats(self._db_path(), r.run_id)) or "—", ""]
            values.append(row)
        fill_table(target, values)
        for i, task in enumerate(rows):
            if reports_only:
                from PySide6.QtGui import QFont
                for column in (0,2):
                    font=QFont(target.font());font.setPixelSize(TYPOGRAPHY["secondary"]);target.item(i,column).setFont(font)
            target.item(i, 2).setToolTip(f"客户：{task.customer_name}\nvCenter：{task.vcenter}\n完整任务ID：{task.run_id}")
            action = button("查看报告" if reports_only else "查看", lambda checked=False, item=task: self._open_task_report(item))
            action.setEnabled(bool(self.service.desktop_report_formats(self._db_path(), task.run_id))); target.setCellWidget(i, 4 if reports_only else 5, action)
            if not reports_only: target.setCellWidget(i, 3, status_badge(task.run_status, ui_text(task.run_status)))

    def _category_objects(self, category):
        kinds={x.get("object_type") for x in category.get("affected_objects",[]) if x.get("object_type")}
        unit={"VirtualMachine":"台虚拟机","HostSystem":"台 ESXi 主机","ClusterComputeResource":"个集群","Datastore":"个数据存储"}.get(next(iter(kinds)),"个对象") if len(kinds)==1 else "个对象"
        return f"{category['affected_object_count']} {unit}"

    def _open_task_report(self, task):
        formats = self.service.desktop_report_formats(self._db_path(), task.run_id)
        self._open_path_safe(next(iter(formats.values()), None))
    def _show_latest_standard_report(self):
        data = self._view_data()
        current = getattr(self, "current_result", None) if getattr(self, "_active_module", "") == "inspection_center" else None
        if current and hasattr(current, "modules"):
            formats = {"HTML":current.report_path} if current.report_path.is_file() else {}
            if current.docx_path:formats["Word"]=current.docx_path
            if current.pdf_path:formats["PDF"]=current.pdf_path
            self._open_path_safe(next(iter(formats.values()),None));return
        if current or data:
            formats = self.service.desktop_report_formats(self._db_path(), current.run_id if current else data.run_id)
            self._open_path_safe(next(iter(formats.values()), None))

    def _inspection_center_page(self):
        self.inspection_pages = QStackedWidget()
        entry, layout = page_layout("巡检中心")
        for title,description,caption,callback,module in (
            ("标准巡检","选择产品与目标 · 基础配置、资产与风险","开始标准巡检",self._open_standard_inspection,"inspection_center"),
            ("批量巡检","多个环境 · 独立凭据、逐项结果","进入批量巡检",self._open_batch,"vcenter_management"),
            ("计划巡检","每日 / 每周 · 本次运行授权、错过不补跑","管理计划巡检",self._open_plans,"history_compare")):
            card=SectionCard();row=QHBoxLayout();icon=QLabel()
            from vstacklens.desktop.navigation_icons import navigation_icon
            icon.setPixmap(navigation_icon(module).pixmap(SIZES["navigation_icon"],SIZES["navigation_icon"]))
            row.addWidget(icon);name=QLabel(title);name.setObjectName("sectionTitle");row.addWidget(name)
            row.addWidget(muted_label(description),1);row.addWidget(button(caption,callback,primary=module=="inspection_center"));card.layout.addLayout(row);layout.addWidget(card)
        self.inspection_latest_task=muted_label("尚无巡检记录");self.inspection_latest_state=status_badge("unknown","等待开始")
        latest=QHBoxLayout();latest.addWidget(QLabel("最近标准任务"));latest.addWidget(self.inspection_latest_task,1);latest.addWidget(self.inspection_latest_state);layout.addLayout(latest)
        tasks = SectionCard("近期任务"); self.inspection_tasks_table = table(self, ["时间", "类型", "任务", "状态", "可用格式", "操作"])
        tasks.layout.addWidget(self.inspection_tasks_table); layout.addWidget(tasks); layout.addStretch(1)
        self.inspection_pages.addWidget(self._scroll_page(entry))
        standard, sl = page_layout("标准巡检")
        crumb = QHBoxLayout(); crumb.addWidget(muted_label("巡检中心 / 标准巡检"), 1)
        crumb.addWidget(button("返回巡检中心", lambda: self.inspection_pages.setCurrentIndex(0)))
        self.production_impact_info = QLabel("i"); self.production_impact_info.setObjectName("productionImpactInfo")
        from vstacklens.desktop.app import PRODUCTION_IMPACT_TOOLTIP
        self.production_impact_info.setToolTip(PRODUCTION_IMPACT_TOOLTIP); crumb.addWidget(self.production_impact_info); sl.insertLayout(0, crumb)
        self.standard_columns = QHBoxLayout(); self.standard_config = self._inspection_config_panel(); self.standard_summary = SectionCard("任务摘要")
        self.scope_label = QLabel(); self.scope_label.setWordWrap(True); self.scope_hint = muted_label("填写本次巡检资料即可开始")
        self.standard_summary.layout.addWidget(self.scope_label); self.standard_summary.layout.addWidget(self.scope_hint)
        self.standard_columns.addWidget(self.standard_config, 3); self.standard_columns.addWidget(self.standard_summary, 1); sl.addLayout(self.standard_columns)
        sl.addWidget(self._inspection_log_panel()); sl.addStretch(1)
        sl.itemAt(1).widget().add_action(self.start_button)
        self.inspection_pages.addWidget(self._scroll_page(standard))
        for field in (self.customer_input, self.vcenter_input): field.textChanged.connect(self._update_task_summary)
        self.inspection_pages.addWidget(self._batch_page())
        self.inspection_pages.addWidget(self._schedule_page())
        self.inspection_pages.addWidget(self._product_results_page())
        layout.insertWidget(layout.count()-1, button("查看产品结果（NSX / AVI / 综合任务）", lambda: self._show_product_results()))
        self._update_task_summary(); return self.inspection_pages

    def _open_standard_inspection(self):
        self.go_to_module("inspection_center"); self.inspection_pages.setCurrentIndex(1); self._resize_standard_columns(); self._update_current_object_bar()
    def _update_task_summary(self):
        if getattr(self, "current_result", None): return
        if self._has_product_scope():
            from vstacklens.desktop.product_inspection import PRODUCT_NAMES
            names = [PRODUCT_NAMES[p] for p, c in self.product_scope_checks.items() if c.isChecked()]
            targets = self._selected_product_targets()
            self.scope_label.setText("范围：" + " / ".join(names) + f"\n产品目标：{len(targets)} 个\n类型：单次综合巡检（实验）")
        else:
            self.scope_label.setText(f"客户：{self.customer_input.text() or '待填写'}\nvCenter：{self.vcenter_input.text() or '待填写'}\n类型：标准巡检")

    def _standard_presentation(self, result=None):
        title = self.standard_summary.layout.itemAt(0).widget()
        self.start_button.setText("重新巡检" if result else "开始标准巡检")
        self.start_button.setObjectName("outlineButton" if result else "primaryButton")
        self.view_standard_report_button.setObjectName("primaryButton" if result else "outlineButton")
        self.start_button.setFixedHeight(SIZES["secondary_button" if result else "primary_button"])
        self.view_standard_report_button.setFixedHeight(SIZES["primary_button" if result else "secondary_button"])
        for control in (self.start_button, self.view_standard_report_button):
            control.style().unpolish(control); control.style().polish(control)
        if result:
            caliber = result.customer_caliber
            title.setText("结果摘要")
            self.scope_label.setText(f"{caliber.get('problem_count', '—')} 类问题 · {caliber.get('affected_total', '—')} 个对象\n{caliber.get('health', {}).get('label', '旧口径')}")
            data = self.service.get_dashboard_data(self._db_path(), run_id=result.run_id)
            self.scope_hint.setText("完成时间：" + local_time(data.finished_at))
        else:
            title.setText("任务摘要"); self.inspection_result_label.clear(); self.view_standard_report_button.setEnabled(False)
            self.scope_hint.setText("填写本次巡检资料即可开始"); self._update_task_summary()
    def _resize_standard_columns(self):
        if hasattr(self, "standard_columns"):
            self.standard_columns.setDirection(QHBoxLayout.TopToBottom if self.pages.width() < 1200 else QHBoxLayout.LeftToRight)
            self.standard_result_actions.setDirection(QHBoxLayout.TopToBottom if self.pages.width() < 850 else QHBoxLayout.LeftToRight)
        if hasattr(self,"_resize_batch_pages"):self._resize_batch_pages()
        from PySide6.QtCore import QTimer
        QTimer.singleShot(0, self._resize_desktop_tables)

    def _resize_desktop_tables(self):
        # Main-window resize precedes its child page layout. This queued pass sees the settled content width.
        if hasattr(self, "dashboard_task_row"):
            compact_home = self.pages.width() < 1020
            self.dashboard_task_row.setDirection(QHBoxLayout.TopToBottom if compact_home else QHBoxLayout.LeftToRight)
            self.dashboard_metric_row.setDirection(QHBoxLayout.TopToBottom if self.pages.width() < 850 else QHBoxLayout.LeftToRight)
            self.dashboard_summary_divider.setVisible(self.pages.width() >= 850)
        if hasattr(self,"dashboard_issues"):
            width=self.dashboard_issues.viewport().width()
            grade_width = SIZES["badge_width"] + 2*SIZES["cell_padding"]
            for column, column_width in ((0, grade_width), (1, round(width*.27)), (2, round(width*.16))):
                self.dashboard_issues.horizontalHeader().setSectionResizeMode(column, QHeaderView.Fixed)
                self.dashboard_issues.setColumnWidth(column, column_width)
        if hasattr(self,"risk_examples"):
            width=self.risk_examples.viewport().width()
            self.risk_examples.horizontalHeader().setSectionResizeMode(0,QHeaderView.Fixed);self.risk_examples.setColumnWidth(0,round(width*0.21))
            self.risk_examples.horizontalHeader().setSectionResizeMode(1,QHeaderView.Fixed);self.risk_examples.setColumnWidth(1,round(width*(1-SIZES["examples_value_share"]-0.21)))
        for name in ("dashboard_issues", "dashboard_reports_table", "inspection_tasks_table", "risk_examples"):
            widget = getattr(self, name, None)
            if widget is None: continue
            widget.resizeRowsToContents()
            if name=="dashboard_issues" and widget.rowCount():
                height=max(widget.rowHeight(row) for row in range(widget.rowCount()))
                for row in range(widget.rowCount()):widget.setRowHeight(row,height)
            height = SIZES["table_header"] + sum(widget.rowHeight(i) for i in range(widget.rowCount()))
            widget.setMinimumHeight(height); widget.setMaximumHeight(height)

    def _inspection_config_panel(self):
        card = SectionCard("巡检配置"); form = QFormLayout(); form.setVerticalSpacing(10)
        self.inspection_environment_combo = NoWheelComboBox()
        self.inspection_environment_combo.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.inspection_environment_combo.setMinimumContentsLength(12)
        self.inspection_environment_combo.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Fixed)
        self.inspection_environment_combo.addItem("手动输入（沿用原单环境巡检）", None)
        self.inspection_environment_combo.currentIndexChanged.connect(lambda: self._select_inspection_environment(self.inspection_environment_combo.currentData()))
        form.addRow("环境档案", self.inspection_environment_combo)
        self.vcenter_input = QLineEdit(); self.vcenter_input.setPlaceholderText("请输入 vCenter IP 或 FQDN")
        self.username_input = QLineEdit(); self.password_input = QLineEdit(); self.password_input.setEchoMode(QLineEdit.Password)
        self.customer_input = QLineEdit(); self.report_title_input = QLineEdit(); self.site_input = QLineEdit(); self.site_input.hide()
        for label, item in (("地址", self.vcenter_input), ("用户名", self.username_input), ("密码", self.password_input)): form.addRow(label, item)
        self._build_product_scope(card, form)
        advanced = SectionCard(); advanced.layout.addWidget(muted_label("HTTPS 端口：443\n使用现有连接和证书校验设置；本页不更改连接流程。"))
        self.connection_fold = FoldSection("高级连接设置", advanced); card.layout.addWidget(self.connection_fold)
        output = QFormLayout(); output.addRow("客户名称", self.customer_input); output.addRow("报告名称", self.report_title_input)
        card.layout.addWidget(QLabel("报告设置")); card.layout.addLayout(output)
        more = SectionCard(); self.report_dir_input = PathLineEdit()
        more.layout.addWidget(self._path_row(self.report_dir_input, self._choose_report_dir, "选择目录"))
        more.layout.addWidget(muted_label("报告输出目录；数据库和规则包设置仍在系统设置中维护。"))
        self.output_fold = FoldSection("更多输出设置", more); card.layout.addWidget(self.output_fold)
        return card

    def _inspection_log_panel(self):
        card = SectionCard("执行进度"); self.stage_label = QLabel("等待开始"); self.progress_bar = QProgressBar(); self.progress_bar.setRange(0, 100)
        self.status_label = muted_label("选择产品并填写对应目标的连接资料后启动。")
        card.layout.addWidget(self.stage_label); card.layout.addWidget(self.progress_bar); card.layout.addWidget(self.status_label)
        logs = SectionCard(); self.result_summary = QTextEdit(); self.result_summary.setReadOnly(True); self.result_summary.setMinimumHeight(150)
        logs.layout.addWidget(self.result_summary); logs.layout.addWidget(button("复制运行记录", lambda: QApplication.clipboard().setText(self.result_summary.toPlainText())), alignment=Qt.AlignRight)
        self.logs_fold = FoldSection("详细运行记录", logs); card.layout.addWidget(self.logs_fold)
        actions = QHBoxLayout(); self.cancel_inspection_button = button("取消巡检", self._cancel_inspection); self.cancel_inspection_button.hide(); self.cancel_inspection_button.setEnabled(False)
        self.start_button = button("开始标准巡检", self._start_inspection, primary=True)
        actions.addStretch(1); actions.addWidget(self.cancel_inspection_button); actions.addWidget(self.start_button); card.layout.addLayout(actions)
        self.inspection_result_label = muted_label(""); self.inspection_result_label.hide(); card.layout.addWidget(self.inspection_result_label)
        result = QHBoxLayout()
        self.open_report_button = button("打开 HTML 报告", self._open_current_report)
        self.open_word_button = button("打开 Word 报告", self._open_current_word_report)
        self.open_pdf_button = button("打开 PDF 报告", self._open_current_pdf_report)
        self.open_dir_button = button("打开报告目录", self._open_current_report_dir)
        self.view_standard_report_button = button("查看报告", self._show_latest_standard_report)
        for action in (self.view_standard_report_button, self.open_report_button, self.open_word_button, self.open_pdf_button, self.open_dir_button): action.setEnabled(False); result.addWidget(action)
        self.standard_result_actions = result; card.layout.addLayout(result); return card

    def _risk_center_page(self):
        owner = self
        class RiskPage(QWidget):
            def resizeEvent(self, event):
                super().resizeEvent(event)
                owner._risk_relayout_details()
            def showEvent(self, event):
                super().showEvent(event)
                owner._risk_relayout_details()
            def hideEvent(self, event):
                super().hideEvent(event)
                dialog = getattr(owner, "risk_detail_dialog", None)
                if dialog is not None: dialog.hide()

        page = RiskPage(); self.risk_page = page
        layout = QVBoxLayout(page)
        layout.setContentsMargins(SIZES["page_margin"], SIZES["page_top"], SIZES["page_margin"], SIZES["card_padding"])
        layout.setSpacing(SIZES["card_gap"])
        heading = PageHeader("风险中心")
        self.risk_caliber_summary = heading.subtitle_label
        self.risk_open_detail_button = button("查看详情", self._open_risk_details)
        self.risk_open_detail_button.setEnabled(False); heading.add_action(self.risk_open_detail_button)
        layout.addWidget(heading)
        totals = QHBoxLayout(); self.risk_summary_numbers = NumberSummary()
        for value in self.risk_summary_numbers.values: value.setObjectName("smallMetricValue")
        totals.addWidget(self.risk_summary_numbers, 1)
        divider = QFrame(); divider.setObjectName("conclusionDivider"); divider.setFixedSize(1, SIZES["badge_height"])
        totals.addWidget(divider); self.risk_header_metrics = {}
        for level in ("P1", "P2", "P3"):
            totals.addWidget(risk_badge(level))
            value = MetricValueLabel("0"); value.setObjectName("smallMetricValue")
            totals.addWidget(value); self.risk_header_metrics[level] = value
        layout.addLayout(totals)
        filters = QHBoxLayout(); filters.addWidget(QLabel("等级："))
        self.risk_level_filter = NoWheelComboBox(); self.risk_level_filter.addItems(["全部等级", "P1", "P2", "P3"])
        self.risk_type_filter = NoWheelComboBox(); self.risk_type_filter.addItem("全部对象", "")
        self.risk_level_filter.setMinimumWidth(112); self.risk_type_filter.setMinimumWidth(130)
        for kind in ("vCenter", "ClusterComputeResource", "HostSystem", "Datastore", "VirtualMachine"):
            self.risk_type_filter.addItem(object_name(kind), kind)
        self.risk_keyword_input = QLineEdit(); self.risk_keyword_input.setPlaceholderText("搜索问题或对象")
        from vstacklens.desktop.navigation_icons import navigation_icon
        self.risk_keyword_input.addAction(navigation_icon("log_analysis"), QLineEdit.LeadingPosition)
        for item in (self.risk_level_filter, self.risk_type_filter, self.risk_keyword_input):
            (item.textChanged if isinstance(item, QLineEdit) else item.currentIndexChanged).connect(self._populate_risk_table)
            if item is self.risk_type_filter: filters.addWidget(QLabel("对象："))
            filters.addWidget(item, 1 if item is self.risk_keyword_input else 0)
        self.risk_non_reported = QCheckBox("显示不进入报告的项"); self.risk_non_reported.setChecked(False)
        self.risk_non_reported.toggled.connect(self._refresh_risk_items); filters.addWidget(self.risk_non_reported)
        layout.addLayout(filters)
        self.risk_empty = muted_label("尚无巡检记录"); layout.addWidget(self.risk_empty)
        from PySide6.QtWidgets import QSplitter
        self.risk_splitter = QSplitter(Qt.Horizontal); self.risk_splitter.setChildrenCollapsible(False)
        self.risk_list = table(self, ["等级", "问题", "对象数"])
        self.risk_list.setMinimumWidth(320); self.risk_list.setWordWrap(False); self.risk_list.setTextElideMode(Qt.ElideRight)
        self.risk_list.currentCellChanged.connect(self._risk_selection_changed)
        self.risk_list.doubleClicked.connect(self._open_risk_details)
        self.risk_list.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        self.risk_list.setColumnWidth(0, SIZES["badge_width"] + 2*SIZES["cell_padding"])
        self.risk_list.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.risk_list.horizontalHeader().setSectionResizeMode(2, QHeaderView.Fixed); self.risk_list.setColumnWidth(2, 94)
        self.risk_detail_card = SectionCard(); self.risk_detail_card.setMinimumWidth(0)
        self.risk_detail_card.layout.setSpacing(SIZES["card_gap"])
        self.risk_title = QLabel(); self.risk_title.setWordWrap(True); self.risk_title.setObjectName("detailHeading")
        self.risk_title.setMinimumWidth(0); self.risk_title.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.risk_title.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.risk_title_strip = QFrame(); self.risk_title_strip.setFixedSize(SIZES["title_strip_width"], SIZES["title_strip_height"])
        detail_heading = QHBoxLayout(); detail_heading.addWidget(self.risk_title_strip); detail_heading.addWidget(self.risk_title, 1)
        detail_heading.addWidget(button("关闭详情", self._close_risk_details, quiet=True))
        self.risk_detail_card.layout.addLayout(detail_heading)
        self.risk_badge_row = QHBoxLayout(); self.risk_detail_card.layout.addLayout(self.risk_badge_row)
        self.risk_object_count = muted_label(""); self.risk_detail_card.layout.addWidget(self.risk_object_count)
        self.risk_evidence_hint = muted_label(""); self.risk_evidence_hint.setWordWrap(True)
        self.risk_detail_card.layout.addWidget(self.risk_evidence_hint); self.risk_evidence_hint.hide()
        self.risk_current = QLabel(); self.risk_advice = QLabel()
        for item in (self.risk_current, self.risk_advice):
            item.setWordWrap(True); item.setObjectName("detailBody"); item.setTextInteractionFlags(Qt.TextSelectableByMouse)
        for title, body in (("当前情况", self.risk_current), ("建议", self.risk_advice)):
            divider = QFrame(); divider.setObjectName("conclusionDivider"); divider.setFixedHeight(1)
            self.risk_detail_card.layout.addWidget(divider)
            section = QVBoxLayout(); section.setSpacing(4); label = QLabel(title); label.setObjectName("detailHeading")
            section.addWidget(label); section.addWidget(body); self.risk_detail_card.layout.addLayout(section)
        divider = QFrame(); divider.setObjectName("conclusionDivider"); divider.setFixedHeight(1)
        self.risk_detail_card.layout.addWidget(divider)
        label = QLabel("相关对象示例"); label.setObjectName("detailHeading"); self.risk_detail_card.layout.addWidget(label)
        self.risk_examples = table(self, ["对象类型", "对象名称", "当前情况"]); self.risk_detail_card.layout.addWidget(self.risk_examples)
        self.risk_examples.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        row = QHBoxLayout(); row.addWidget(button("查看对象明细", self._show_object_details))
        row.addWidget(button("查看关联报告", self._show_latest_standard_report))
        self.risk_detail = QTextEdit(); self.risk_detail.setReadOnly(True); self.risk_detail.hide(); self.risk_detail_card.layout.addWidget(self.risk_detail)
        self.risk_detail_card.layout.addStretch(1); self.risk_detail_card.layout.addLayout(row)
        self.risk_detail_side = QWidget(); side = QVBoxLayout(self.risk_detail_side); side.setContentsMargins(0, 0, 0, 0)
        self.risk_details_scroll = self._scroll_page(self.risk_detail_card); side.addWidget(self.risk_details_scroll, 1)
        self.risk_detail_dialog = QDialog(self); self.risk_detail_dialog.setWindowTitle("风险详情")
        self.risk_detail_dialog.setModal(False); self.risk_detail_dialog.setMinimumSize(480, 360)
        dialog_layout = QVBoxLayout(self.risk_detail_dialog); dialog_layout.setContentsMargins(0, 0, 0, 0)
        self.risk_detail_dialog.finished.connect(self._close_risk_details)
        self._risk_detail_open = False
        self.risk_splitter.addWidget(self.risk_list); self.risk_splitter.addWidget(self.risk_detail_side)
        self.risk_splitter.setStretchFactor(0, 3); self.risk_splitter.setStretchFactor(1, 2)
        self.risk_detail_side.hide(); layout.addWidget(self.risk_splitter, 1)
        return page

    def _open_risk_details(self, *args):
        if self.risk_list.currentItem() is None: return
        self._risk_detail_open = True
        self._risk_selection_changed(); self._risk_relayout_details()

    def _close_risk_details(self, *args):
        self._risk_detail_open = False
        self.risk_detail_dialog.hide(); self.risk_detail_side.hide()

    def _risk_relayout_details(self):
        if not hasattr(self, "risk_detail_dialog"): return
        if not self._risk_detail_open:
            self.risk_detail_side.hide(); self.risk_detail_dialog.hide(); return
        if self.risk_page.width() >= 1080:
            self.risk_detail_dialog.hide()
            if self.risk_details_scroll.parentWidget() is not self.risk_detail_side:
                self.risk_detail_side.layout().addWidget(self.risk_details_scroll)
            self.risk_detail_side.show(); self.risk_details_scroll.show()
            if self.risk_splitter.sizes()[1] < 200:
                width = self.risk_splitter.width(); self.risk_splitter.setSizes([round(width*.58), round(width*.42)])
        else:
            self.risk_detail_side.hide()
            if self.risk_details_scroll.parentWidget() is not self.risk_detail_dialog:
                self.risk_detail_dialog.layout().addWidget(self.risk_details_scroll)
            self.risk_details_scroll.show()
            if self.risk_page.isVisible() and not self.risk_detail_dialog.isVisible():
                self.risk_detail_dialog.resize(min(760, max(500, self.width()-80)), max(400, min(700, self.height()-80)))
                self.risk_detail_dialog.show()

    @staticmethod
    def _risk_group_key(group):
        category, items, reason = group
        return (category.get("category_id", category.get("title", "")), reason,
                tuple(sorted((item.object_type, item.object_name, getattr(item, "finding_id", ""), item.rule_id) for item in items)))

    def _populate_risk_table(self):
        if not hasattr(self, "risk_list"): return
        selected = self.risk_list.currentItem(); selected_key = None
        if selected is not None and selected.data(Qt.UserRole) is not None:
            index = selected.data(Qt.UserRole)
            if index < len(getattr(self, "_risk_groups", [])): selected_key = self._risk_group_key(self._risk_groups[index])
        scroll = (self.risk_list.verticalScrollBar().value(), self.risk_list.horizontalScrollBar().value())
        sorting = self.risk_list.isSortingEnabled(); header = self.risk_list.horizontalHeader()
        sort_column, sort_order = header.sortIndicatorSection(), header.sortIndicatorOrder()
        data = self._view_data(); caliber = data.customer_caliber if data else {}
        scope = data.run_id if data else None
        if getattr(self, "_risk_list_scope", scope) != scope:
            selected_key = None; scroll = (0, 0); self._close_risk_details()
        self._risk_list_scope = scope
        task = next((r for r in data.recent_reports if r.run_id == data.run_id), None) if data else None
        self.risk_caliber_summary.setText(f"标准任务：{self._short_task(data.run_id if data else '')} · {local_time(data.finished_at if data else None)}")
        self.risk_caliber_summary.setVisible(True)
        self.risk_caliber_summary.setToolTip(data.run_id if data else "")
        self.risk_summary_numbers.set_counts(caliber.get('problem_count', '—'), caliber.get('affected_total', '—'))
        for level, label in self.risk_header_metrics.items(): label.setText(str(caliber.get('counts', {}).get(level, '—')))
        self._risk_groups = []; keyword = self.risk_keyword_input.text().strip().lower(); level = self.risk_level_filter.currentText(); kind = self.risk_type_filter.currentData()
        for category in caliber.get("categories", []):
            items = [x for x in self._risk_items if x.category_id == category["category_id"] and not x.non_report_reason]
            exact=getattr(self,"_risk_exact_asset",None)
            if exact and (keyword!=exact[1].casefold() or kind!=exact[0]):self._risk_exact_asset=None;exact=None
            if exact:
                items=[x for x in items if (x.object_type,x.object_name)==exact]
                if not items:continue
            if level != "全部等级" and category["priority"] != level: continue
            if kind and not any(x.object_type == kind for x in items): continue
            if keyword and keyword not in (category["title"] + " ".join(x.object_name for x in items)).lower(): continue
            self._risk_groups.append((category, items, ""))
        if self.risk_non_reported.isChecked():
            for reason in ("P4", "已定不报", "待映射"):
                for item in self._risk_items:
                    if item.non_report_reason != reason: continue
                    if kind and item.object_type != kind: continue
                    if keyword and keyword not in (item.title + item.object_name).lower(): continue
                    self._risk_groups.append(({"title": item.title, "affected_object_count": 1, "priority": item.risk_level}, [item], reason))
        self.risk_list.blockSignals(True); self.risk_list.setSortingEnabled(False); self.risk_list.clearContents(); self.risk_list.setRowCount(0); self.risk_list.clearSpans(); last_reason = None
        for i, (category, items, reason) in enumerate(self._risk_groups):
            if reason and reason != last_reason:
                row = self.risk_list.rowCount(); self.risk_list.insertRow(row)
                header = QTableWidgetItem("不进入客户报告 · " + reason); header.setFlags(Qt.NoItemFlags); self.risk_list.setItem(row, 0, header); self.risk_list.setSpan(row, 0, 1, 3); last_reason = reason
            row = self.risk_list.rowCount(); self.risk_list.insertRow(row)
            for column, value in enumerate(("—" if reason else category["priority"], category["title"], str(category["affected_object_count"]))):
                entry = QTableWidgetItem(ui_text(value)); entry.setData(Qt.UserRole, i)
                entry.setToolTip(ui_text(value))
                entry.setTextAlignment((Qt.AlignRight if column == 2 else Qt.AlignLeft) | Qt.AlignVCenter)
                self.risk_list.setItem(row, column, entry)
            if not reason: self.risk_list.setCellWidget(row, 0, badge_cell(category["priority"]))
        self.risk_list.resizeRowsToContents()
        for row in range(self.risk_list.rowCount()):self.risk_list.setRowHeight(row,max(SIZES["risk_row"],self.risk_list.rowHeight(row)))
        self.risk_list.setSortingEnabled(sorting)
        if sorting: self.risk_list.sortItems(sort_column, sort_order)
        self.risk_list.blockSignals(False)
        self.risk_empty.setVisible(not self._risk_groups); self.risk_empty.setText("未发现进入客户报告的问题" if data and data.has_data else "尚无巡检记录")
        self.risk_splitter.setVisible(bool(self._risk_groups))
        self.risk_open_detail_button.setEnabled(bool(self._risk_groups))
        if self._risk_groups:
            target = next((i for i, group in enumerate(self._risk_groups) if self._risk_group_key(group) == selected_key), 0)
            row = next((row for row in range(self.risk_list.rowCount()) if self.risk_list.item(row, 1) is not None
                        and self.risk_list.item(row, 1).data(Qt.UserRole) == target), 0)
            self.risk_list.setCurrentCell(row, 1); self.risk_list.selectRow(row); self._risk_selection_changed()
            self.risk_list.verticalScrollBar().setValue(scroll[0]); self.risk_list.horizontalScrollBar().setValue(scroll[1])
        else:
            self._selected_risk_objects = []; self._close_risk_details()

    def _risk_selection_changed(self, *args):
        entry = self.risk_list.currentItem()
        if entry is None or entry.data(Qt.UserRole) is None: return
        category, items, reason = self._risk_groups[entry.data(Qt.UserRole)]
        self._selected_risk_objects = items; self.risk_title.setText(ui_text(category["title"]))
        self.risk_title.setToolTip(ui_text(category["title"]))
        self.risk_title_strip.setStyleSheet(f"background:{COLORS.get(category['priority'],COLORS['subtext'])};border:none;")
        self._clear_layout(self.risk_badge_row)
        self.risk_badge_row.addWidget(QLabel("不进入客户报告：" + reason) if reason else risk_badge(category["priority"]), alignment=Qt.AlignLeft)
        self.risk_object_count.setText(f"影响对象：{category['affected_object_count']} 个")
        self.risk_current.setText("\n".join(dict.fromkeys(current_sentence(x) for x in items)))
        self.risk_advice.setText(ui_text(category.get("remediation_zh") or (items[0].remediation if items else "") or "请核查具体对象及对应证据。"))
        unknown = {"", "未记录", "—", "None"}
        limited = not items or any(str(item.current_observed or "").strip() in unknown
                                  or str(getattr(item, "status", "")).upper() in {"NOT_EVALUATED", "INSUFFICIENT_DATA", "UNAVAILABLE", "UNSUPPORTED"}
                                  for item in items)
        self.risk_evidence_hint.setText("资料不足：部分对象缺少有效的当前值，不能据此判断正常。" if limited else "")
        self.risk_evidence_hint.setVisible(limited)
        fill_table(self.risk_examples, [(object_name(x.object_type), x.object_name, current_sentence(x)) for x in items[:5]])
        for row in range(self.risk_examples.rowCount()):
            for column in range(self.risk_examples.columnCount()):
                cell = self.risk_examples.item(row, column)
                if cell is not None: cell.setToolTip(cell.text())
        if items: self._engineer_risk_detail(items[0])
        else: self.risk_detail.clear()
    def _show_object_details(self):
        dialog = QDialog(self); dialog.setWindowTitle("对象明细"); dialog.resize(760, 540); layout = QVBoxLayout(dialog); text = QTextEdit(); text.setReadOnly(True)
        details = []
        for item in getattr(self, "_selected_risk_objects", []):
            self._engineer_risk_detail(item); details.append(self.risk_detail.toPlainText())
        text.setPlainText(ui_text("\n\n".join(details))); layout.addWidget(text); dialog.exec()

    def _localize_visible_text(self):
        # Display only: editable fields, identifiers, stored values and reports remain untouched.
        for item in self.findChildren(QLabel):
            text = item.text(); shown = ui_text(text)
            for run_id, short in getattr(self, "_task_numbers", {}).items():
                if run_id in shown:
                    item.setToolTip(text); shown = shown.replace(run_id, short)
            if shown != text: item.setText(shown)
        for widget in self.findChildren(QTableWidget):
            for i in range(widget.rowCount()):
                for j in range(widget.columnCount()):
                    cell = widget.item(i, j)
                    if cell:
                        shown = ui_text(cell.text())
                        for run_id, short in getattr(self, "_task_numbers", {}).items():
                            if run_id in shown:
                                cell.setToolTip(cell.text()); shown = shown.replace(run_id, short)
                        cell.setText(shown)
                        header = widget.horizontalHeaderItem(j)
                        numeric = header and header.text() in {"涉及对象", "对象数", "数量", "风险数", "问题数量", "问题类别", "新增", "减少"}
                        alignment = (Qt.AlignRight if numeric else Qt.AlignLeft) | Qt.AlignVCenter
                        cell.setTextAlignment(alignment)
                        if header: header.setTextAlignment(alignment)
        for widget in self.findChildren(QTextEdit):
            if widget.isReadOnly() and widget not in (self.result_summary, self.risk_detail):
                text = widget.toPlainText(); shown = ui_text(text)
                for run_id, short in getattr(self, "_task_numbers", {}).items():
                    if run_id in shown: widget.setToolTip(text); shown = shown.replace(run_id, short)
                if shown != text: widget.setPlainText(shown)
        for widget in self.findChildren(QListWidget):
            for index in range(widget.count()):
                item = widget.item(index); text = item.text()
                for run_id, short in getattr(self, "_task_numbers", {}).items():
                    if run_id in text: item.setToolTip(item.text()); text = text.replace(run_id, short)
                if text != item.text(): item.setText(text)
        for widget in self.findChildren(NoWheelComboBox):
            for index in range(widget.count()):
                text = widget.itemText(index)
                for run_id, short in getattr(self, "_task_numbers", {}).items():
                    if run_id in text: widget.setItemData(index, text, Qt.ToolTipRole); text = text.replace(run_id, short)
                if text != widget.itemText(index): widget.setItemText(index, text)
