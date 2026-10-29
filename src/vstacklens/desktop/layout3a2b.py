"""Second batch desktop layouts, reusing existing controls and service handlers."""
from pathlib import Path
import calendar,re
from datetime import datetime
from PySide6.QtCore import Qt,QRectF,QPointF,QSize,Signal
from PySide6.QtWidgets import (QWidget,QLabel,QVBoxLayout,QHBoxLayout,QFormLayout,QGridLayout,
    QRadioButton,QButtonGroup,QPushButton,QTreeWidget,QTreeWidgetItem,QFrame,QApplication,QScrollArea,QSizePolicy)
from vstacklens.desktop.widgets import SectionCard,muted_label,status_badge,PathLineEdit,StatusBadge
from vstacklens.desktop.layout3a import page_layout,button,FoldSection
from vstacklens.desktop.task_layout import TaskWorkspace,ContentHeight,SingleStatusDelegate
from vstacklens.desktop.navigation_icons import navigation_icon,PATHS
from PySide6.QtGui import QPainter,QPen,QColor
from PySide6.QtSvg import QSvgRenderer
from vstacklens.desktop.theme import SIZES,COLORS
from vstacklens.desktop.presentation import ui_text
from vstacklens.desktop.topology import ProductLogo
from vstacklens.application.logging_config import APP_VERSION,runtime_log_path

PRIVACY_TEXT = "vCenter / ESXi 连接密码仅用于本次使用，不写入配置和报告；模型 API Key 保存在本机配置文件中。"
LOG_STEPS = ("读取日志","整理证据","形成判断","生成报告")
LOG_STAGE_INDEX = {"reading_bundle":0,"analyzing_logs":1,"cloud_planning":1,
    "cloud_diagnosing":2,"rendering_html":3,"rendering_docx":3,"success":3,"completed":3,"started":0}

class StepCircle(QWidget):
    def __init__(self,module):
        super().__init__();self.module=module;self.setProperty("stepStatus","unknown")
        self.setFixedSize(SIZES["batch2_step_icon"],SIZES["batch2_step_icon"])
    def paintEvent(self,event):
        painter=QPainter(self);painter.setRenderHint(QPainter.Antialiasing)
        state=self.property("stepStatus");color=COLORS["P1"] if state=="failed" else COLORS["primary"] if state in {"running","success"} else COLORS["subtext"]
        painter.setPen(QPen(QColor(color),SIZES["step_outline_width"]));painter.setBrush(QColor(COLORS["primary"]) if state=="success" else Qt.NoBrush)
        inset=SIZES["step_outline_width"];painter.drawEllipse(QRectF(inset,inset,self.width()-2*inset,self.height()-2*inset))
        ink=COLORS["button_text"] if state=="success" else color
        svg=f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="{ink}" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">{PATHS[self.module]}</svg>'
        margin=SIZES["cell_icon_margin"];QSvgRenderer(svg.encode()).render(painter,QRectF(margin,margin,self.width()-2*margin,self.height()-2*margin))

class StepTrack(QWidget):
    def __init__(self):
        super().__init__();self.setObjectName("inlineNumberGroup");self.circles=[]
    def paintEvent(self,event):
        painter=QPainter(self)
        for left,right in zip(self.circles,self.circles[1:]):
            origin=left.mapTo(self,left.rect().center());target=right.mapTo(self,right.rect().center())
            color=COLORS["primary"] if left.property("stepStatus")=="success" else COLORS["divider"]
            painter.setPen(QPen(QColor(color),SIZES["step_connector_width"]))
            painter.drawLine(QPointF(origin.x()+left.width()/2,origin.y()),QPointF(target.x()-right.width()/2,target.y()))

class InspectionModeRadio(QRadioButton):
    def sizeHint(self):
        metrics=self.fontMetrics();return QSize(metrics.horizontalAdvance(self.text())+SIZES["mode_radio_size"]+SIZES["mode_radio_gap"],max(metrics.height(),SIZES["mode_radio_size"])+2*SIZES["section_gap"])
    def paintEvent(self,event):
        painter=QPainter(self);painter.setRenderHint(QPainter.Antialiasing)
        diameter=SIZES["mode_radio_size"];top=(self.height()-diameter)/2;color=COLORS["primary"] if self.isChecked() else COLORS["subtext"]
        painter.setPen(QPen(QColor(color),SIZES["step_outline_width"]));painter.setBrush(Qt.NoBrush);painter.drawEllipse(QRectF(1,top,diameter,diameter))
        if self.isChecked():
            painter.setPen(Qt.NoPen);painter.setBrush(QColor(COLORS["primary"]));r=SIZES["mode_radio_dot"];painter.drawEllipse(QPointF(1+diameter/2,self.height()/2),r,r)
        painter.setPen(QColor(COLORS["text"] if self.isChecked() else COLORS["subtext"]));painter.drawText(self.rect().adjusted(diameter+SIZES["mode_radio_gap"],0,0,0),Qt.AlignLeft|Qt.AlignVCenter,self.text())
        if self.hasFocus():
            painter.setPen(QPen(QColor(COLORS["subtext"]),1,Qt.DotLine));painter.setBrush(Qt.NoBrush);painter.drawRect(self.rect().adjusted(0,0,-1,-1))

class UpgradeStateBadge(StatusBadge):
    def __init__(self,text):
        super().__init__(text);self.setObjectName("batch2StateBadge");self.setText(text)
    def setText(self,text):
        super().setText(text)
        role="success" if text=="完成" else "running" if text=="进行中" else "failed" if "失败" in text else "warning" if "诊断" in text else "unknown"
        self.setProperty("status",role);self.style().unpolish(self);self.style().polish(self);self.update()

class CardArrow(QWidget):
    def __init__(self,detail):
        super().__init__();self.detail=detail;self.setFixedSize(SIZES["fold_arrow"],SIZES["fold_arrow"]);self.setAttribute(Qt.WA_TransparentForMouseEvents)
    def paintEvent(self,event):
        painter=QPainter(self);painter.setRenderHint(QPainter.Antialiasing);painter.setPen(QPen(QColor(COLORS["subtext"]),SIZES["step_outline_width"]))
        x=self.width()/2;y=self.height()/2;d=self.width()/4
        points=(QPointF(x-d,y+d/2),QPointF(x,y-d/2),QPointF(x+d,y+d/2)) if not self.detail.isHidden() else (QPointF(x-d,y-d/2),QPointF(x,y+d/2),QPointF(x+d,y-d/2))
        painter.drawLine(points[0],points[1]);painter.drawLine(points[1],points[2])

class CollapsibleCardHeader(QFrame):
    def __init__(self,toggle,detail):
        super().__init__();self.toggle=toggle;self.detail=detail;self.setObjectName("batch2CardHeader");self.setCursor(Qt.PointingHandCursor);self.setFocusPolicy(Qt.StrongFocus)
        self.arrow=CardArrow(detail)
    def activate(self):
        self.toggle.click();self.arrow.update();self.setProperty("expanded",not self.detail.isHidden());self.update()
    def mouseReleaseEvent(self,event):
        if event.button()==Qt.LeftButton:self.activate();event.accept()
        else:super().mouseReleaseEvent(event)
    def keyPressEvent(self,event):
        if event.key() in {Qt.Key_Space,Qt.Key_Return,Qt.Key_Enter}:self.activate();event.accept()
        else:super().keyPressEvent(event)

class BundleNameEdit(PathLineEdit):
    def __init__(self):
        super().__init__();self.setClearButtonEnabled(True)
        self.textEdited.connect(lambda text:self.set_path_value("") if not text else None)
    def _show_elided(self):
        self.setText(Path(self._full_value).name if self._full_value else "")
    def clear(self):self.set_path_value("")

def material_date(value):
    text=str(value or "")
    try:return datetime.fromisoformat(text.replace("Z","+00:00")).strftime("%Y-%m-%d")
    except ValueError:pass
    months={name:i for i,name in enumerate(calendar.month_name) if name}
    match=re.search(r"([A-Za-z]+)\s+(\d{1,2}),\s+(\d{4})",text)
    if match and match[1] in months:return f"{match[3]}-{months[match[1]]:02d}-{int(match[2]):02d}"
    return text or "未记录"


def log_step(stage, previous=0):
    return previous if stage=="failed" else LOG_STAGE_INDEX.get(stage,previous)

def icon_heading(card,title,module,description=""):
    for label in card.findChildren(QLabel,options=Qt.FindDirectChildrenOnly):
        if label.objectName()=="sectionTitle":label.hide()
    row=QHBoxLayout();icon=QLabel();icon.setPixmap(navigation_icon(module,size=SIZES["batch2_card_icon"]).pixmap(SIZES["batch2_card_icon"],SIZES["batch2_card_icon"]))
    row.addWidget(icon);label=QLabel(title);label.setObjectName("sectionTitle");row.addWidget(label,1);card.layout.insertLayout(0,row)
    if description:card.layout.insertWidget(1,muted_label(description))
    return row

def form():
    result=QFormLayout();result.setLabelAlignment(Qt.AlignLeft|Qt.AlignVCenter)
    result.setVerticalSpacing(SIZES["card_gap"]);result.setHorizontalSpacing(SIZES["detail_gap"])
    result.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow);result.setFormAlignment(Qt.AlignLeft|Qt.AlignTop);return result

class RowForms:
    """Route existing desktop row visibility calls after splitting one form."""
    def __init__(self,*forms):self.forms=forms
    def setRowVisible(self,widget,visible):
        for layout in self.forms:
            if layout.getWidgetPosition(widget)[0]>=0:layout.setRowVisible(widget,visible);return

class Layout3a2bMixin:
    def _adopt_widget_tree(self,widget):
        layout=getattr(widget,"layout")
        layout=layout() if callable(layout) else layout
        if layout is None:return
        self._adopt_layout_tree(layout,widget)

    def _adopt_layout_tree(self,layout,owner):
        for index in range(layout.count()):
            item=layout.itemAt(index)
            if item.widget():
                child=item.widget()
                if child.parentWidget() is not owner:child.setParent(owner)
                self._adopt_widget_tree(child)
            elif item.layout():self._adopt_layout_tree(item.layout(),owner)

    def _retain_batch2(self,widget):
        if not hasattr(self,"_batch2_retained"):self._batch2_retained=[]
        widget.setParent(self);widget.hide();self._batch2_retained.append(widget)

    def _batch2_fixed_footer_page(self,page,footer_layout):
        self._adopt_widget_tree(page)
        outer=page.layout();title=outer.takeAt(0).widget();body=QWidget();body_layout=QVBoxLayout(body);body_layout.setContentsMargins(0,0,0,0);body_layout.setSpacing(SIZES["card_gap"]);saved_footer=None
        while outer.count():
            item=outer.takeAt(0)
            if item.layout() is footer_layout:saved_footer=footer_layout;continue
            body_layout.addItem(item)
            if item.layout():self._adopt_layout_tree(item.layout(),body)
            elif item.widget() and item.widget().parentWidget() is not body:item.widget().setParent(body)
        outer.setContentsMargins(SIZES["page_margin"],SIZES["page_top"],SIZES["page_margin"],SIZES["card_padding"])
        body_scroll=self._scroll_page(body);outer.addWidget(title);outer.addWidget(body_scroll,1)
        footer=QWidget();footer.setObjectName("batch2StickyFooter");self._adopt_layout_tree(saved_footer,footer);footer.setLayout(saved_footer);outer.addWidget(footer)
        return page

    def _batch2_log_page(self):
        old_input=self._log_analysis_config_panel();old_result=self._log_analysis_result_panel()
        self._retain_batch2(old_input);self._retain_batch2(old_result)
        page,layout=page_layout("日志分析")
        config=SectionCard("分析输入");fields=form()
        bundle_row=self.log_bundle_input.parentWidget();previous=self.log_bundle_input;self.log_bundle_input=BundleNameEdit();bundle_row.layout().replaceWidget(previous,self.log_bundle_input);previous.hide()
        for control in bundle_row.findChildren(QPushButton):control.setText("选择文件")
        fields.addRow("日志包",bundle_row);fields.addRow("客户",self.log_customer_input)
        self.log_problem_input.setMinimumHeight(SIZES["batch2_problem_height"]);self.log_problem_input.setMaximumHeight(SIZES["batch2_problem_height"])
        fields.addRow("问题描述",self.log_problem_input);self.log_character_count=muted_label("0 字",word_wrap=False);fields.addRow("",self.log_character_count)
        self.log_problem_input.textChanged.connect(lambda:self.log_character_count.setText(f"{len(self.log_problem_input.toPlainText())} 字"))
        fields.addRow("报告名称",self.log_report_title_input);config.layout.addLayout(fields)
        config.layout.addWidget(self.log_cloud_enabled_input);self.log_privacy_notice=muted_label("");config.layout.addWidget(self.log_privacy_notice)
        self.log_cloud_fields=QWidget();cloud=form();self.log_cloud_fields.setLayout(cloud)
        cloud.addRow("模型配置",self.log_model_profile_combo);cloud.addRow("模型",self.log_model_input.parentWidget());cloud.addRow("状态",self.log_cloud_status_label);config.layout.addWidget(self.log_cloud_fields)
        more=QWidget();extra=form();more.setLayout(extra);extra.addRow("输出目录",self.log_report_dir_input.parentWidget());extra.addRow("",muted_label("日志分析是独立功能，仅基于导入的 support bundle 生成报告，不写入健康巡检结果。"))
        for text in ("本地分析可能需要几分钟，请耐心等待。","分析结果基于日志内容进行推断，仅供参考。","如需进一步确认，请结合实际环境进行验证。"):
            extra.addRow("",muted_label(text))
        config.layout.addWidget(FoldSection("输出位置与分析说明",more))
        self.log_cloud_enabled_input.toggled.connect(self._batch2_log_privacy)
        progress=SectionCard();self.log_step_labels=[];self.log_step_icons=[];self.log_step_track=StepTrack();steps=QHBoxLayout(self.log_step_track);steps.setContentsMargins(0,0,0,0);steps.setSpacing(0)
        for index,(title,module) in enumerate(zip(LOG_STEPS,("log_analysis","history_compare","risk_center","report_center"))):
            block=QWidget();block.setObjectName("inlineNumberGroup");stack=QVBoxLayout(block);stack.setContentsMargins(0,0,0,0)
            circle=StepCircle(module);circle.setFixedSize(36,36);caption=QLabel(f"{index+1}. {title}");caption.setProperty("stepStatus","unknown");caption.setAlignment(Qt.AlignHCenter)
            stack.addWidget(circle,alignment=Qt.AlignHCenter);stack.addWidget(caption);self.log_step_icons.append(circle);self.log_step_labels.append(caption);steps.addWidget(block,1)
        self.log_step_track.circles=self.log_step_icons;self._log_step_index=0;progress.layout.addWidget(self.log_step_track);progress.layout.addWidget(self.log_progress_bar)
        result=SectionCard();head=QHBoxLayout();head.addWidget(QLabel("任务状态与结果"),1);self.log_stage_label.setObjectName("sectionTitle");head.addWidget(self.log_stage_label);result.layout.addLayout(head);result.layout.addWidget(self.log_status_label)
        self.log_result_empty=muted_label("暂无日志分析结果");result.layout.addWidget(self.log_result_empty)
        self.log_result_fold=FoldSection("详细分析记录",self.log_result_summary);result.layout.addWidget(self.log_result_fold);self.log_result_height=ContentHeight(self.log_result_summary)
        self.log_result_summary.textChanged.connect(self._batch2_log_result_visibility);self._batch2_log_result_visibility()
        self.log_workspace=TaskWorkspace(config,progress,result);self.log_workspace.phaseChanged.connect(self._log_task_phase_changed);self.log_workspace.layout().insertWidget(1,self.log_privacy_notice);self.log_input_scroll=self.log_workspace.scroll;layout.addWidget(self.log_workspace,1)
        self.log_start_button.setText("开始分析");self.log_start_button.setProperty("keepInPanel",True);self.log_start_button.setFixedHeight(SIZES["primary_button"])
        footer=QHBoxLayout();self.log_delivery_actions=QWidget();actions=QHBoxLayout(self.log_delivery_actions);actions.setContentsMargins(0,0,0,0)
        for control in (self.open_log_html_button,self.open_log_word_button,self.open_log_dir_button):actions.addWidget(control)
        footer.addWidget(self.log_delivery_actions);footer.addStretch(1);footer.addWidget(self.log_start_button);layout.addLayout(footer)
        self._adopt_widget_tree(page);self._log_task_phase_changed("idle");self._batch2_log_privacy();return page

    def _log_task_phase_changed(self,phase):
        finished=phase in {"completed","failed","cancelled"}
        self.log_result_fold.body.setVisible(finished);self.log_result_fold.toggle.setVisible(not finished)
        self.log_delivery_actions.setVisible(phase=="completed")

    def _batch2_log_result_visibility(self):
        has_text=bool(self.log_result_summary.toPlainText().strip())
        phase=getattr(getattr(self,"log_workspace",None),"phase","idle")
        if phase!="running" or not has_text:self.log_result_summary.setVisible(has_text)
        self.log_result_empty.setVisible(not has_text)

    def _batch2_log_privacy(self,*args):
        if not hasattr(self,"log_privacy_notice"):return
        level=self._current_privacy_level()
        descriptions={"standard":"标准脱敏","strict":"严格脱敏","local-only":"仅本地"}
        self.log_privacy_notice.setText("当前脱敏级别："+descriptions.get(level,level)+"。启用大模型辅助分析时，将向所选模型 API 发送筛选后的日志证据；现有日志处理会遮蔽敏感字段。仅本地模式不发起模型调用。")
        self.log_privacy_notice.setVisible(self.log_cloud_enabled_input.isChecked() or level=="local-only")
        if hasattr(self,"log_cloud_fields"):self.log_cloud_fields.setVisible(self.log_cloud_enabled_input.isChecked())

    def _batch2_log_state(self,stage,state="进行中"):
        if not hasattr(self,"log_step_labels"):return
        self._log_step_index=log_step(stage,self._log_step_index)
        self.log_stage_label.setText(state)
        for i,label in enumerate(self.log_step_labels):
            status="failed" if stage=="failed" and i==self._log_step_index else "success" if i<self._log_step_index or state=="完成" else "running" if i==self._log_step_index and state=="进行中" else "unknown"
            label.setProperty("status",status);label.setProperty("stepStatus",status);icon=self.log_step_icons[i];icon.setProperty("stepStatus",status)
            for widget in (label,icon):widget.style().unpolish(widget);widget.style().polish(widget);widget.update()
        self.log_step_track.update()
        if hasattr(self,"log_workspace"):self.log_workspace.set_phase("failed" if state=="失败" else "completed" if state=="完成" else "running")

    def _batch2_upgrade_page(self):
        legacy=self._legacy_upgrade_compat_page();self._retain_batch2(legacy)
        page,layout=page_layout("升级兼容性");config=SectionCard("检查配置");fields=form()
        fields.addRow("目标 ESXi 版本",self.upgrade_release_combo)
        radio_body=QWidget();radio_row=QHBoxLayout(radio_body);radio_row.setContentsMargins(0,0,0,0)
        self.upgrade_vcenter_radio=InspectionModeRadio("连接 vCenter");self.upgrade_bundle_radio=InspectionModeRadio("导入支持包")
        self.upgrade_mode_buttons=QButtonGroup(self);self.upgrade_mode_buttons.addButton(self.upgrade_vcenter_radio,0);self.upgrade_mode_buttons.addButton(self.upgrade_bundle_radio,1);self.upgrade_collection_combo.hide()
        for control,value in ((self.upgrade_vcenter_radio,"vcenter"),(self.upgrade_bundle_radio,"support_bundle")):
            control.toggled.connect(lambda checked,v=value:self.upgrade_collection_combo.setCurrentIndex(self.upgrade_collection_combo.findData(v)) if checked else None);radio_row.addWidget(control)
        self.upgrade_collection_combo.currentIndexChanged.connect(self._batch2_upgrade_mode);fields.addRow("采集方式",radio_body)
        for title,control in (("vCenter 地址",self.upgrade_vcenter_input),("用户名",self.upgrade_username_input),("密码",self.upgrade_password_input),("支持包",self.upgrade_bundle_input.parentWidget())):fields.addRow(title,control)
        config.layout.addLayout(fields);advanced=QWidget();extras=form();advanced.setLayout(extras)
        for title,control in (("vSAN 检查",self.upgrade_vsan_combo),("客户名称",self.upgrade_customer_input),("输出目录",self.upgrade_report_dir_input.parentWidget())):extras.addRow(title,control)
        config.layout.addWidget(FoldSection("高级连接设置",advanced));config.layout.addWidget(muted_label("检查服务器、存储控制器、网卡、磁盘及 vSAN；资料不足时保留无法确定，不算兼容。"))
        criteria=QWidget();criteria_layout=QVBoxLayout(criteria);criteria_layout.setContentsMargins(0,0,0,0);self.upgrade_hcl_timestamps={}
        for source,badge in (("vcg",self.upgrade_vcg_badge),("vsan_hcl",self.upgrade_vsan_badge)):
            entry=QHBoxLayout();entry.addWidget(badge,1);stamp=muted_label("更新时间未记录",word_wrap=False);self.upgrade_hcl_timestamps[source]=stamp;entry.addWidget(stamp);criteria_layout.addLayout(entry)
        hcl_fields=form()
        for title,control in (("HCL 数据源",self.upgrade_hcl_source_combo),("导入方式",self.upgrade_hcl_mode_combo),("本地文件",self.upgrade_hcl_path_input.parentWidget())):hcl_fields.addRow(title,control)
        criteria_layout.addLayout(hcl_fields)
        for control in (self.upgrade_hcl_status_label,self.upgrade_hcl_import_status,self.upgrade_hcl_import_button):criteria_layout.addWidget(control)
        self.upgrade_criteria_fold=FoldSection("数据来源、目录版本与检查限制",criteria);config.layout.addWidget(self.upgrade_criteria_fold)
        self.upgrade_form=RowForms(fields,extras,hcl_fields);self._upgrade_collection_changed(0);self._upgrade_hcl_import_options_changed();self._batch2_upgrade_mode()
        progress=QWidget();progress_layout=QVBoxLayout(progress);progress_layout.setContentsMargins(0,0,0,0);progress_layout.addWidget(self.upgrade_progress_bar)
        result=SectionCard();result_header=QHBoxLayout();title=QLabel("检查结果");title.setObjectName("sectionTitle");result_header.addWidget(title,1);self.upgrade_stage_label=UpgradeStateBadge("等待检查");result_header.addWidget(self.upgrade_stage_label);result.layout.addLayout(result_header);result.layout.addWidget(self.upgrade_status_label)
        self.upgrade_outcomes=QWidget();outcomes=QVBoxLayout(self.upgrade_outcomes);outcomes.setContentsMargins(0,0,0,0);metrics=QHBoxLayout()
        for card in (self.upgrade_metric_total,self.upgrade_metric_pass,self.upgrade_metric_fail,self.upgrade_metric_unknown):metrics.addWidget(card,1);self._batch2_metric_status(card,"0")
        outcomes.addLayout(metrics);self.upgrade_result_tree=QTreeWidget();self.upgrade_result_tree.setColumnCount(5);self.upgrade_result_tree.setHeaderLabels(["对象类型","检查项","检查结果","详情","建议"]);self.upgrade_result_tree.setProperty("cardTable",True);self.upgrade_result_tree.setUniformRowHeights(True);self.upgrade_result_tree.setItemDelegateForColumn(2,SingleStatusDelegate(self.upgrade_result_tree))
        outcomes.addWidget(self.upgrade_result_tree);self.upgrade_tree_height=ContentHeight(self.upgrade_result_tree);outcomes.addWidget(QLabel("整机型号判定"));outcomes.addWidget(self.upgrade_server_summary);self.upgrade_server_height=ContentHeight(self.upgrade_server_summary);result.layout.addWidget(self.upgrade_outcomes)
        self.upgrade_failure_text=muted_label("");result.layout.addWidget(self.upgrade_failure_text)
        detail=QWidget();detail_layout=QVBoxLayout(detail);detail_layout.setContentsMargins(0,0,0,0);detail_layout.addWidget(self.upgrade_result_summary);detail_layout.addWidget(self.upgrade_device_table)
        self.upgrade_summary_height=ContentHeight(self.upgrade_result_summary);self.upgrade_raw_height=ContentHeight(self.upgrade_device_table)
        result.layout.addWidget(FoldSection("详细运行记录与原始判定",detail));self.upgrade_result_summary.textChanged.connect(self._upgrade_task_failure_text)
        self.upgrade_workspace=TaskWorkspace(config,progress,result);self.upgrade_workspace.phaseChanged.connect(self._upgrade_task_phase_changed);layout.addWidget(self.upgrade_workspace,1)
        footer=QHBoxLayout();footer.addWidget(QLabel("报告名称"));footer.addWidget(self.upgrade_report_title_input,1);footer.addWidget(button("数据来源/限制",self._show_upgrade_task_sources));footer.addWidget(self.upgrade_open_html_button)
        self.upgrade_start_button.setText("开始兼容性检查");self.upgrade_start_button.setProperty("keepInPanel",True);footer.addWidget(self.upgrade_start_button);footer.addWidget(self.upgrade_cancel_button);layout.addLayout(footer)
        self._adopt_widget_tree(page);self._upgrade_task_phase_changed("idle");return page

    def _show_upgrade_task_sources(self):
        self.upgrade_workspace.config_toggle.setChecked(True)
        if self.upgrade_criteria_fold.body.isHidden():self.upgrade_criteria_fold.toggle.click()
        from PySide6.QtCore import QTimer
        QTimer.singleShot(0,lambda:self.upgrade_workspace.scroll.ensureWidgetVisible(self.upgrade_criteria_fold))

    def _upgrade_task_phase_changed(self,phase):
        self.upgrade_outcomes.setVisible(phase=="completed" or phase=="cancelled" and self.upgrade_result_tree.topLevelItemCount()>0)
        self.upgrade_open_html_button.setVisible(phase=="completed")
        self.upgrade_failure_text.setVisible(phase in {"failed","cancelled"});self._upgrade_task_failure_text()

    def _upgrade_task_failure_text(self):
        if hasattr(self,"upgrade_failure_text"):
            partial=getattr(getattr(self,"upgrade_workspace",None),"phase","")=="cancelled" and self.upgrade_result_tree.topLevelItemCount()>0
            prefix="已取消：仅展示本次已取得的部分结果，未检查项目不视为通过；未生成报告。\n" if partial else ""
            self.upgrade_failure_text.setText(prefix+self.upgrade_result_summary.toPlainText())

    def _batch2_upgrade_mode(self,*args):
        for control,value in ((self.upgrade_vcenter_radio,"vcenter"),(self.upgrade_bundle_radio,"support_bundle")):
            control.blockSignals(True);control.setChecked(self.upgrade_collection_combo.currentData()==value);control.blockSignals(False)

    def _batch2_upgrade_results(self,result):
        from vstacklens.upgrade_compat.decision import effective_match,BLOCKING,PASSING
        self.upgrade_result_tree.clear();groups={}
        for item in result.device_results:
            category=ui_text(str(item.get("category") or "其他对象"))
            if category not in groups:groups[category]=QTreeWidgetItem(self.upgrade_result_tree,[category]);groups[category].setExpanded(True)
            match=effective_match(item);state=str(match.get("status") or "")
            passed=state in PASSING;failed=state in BLOCKING
            label="通过" if passed else "不通过" if failed else "无法确定"
            details=str(match.get("detail") or "—")
            from vstacklens.reports.upgrade_compat_report import remediation_for
            recommendation=remediation_for(state)
            row=QTreeWidgetItem(groups[category],[category,str(item.get("object_name") or "—"),label,details,recommendation])
            self.upgrade_result_tree.setItemWidget(row,2,status_badge("success" if passed else "failed" if failed else "warning",label))
        self.upgrade_result_tree.header().setStretchLastSection(True)
        for column in range(4):self.upgrade_result_tree.resizeColumnToContents(column)
        if result.server_results:
            group=QTreeWidgetItem(self.upgrade_result_tree,["服务器"]);group.setExpanded(True)
            for server in result.server_results:
                state=str(server.get("status") or "无法确定");label="通过" if state=="SERVER_CERTIFIED" else "不通过" if state=="SERVER_NOT_CERTIFIED" else "无法确定"
                detail=str(server.get("detail") or "—");row=QTreeWidgetItem(group,["服务器",str(server.get("model") or "—"),label,detail,detail]);self.upgrade_result_tree.setItemWidget(row,2,status_badge("success" if label=="通过" else "failed" if label=="不通过" else "warning",label))

    def _batch2_metric_status(self,card,value):
        zero=str(value).strip() in {"0","0.0"}
        for badge in card.findChildren(StatusBadge):
            badge.setProperty("zero",zero);badge.style().unpolish(badge);badge.style().polish(badge);badge.update()

    def _batch2_clickable_header(self,card,toggle,detail,title):
        header_row=card.layout.takeAt(0).layout();description=card.layout.takeAt(0).widget()
        header=CollapsibleCardHeader(toggle,detail);header.setAccessibleName(title);box=QVBoxLayout(header);box.setContentsMargins(0,0,0,0);box.setSpacing(SIZES["section_gap"])
        header_row.removeWidget(toggle);toggle.hide();header_row.addWidget(header.arrow)
        box.addLayout(header_row);box.addWidget(description)
        for label in header.findChildren(QLabel):label.setAttribute(Qt.WA_TransparentForMouseEvents)
        card.layout.insertWidget(0,header)
        return header

    def _batch2_settings_page(self):
        legacy=self._legacy_settings_page();self._retain_batch2(legacy)
        page,layout=page_layout("系统设置");layout.itemAt(0).widget().set_subtitle("管理本地界面、数据、模型及账号安全设置。")
        interface=SectionCard();icon_heading(interface,"界面与报告","report_center","调整界面主题，管理报告保存位置。")
        fields=form();fields.addRow("界面主题",self.ui_theme_combo);output=self.default_report_dir_input.parentWidget()
        output.layout().addWidget(button("打开目录",lambda:self._open_path_safe(Path(self.default_report_dir_input.path_value()))));fields.addRow("报告输出目录",output);interface.layout.addLayout(fields);layout.addWidget(interface)
        local=self.rulepack_status_label.parentWidget();icon_heading(local,"本地数据","asset_center","管理数据库、规则包和本地校验结果。")
        db=self.db_path_input.parentWidget();db.layout().addWidget(button("查看位置",lambda:self._open_path_safe(Path(self.db_path_input.path_value()).parent)))
        database=form();database.addRow("数据库路径",db);local.layout.insertLayout(2,database);layout.addWidget(local)
        model=self.model_settings_summary_label.parentWidget();model_header=icon_heading(model,"模型配置","settings","管理现有模型档案与连接状态。")
        model.layout.setSpacing(SIZES["section_gap"]);model.setMinimumHeight(SIZES["batch2_fold_height"])
        self.model_settings_toggle_button.setObjectName("quietButton");model_header.addWidget(self.model_settings_toggle_button)
        model_detail=self.settings_profile_name_input.parentWidget();model_detail.layout().insertWidget(0,self.model_settings_summary_label)
        layout.addWidget(model)
        security=self.security_summary_label.parentWidget();security_header=icon_heading(security,"账号安全","settings","管理本地密码及密码策略。")
        security.layout.setSpacing(SIZES["section_gap"]);security.setMinimumHeight(SIZES["batch2_fold_height"])
        self.security_toggle_button.setObjectName("quietButton");security_header.addWidget(self.security_toggle_button)
        # Remove only the privacy row from the security form; its control is moved below.
        for old_form in security.findChildren(QFormLayout):
            row=old_form.getWidgetPosition(self.privacy_level_combo)[0]
            if row>=0:
                taken=old_form.takeRow(row)
                if taken.labelItem and taken.labelItem.widget():taken.labelItem.widget().hide()
        layout.addWidget(security)
        privacy,privacy_summary,self.privacy_settings_toggle_button,privacy_detail=self._expandable_section("隐私与脱敏","")
        privacy_header=icon_heading(privacy,"隐私与脱敏","settings","查看连接密码与日志脱敏说明。")
        privacy.layout.setSpacing(SIZES["section_gap"]);privacy.setMinimumHeight(SIZES["batch2_fold_height"])
        privacy_summary.hide();self.privacy_settings_toggle_button.setObjectName("quietButton");privacy_header.addWidget(self.privacy_settings_toggle_button)
        privacy_fields=form();privacy_fields.addRow("脱敏级别",self.privacy_level_combo);privacy_detail.layout().addLayout(privacy_fields);privacy_detail.layout().addWidget(self.security_summary_label);privacy_detail.layout().addWidget(muted_label(PRIVACY_TEXT));layout.addWidget(privacy)
        self.privacy_level_combo.currentIndexChanged.connect(self._batch2_log_privacy)
        layout.addWidget(self._close_preference_card())
        for control in security.findChildren(QPushButton):
            if control.objectName()=="primaryButton":control.setObjectName("")
        save=next(control for control in legacy.findChildren(QPushButton) if control.text()=="保存配置")
        save.setProperty("keepInPanel",True);footer=QHBoxLayout();footer.addStretch(1);footer.addWidget(save);layout.addLayout(footer)
        self.settings_fold_headers=[self._batch2_clickable_header(model,self.model_settings_toggle_button,model_detail,"模型配置"),self._batch2_clickable_header(security,self.security_toggle_button,self.current_password_input.parentWidget(),"账号安全"),self._batch2_clickable_header(privacy,self.privacy_settings_toggle_button,privacy_detail,"隐私与脱敏")]
        self._adopt_widget_tree(interface);self._adopt_widget_tree(local);self._adopt_widget_tree(model);self._adopt_widget_tree(security);self._adopt_widget_tree(privacy)
        return self._batch2_fixed_footer_page(page,footer)

    def _batch2_about_page(self):
        legacy=self._legacy_license_page();self._retain_batch2(legacy)
        page,layout=page_layout("关于软件");layout.itemAt(0).widget().set_subtitle("VStackLens 的功能与本地数据位置。")
        grid=QGridLayout();layout.addLayout(grid)
        product=SectionCard();line=QHBoxLayout();logo=ProductLogo();logo.setFixedSize(SIZES["batch2_logo_size"],SIZES["batch2_logo_size"]);line.addWidget(logo)
        words=QVBoxLayout();title=QLabel("VStackLens");title.setObjectName("pageTitle");words.addWidget(title);words.addWidget(QLabel("虚拟化巡检工作台"));words.addWidget(status_badge("success","本地运行"));line.addLayout(words);product.layout.addLayout(line)
        product.layout.addWidget(QLabel("版本 "+APP_VERSION));product.layout.addWidget(muted_label("面向工程师的 VMware 环境检查与报告工具"));grid.addWidget(product,0,0)
        features=SectionCard("主要功能");self.about_feature_names=[]
        for module,name,text in (("inspection_center","标准巡检","基础配置、资产及运行状态检查。"),("log_analysis","日志分析","分析已有日志证据，辅助定位问题。"),("upgrade_compat","升级兼容性","按目标版本核对整机及设备兼容性。")):
            card=SectionCard();icon_heading(card,name,module,text);features.layout.addWidget(card);self.about_feature_names.append(name)
        grid.addWidget(features,0,1)
        data=SectionCard("本地资料");locations=QGridLayout();locations.setColumnStretch(0,1)
        for row,(name,path) in enumerate((("报告位置",lambda:Path(self.default_report_dir_input.path_value())),("数据位置",lambda:Path(self.db_path_input.path_value()).parent))):
            locations.addWidget(QLabel(name),row,0);locations.addWidget(button("查看位置",lambda checked=False,p=path:self._open_path_safe(p())),row,1)
        old_actions={control.text():control for control in legacy.findChildren(QPushButton)}
        open_logs=old_actions["打开日志目录"];open_logs.setText("查看位置");open_logs.setObjectName("outlineButton");open_logs.setToolTip("打开运行日志所在目录")
        copy_logs=old_actions["复制日志路径"];copy_logs.setObjectName("outlineButton")
        locations.addWidget(QLabel("运行日志"),2,0);locations.addWidget(open_logs,2,1);locations.addWidget(copy_logs,2,2);data.layout.addLayout(locations)
        grid.addWidget(data,1,0)
        privacy=SectionCard("隐私提示");privacy.layout.addWidget(muted_label(PRIVACY_TEXT));grid.addWidget(privacy,1,1)
        info=legacy.widget().findChildren(SectionCard)[0]
        for label in info.findChildren(QLabel):
            if label.text()==str(runtime_log_path()):label.setWordWrap(True)
        layout.addWidget(FoldSection("软件信息",info))
        # Show only a real, explicitly named user manual, never a placeholder action.
        manuals=[p for p in Path(__file__).resolve().parents[3].glob('**/*使用说明*') if p.is_file() and p.suffix.lower() in {'.pdf','.html','.md','.txt'}]
        if manuals:
            help_card=SectionCard("使用说明");help_card.layout.addWidget(button("打开使用说明",lambda:self._open_path_safe(manuals[0])));layout.addWidget(help_card)
        flow=SectionCard("工作路径");flow.layout.addWidget(QLabel("标准巡检  →  查看结果（风险中心／资产中心）  →  报告交付"));layout.addWidget(flow)
        self._adopt_widget_tree(page);return self._scroll_page(page)
