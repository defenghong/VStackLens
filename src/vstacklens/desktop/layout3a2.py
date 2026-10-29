"""First batch desktop pages. Existing report/history service semantics are retained."""
from pathlib import Path
import json
import hashlib
from PySide6.QtCore import Qt,QEvent
from PySide6.QtGui import QAction,QKeySequence
from PySide6.QtWidgets import (QApplication,QWidget,QLabel,QVBoxLayout,QHBoxLayout,QFormLayout,QLineEdit,QTextEdit,QTableWidget,QTableWidgetItem,QHeaderView,QSplitter,QTabWidget,QDialog,QPushButton,QFrame,QGridLayout,QSizePolicy,QLayout)
from vstacklens.desktop.widgets import ElidingLabel,PageHeader,SectionCard,NoWheelComboBox,MetricValueLabel,RowSeparatorDelegate,muted_label,status_badge
from vstacklens.desktop.layout3a import button,page_layout,table,fill_table,FoldSection,badge_cell
from vstacklens.desktop.presentation import ui_text,local_time,object_name,history_change,power_state,metadata_text
from vstacklens.desktop.theme import COLORS,SIZES
from vstacklens.desktop.data3a2 import inventory,asset_fields,related_assets,display,run_target,nic_link_state
from vstacklens.desktop.navigation_icons import navigation_icon

def populate_table(widget,rows):
    widget.setRowCount(0)
    widget.setRowCount(len(rows))
    for row,values in enumerate(rows):
        for column,value in enumerate(values):
            item=QTableWidgetItem(ui_text(value));item.setTextAlignment(Qt.AlignLeft|Qt.AlignVCenter);widget.setItem(row,column,item)
        widget.setRowHeight(row,SIZES["asset_row"])

def hide_empty_columns(widget, rows):
    for column in range(widget.columnCount()):
        widget.setColumnHidden(column, not any(column<len(row) and row[column] not in (None,"","—") for row in rows))

def key_values(window,rows,*,wrap_values=False):
    widget=QWidget();layout=QGridLayout(widget);layout.setContentsMargins(0,0,0,0);layout.setHorizontalSpacing(12);layout.setVerticalSpacing(8)
    for row,(key,value) in enumerate(rows):
        label=muted_label(str(key));content=QLabel(metadata_text(value));content.setWordWrap(True)
        if wrap_values: content.setSizePolicy(QSizePolicy.Ignored,QSizePolicy.Preferred)
        content.setTextInteractionFlags(Qt.TextSelectableByMouse|Qt.TextSelectableByKeyboard)
        content.setToolTip(metadata_text(value));layout.addWidget(label,row,0,Qt.AlignTop);layout.addWidget(content,row,1)
    layout.setColumnStretch(1,1);return widget

def clear_children(layout,keep=()):
    while layout.count():
        item=layout.takeAt(0)
        if item.layout():clear_children(item.layout(),keep);item.layout().deleteLater()
        elif item.widget():
            widget=item.widget();widget.hide()
            if widget not in keep:widget.setParent(None);widget.deleteLater()

class Layout3a2Mixin:
    def _asset_center_page(self):
        page,layout=page_layout("资产中心")
        self.asset_scope_summary=ElidingLabel("");self.asset_scope_summary.setObjectName("mutedText");layout.addWidget(self.asset_scope_summary)
        self.asset_type_filter=NoWheelComboBox();self.asset_type_filter.addItems(["全部对象","vCenter","Cluster","ESXi","Datastore","VM"]);self.asset_type_filter.hide()
        self.asset_type_filter.setCurrentText("ESXi");self.asset_type_filter.currentIndexChanged.connect(self._populate_asset_table)
        self.asset_category_bar=QHBoxLayout();self.asset_category_buttons={}
        names={"Cluster":"集群","ESXi":"ESXi 主机","VM":"虚拟机","Datastore":"存储","全部对象":"全部对象","vCenter":"vCenter"}
        for key,title in names.items():
            control=button(title,lambda checked=False,k=key:self._select_asset_category(k));control.setProperty("assetTab",True);control.setFixedHeight(SIZES["page_tabs_height"]);self.asset_category_buttons[key]=control
            if key in {"全部对象","vCenter"}:continue
            self.asset_category_bar.addWidget(control)
        self.asset_category_bar.addStretch(1);layout.addLayout(self.asset_category_bar)
        filters=QHBoxLayout();filters.addWidget(QLabel("集群："));self.asset_cluster_filter=NoWheelComboBox();self.asset_cluster_filter.addItem("全部集群","");self.asset_cluster_filter.currentIndexChanged.connect(self._populate_asset_table);filters.addWidget(self.asset_cluster_filter)
        self.asset_search_input=QLineEdit();self.asset_search_input.setPlaceholderText("搜索对象名称、位置或状态");self.asset_search_input.addAction(navigation_icon("log_analysis"),QLineEdit.LeadingPosition);self.asset_search_input.textChanged.connect(self._populate_asset_table);filters.addWidget(self.asset_search_input,1)
        self.asset_detail_open_button=button("查看详情",self._asset_open_detail);filters.addWidget(self.asset_detail_open_button);layout.addLayout(filters)
        more=QWidget();extra=QHBoxLayout(more);extra.setContentsMargins(0,0,0,0)
        extra.addWidget(self.asset_category_buttons["全部对象"]);extra.addWidget(self.asset_category_buttons["vCenter"])
        self.asset_sort_filter=NoWheelComboBox();self.asset_sort_filter.addItems(["按名称","按对象类型","按位置"]);self.asset_sort_filter.currentIndexChanged.connect(self._populate_asset_table);extra.addWidget(self.asset_sort_filter)
        self.asset_more_options=FoldSection("更多对象与排序",more);layout.addWidget(self.asset_more_options)
        self.asset_empty=muted_label("尚无有效巡检资产");self.asset_empty.setAlignment(Qt.AlignLeft|Qt.AlignTop);self.asset_empty.setSizePolicy(QSizePolicy.Preferred,QSizePolicy.Expanding);layout.addWidget(self.asset_empty,1)
        self.asset_table=table(self,["主机名称","所属集群","连接状态","ESXi 版本","虚拟机数量"]);self.asset_table.currentCellChanged.connect(self._asset_selection_changed)
        self.asset_table.setWordWrap(False);self.asset_table.setTextElideMode(Qt.ElideRight)
        class AssetStateDelegate(RowSeparatorDelegate):
            def initStyleOption(delegate,option,index):
                super().initStyleOption(option,index)
                if self.asset_table.cellWidget(index.row(),index.column()) is not None:option.text=""
        self.asset_table.setItemDelegateForColumn(2,AssetStateDelegate(self.asset_table))
        self.asset_table.itemDoubleClicked.connect(lambda *_:self._asset_open_detail())
        self.asset_copy_action=QAction("复制选中内容",self.asset_table);self.asset_copy_action.setShortcut(QKeySequence.Copy);self.asset_copy_action.setShortcutContext(Qt.WidgetWithChildrenShortcut)
        self.asset_copy_action.triggered.connect(self._asset_copy_selected);self.asset_table.addAction(self.asset_copy_action);self.asset_table.setContextMenuPolicy(Qt.ActionsContextMenu)
        self.asset_detail=QTextEdit();self.asset_detail.setReadOnly(True)
        self.asset_detail_panel=SectionCard();self.asset_detail_title=QLabel("主机详情");self.asset_detail_title.setObjectName("sectionTitle")
        self.asset_related_button=button("查看相关问题",self._asset_related_risks);heading=QHBoxLayout();heading.addWidget(self.asset_detail_title,1);heading.addWidget(self.asset_related_button);heading.addWidget(button("关闭详情",lambda:self.asset_detail_dialog.close()));self.asset_detail_panel.layout.addLayout(heading)
        self.asset_detail_name=QLabel();self.asset_detail_name.setObjectName("detailHeading");self.asset_detail_name.setWordWrap(True);self.asset_detail_name.setTextInteractionFlags(Qt.TextSelectableByMouse|Qt.TextSelectableByKeyboard);self.asset_detail_panel.layout.addWidget(self.asset_detail_name)
        self.asset_kv_holder=QVBoxLayout();self.asset_detail_panel.layout.addLayout(self.asset_kv_holder)
        self.asset_network_title=QLabel("网络适配器");self.asset_network_title.setObjectName("detailHeading");self.asset_detail_panel.layout.addWidget(self.asset_network_title)
        self.asset_network_table=table(self,["名称","连接状态"]);self.asset_detail_panel.layout.addWidget(self.asset_network_table)
        self.asset_network_empty=muted_label("本次巡检没有记录该主机的网卡信息");self.asset_detail_panel.layout.addWidget(self.asset_network_empty)
        self.asset_children_title=QLabel();self.asset_children_title.setObjectName("detailHeading");self.asset_detail_panel.layout.addWidget(self.asset_children_title)
        self.asset_children_table=table(self,["对象名称","运行状态"]);self.asset_detail_panel.layout.addWidget(self.asset_children_table)
        self.asset_children_empty=muted_label("");self.asset_detail_panel.layout.addWidget(self.asset_children_empty)
        self.asset_children_more=button("",self._asset_expand_children,quiet=True);self.asset_detail_panel.layout.addWidget(self.asset_children_more)
        self.asset_engineer_fold=FoldSection("完整资产记录",self.asset_detail);self.asset_detail_panel.layout.addWidget(self.asset_engineer_fold)
        class AssetDetailDialog(QDialog):
            def eventFilter(dialog,watched,event):
                if event.type()==QEvent.Hide:dialog.hide()
                return super().eventFilter(watched,event)
        self.asset_detail_dialog=AssetDetailDialog(self);self.installEventFilter(self.asset_detail_dialog);page.installEventFilter(self.asset_detail_dialog);self.asset_detail_dialog.setWindowTitle("资产详情");self.asset_detail_dialog.setWindowModality(Qt.NonModal);detail_layout=QVBoxLayout(self.asset_detail_dialog);detail_layout.setContentsMargins(0,0,0,0);detail_layout.addWidget(self._scroll_page(self.asset_detail_panel));self.asset_detail_dialog.resize(660,640)
        self.asset_splitter=QSplitter(Qt.Horizontal);self.asset_splitter.addWidget(self.asset_table);layout.addWidget(self.asset_splitter,1)
        self.asset_detail_open_button.setEnabled(False)
        return page

    def _asset_record(self,item):
        candidates=getattr(self,"_asset_props",{}).get((item.object_type,item.object_name),[])
        if len(candidates)==1:return candidates[0]
        def location_key(value):return "/".join(part.strip() for part in str(value or "").replace("\\","/").split("/") if part.strip())
        location=location_key(item.location);matches=[]
        for record in candidates:
            path=location_key(record.get("path"));recorded=location_key(record.get("properties",{}).get("asset_location"))
            parent=path.rsplit("/",1)[0] if "/" in path and path.rsplit("/",1)[-1]==item.object_name else ""
            if location and location in {recorded,path,parent}:matches.append(record)
        return matches[0] if len(matches)==1 else {}

    def _asset_row_identity(self,item):
        record=self._asset_record(item)
        return (item.run_id,item.object_type,record["object_key"]) if record.get("object_key") else (item.run_id,item.object_type,item.object_name,item.location)

    def _asset_copy_selected(self):
        indexes=self.asset_table.selectedIndexes()
        rows=sorted({index.row() for index in indexes});columns=sorted({index.column() for index in indexes if not self.asset_table.isColumnHidden(index.column())})
        if rows and columns:QApplication.clipboard().setText("\n".join("\t".join(self.asset_table.item(row,column).text() if self.asset_table.item(row,column) else "" for column in columns) for row in rows))

    def _asset_open_detail(self):
        row=self.asset_table.currentRow()
        if not 0<=row<len(getattr(self,"_asset_display_rows",[])):return
        self._show_asset_detail(self._asset_display_rows[row])
        self.asset_detail_dialog.resize(min(660,max(360,self.width()-32)),min(640,max(320,self.height()-48)))
        self.asset_detail_dialog.show();self.asset_detail_dialog.raise_();self.asset_detail_dialog.activateWindow()

    def _populate_asset_table(self):
        if not hasattr(self,"asset_table"):return
        old_rows=getattr(self,"_asset_display_rows",[]);old_row=self.asset_table.currentRow()
        selected_identity=self._asset_row_identity(old_rows[old_row]) if 0<=old_row<len(old_rows) else None
        scroll_position=(self.asset_table.verticalScrollBar().value(),self.asset_table.horizontalScrollBar().value())
        data=self._view_data();run_id=data.run_id if data else ""
        self._asset_records=inventory(self._db_path(),run_id)
        self._asset_props={}
        for record in self._asset_records:self._asset_props.setdefault((record["object_type"],record["object_name"]),[]).append(record)
        counts={key:sum(x.object_type_label==key for x in self._asset_items) for key in self.asset_category_buttons}
        counts["全部对象"]=len(self._asset_items)
        names={"Cluster":"集群","ESXi":"ESXi 主机","VM":"虚拟机","Datastore":"存储","全部对象":"全部对象","vCenter":"vCenter"}
        selected=self.asset_type_filter.currentText()
        for key,control in self.asset_category_buttons.items():
            control.setText(f"{names[key]} {counts.get(key,0)}");control.setProperty("active",key==selected);control.style().unpolish(control);control.style().polish(control)
        if data:
            summary=f"巡检任务：{self._short_task(run_id)}　执行时间：{local_time(data.finished_at)}　{counts['Cluster']} 个集群 · {counts['ESXi']} 台 ESXi 主机 · {counts['VM']} 台虚拟机 · {counts['Datastore']} 个存储"
            self.asset_scope_summary.setText(summary);self.asset_scope_summary.setToolTip(summary+f"\n完整任务编号：{run_id}")
        else:self.asset_scope_summary.clear();self.asset_scope_summary.setToolTip("")
        cluster=self.asset_cluster_filter.currentData();self.asset_cluster_filter.blockSignals(True);self.asset_cluster_filter.clear();self.asset_cluster_filter.addItem("全部集群","")
        clusters=sorted({str(r["properties"].get("cluster_name")) for r in self._asset_records if r["properties"].get("cluster_name")})
        for name in clusters:self.asset_cluster_filter.addItem(name,name)
        self.asset_cluster_filter.setCurrentIndex(max(0,self.asset_cluster_filter.findData(cluster)));self.asset_cluster_filter.blockSignals(False)
        keyword=self.asset_search_input.text().strip().lower();rows=[]
        for item in self._asset_items:
            props=self._asset_record(item).get("properties",{})
            if selected!="全部对象" and item.object_type_label!=selected:continue
            if cluster and props.get("cluster_name")!=cluster:continue
            searchable=f"{item.object_name} {item.location} {item.detail} {display(props.get('connection_state'))} {power_state(props.get('power_state'))}"
            if keyword and keyword not in searchable.lower():continue
            rows.append(item)
        sorting=self.asset_sort_filter.currentText();rows.sort(key=lambda x:(x.location,x.object_name) if sorting=="按位置" else (x.object_type_label,x.object_name) if sorting=="按对象类型" else x.object_name)
        self._asset_display_rows=rows;self.asset_empty.setVisible(not rows);self.asset_empty.setText("没有匹配当前筛选条件的资产" if self._asset_items else "尚无有效巡检资产");self.asset_splitter.setVisible(bool(rows));self.asset_detail_open_button.setEnabled(bool(rows))
        headers={"ESXi":["主机名称","所属集群","连接状态","ESXi 版本","虚拟机数量"],"VM":["虚拟机","所属主机","电源状态","CPU","内存"],"Cluster":["集群","归属范围","HA","DRS","主机数量"],"Datastore":["数据存储","归属范围","类型","容量使用率","已有属性"],"vCenter":["vCenter","位置","版本","采集任务","已有属性"],"全部对象":["对象类型","对象名称","位置","采集任务","已有属性"]}[selected]
        self.asset_table.setHorizontalHeaderLabels(headers);values=[]
        for item in rows:
            record=self._asset_record(item);p=record.get("properties",{})
            if selected=="ESXi":row=[item.object_name,display(p.get("cluster_name")),display(p.get("connection_state")),display(p.get("host_version",p.get("version"))),display(p.get("vm_count"))]
            elif selected=="VM":row=[item.object_name,display(p.get("host_name")),power_state(p.get("power_state")),display(p.get("vcpu_count")," 核"),display(p.get("memory_mb",p.get("vm_memory_configured_mb"))," MB")]
            elif selected=="Cluster":row=[item.object_name,item.location,display(p.get("ha_enabled")),display(p.get("drs_enabled")),display(p.get("host_count"))]
            elif selected=="Datastore":row=[item.object_name,item.location,display(p.get("datastore_filesystem_type")),display(p.get("used_percent"),"%"),item.detail]
            elif selected=="vCenter":row=[item.object_name,item.location,display(p.get("version")),self._short_task(item.run_id),item.detail]
            else:row=[object_name(item.object_type),item.object_name,item.location,self._short_task(item.run_id),item.detail]
            values.append(row)
        blocked=self.asset_table.blockSignals(True)
        try:
            populate_table(self.asset_table,values);hide_empty_columns(self.asset_table,values)
            for i,item in enumerate(rows):
                for column in range(self.asset_table.columnCount()):
                    cell=self.asset_table.item(i,column)
                    if cell:cell.setToolTip(cell.text());cell.setData(Qt.UserRole,self._asset_row_identity(item))
                if selected not in {"ESXi","VM"}:continue
                props=self._asset_record(item).get("properties",{})
                state=props.get("connection_state" if selected=="ESXi" else "power_state")
                label=display(state) if selected=="ESXi" else power_state(state)
                status=("success" if state=="connected" else "failed" if state in {"disconnected","notResponding"} else "unknown") if selected=="ESXi" else ("success" if label=="运行中" else "unknown" if label=="关机" else "info")
                marker=status_badge(status,label);marker.setAttribute(Qt.WA_TransparentForMouseEvents);marker.setToolTip(label);self.asset_table.setCellWidget(i,2,marker)
            if rows:
                row=next((i for i,item in enumerate(rows) if self._asset_row_identity(item)==selected_identity),0);self.asset_table.setCurrentCell(row,0)
        finally:self.asset_table.blockSignals(blocked)
        if rows:self._show_asset_detail(rows[self.asset_table.currentRow()])
        else:self._selected_asset=None;self.asset_detail_dialog.hide()
        self.asset_table.verticalScrollBar().setValue(scroll_position[0]);self.asset_table.horizontalScrollBar().setValue(scroll_position[1])

    def _show_asset_detail(self,item):
        self._selected_asset=item;self._asset_children_expanded=False
        record=self._asset_record(item) or {"object_type":item.object_type,"object_name":item.object_name,"properties":{}};p=record["properties"]
        self.asset_detail_title.setText({"HostSystem":"主机详情","VirtualMachine":"虚拟机详情","Datastore":"存储详情","ClusterComputeResource":"集群详情"}.get(item.object_type,"对象详情"));self.asset_detail_name.setText(item.object_name)
        self._clear_layout(self.asset_kv_holder);self.asset_key_fields=asset_fields(item,p);self.asset_kv_holder.addWidget(key_values(self,self.asset_key_fields[:-4] or self.asset_key_fields))
        nics=p.get("physical_nic_details",[]);nics=nics if isinstance(nics,list) else []
        nic_rows=[(display(n.get("device",n.get("name"))),nic_link_state(n)) for n in nics]
        fill_table(self.asset_network_table,nic_rows);hide_empty_columns(self.asset_network_table,nic_rows);host=item.object_type=="HostSystem"
        self.asset_network_title.setVisible(host and bool(nics));self.asset_network_table.setVisible(host and bool(nics));self.asset_network_empty.setVisible(host and not nics)
        self._asset_children=related_assets(record,self._asset_records);self._asset_fill_children()
        self.asset_detail.setPlainText(ui_text(f"对象类型：{item.object_type_label}\n对象名称：{item.object_name}\n完整位置：{item.location}\n属性：{item.detail}\n数据来源：巡检记录 {item.run_id}\n"+json.dumps(p,ensure_ascii=False,indent=2)))

    def _asset_fill_children(self):
        children=self._asset_children;host=getattr(self,"_selected_asset",None) and self._selected_asset.object_type=="HostSystem"
        self.asset_children_title.setText(f"虚拟机清单（已记录 {len(children)} 台）" if host and children else "虚拟机清单（未记录关联）" if host else f"相关资产清单（已记录 {len(children)} 项）" if children else "相关资产清单（未记录关联）")
        shown=children if self._asset_children_expanded else children[:2]
        child_rows=[(r["object_name"],power_state(r["properties"].get("power_state")) if r["object_type"]=="VirtualMachine" else display(r["properties"].get("connection_state"))) for r in shown]
        fill_table(self.asset_children_table,child_rows);hide_empty_columns(self.asset_children_table,[(r["object_name"],power_state(r["properties"].get("power_state")) if r["object_type"]=="VirtualMachine" else display(r["properties"].get("connection_state"))) for r in children])
        self.asset_children_table.setVisible(bool(children));self.asset_children_empty.setVisible(not children)
        self.asset_children_title.setVisible(bool(children))
        self.asset_children_empty.setText("本次巡检没有记录该主机的虚拟机关联信息" if host else "本次巡检没有记录该对象的相关资产信息")
        self.asset_children_more.setVisible(len(children)>2);self.asset_children_more.setText("收起" if self._asset_children_expanded else f"查看更多（{len(children)-2}）")
    def _asset_expand_children(self):self._asset_children_expanded=not self._asset_children_expanded;self._asset_fill_children()
    def _asset_related_risks(self):
        item=getattr(self,"_selected_asset",None)
        if not item:return
        self.asset_detail_dialog.hide();self.go_to_module("risk_center");self.risk_keyword_input.setText(item.object_name);index=self.risk_type_filter.findData(item.object_type)
        if index>=0:self.risk_type_filter.setCurrentIndex(index)
        self._risk_exact_asset=(item.object_type,item.object_name);self._populate_risk_table()

    def _history_compare_page(self):
        page,layout=page_layout("历史对比")
        selector=SectionCard();row=QHBoxLayout()
        self.baseline_run_combo=NoWheelComboBox();self.comparison_run_combo=NoWheelComboBox()
        for label,combo in (("基准巡检",self.baseline_run_combo),("对比巡检",self.comparison_run_combo)):
            column=QVBoxLayout();column.addWidget(QLabel(label));column.addWidget(combo);row.addLayout(column,1);combo.currentIndexChanged.connect(self._history_combo_changed)
        self.history_compare_button=button("开始对比",self._history_combo_changed,primary=True);self.history_compare_button.setProperty("keepInPanel",True);row.addWidget(self.history_compare_button);selector.layout.addLayout(row)
        self.history_summary_label=muted_label("");selector.layout.addWidget(self.history_summary_label);layout.addWidget(selector)
        self.history_empty=SectionCard("历史对比状态");self.history_empty_text=muted_label("尚无可比结果");self.history_empty.layout.addWidget(self.history_empty_text);layout.addWidget(self.history_empty)
        self.history_content=QWidget();content=QVBoxLayout(self.history_content);content.setContentsMargins(0,0,0,0)
        totals=SectionCard();total_row=QHBoxLayout();self.history_change_counts={}
        for key,title in (("new","项新增问题记录"),("closed","项本次未再发现记录"),("persistent","项持续问题记录")):
            if key!="new":divider=QFrame();divider.setObjectName("conclusionDivider");divider.setFixedSize(1,SIZES["title_strip_height"]*2);total_row.addWidget(divider)
            wrapper=QWidget();wrapper.setObjectName("inlineNumberGroup");wrapper.setSizePolicy(QSizePolicy.Maximum,QSizePolicy.Preferred);group=QHBoxLayout(wrapper);group.setContentsMargins(0,0,0,0);group.setSpacing(SIZES["number_pair_gap"])
            value=QLabel("—");value.setObjectName("largeNumber");value.setSizePolicy(QSizePolicy.Maximum,QSizePolicy.Preferred);group.addWidget(value);text=QLabel(title);text.setWordWrap(True);text.setSizePolicy(QSizePolicy.Maximum,QSizePolicy.Preferred);group.addWidget(text);total_row.addWidget(wrapper);self.history_change_counts[key]=value
        total_row.addWidget(muted_label("ⓘ 仅比较两次有效结果；未采集不代表问题已解决"));totals.layout.addLayout(total_row);content.addWidget(totals)
        self.history_metric_labels={};self.history_metric_subtitles={};legacy=QWidget();legacy_layout=QFormLayout(legacy)
        for key in ("P1","P2","P3","host","vm","datastore"):
            value=QLabel();description=QLabel();self.history_metric_labels[key]=value;self.history_metric_subtitles[key]=description;line=QHBoxLayout();line.addWidget(value);line.addWidget(description);legacy_layout.addRow(object_name(key),line)
        self.history_legacy_fold=FoldSection("分级与资产原始对比",legacy)
        self.history_tabs=QTabWidget();self.history_tabs.setProperty("pageTabs",True)
        for category,title in (("risk","问题变化"),("asset","资产变化")):
            section=SectionCard();getattr(self,"history_tabs").addTab(section,title)
            if category=="risk":
                self.history_risk_filter=NoWheelComboBox();self.history_risk_filter.addItems(["全部","新增","本次未再发现","持续"]);self.history_risk_filter.currentIndexChanged.connect(self._history_risk_filter_changed);section.layout.addWidget(self.history_risk_filter,alignment=Qt.AlignLeft)
            widget=table(self,["变化","等级","问题","涉及对象","说明","操作"] if category=="risk" else ["变化","对象类型","对象名称","位置"])
            setattr(self,f"history_{category}_list",widget);section.layout.addWidget(widget,1)
            label=muted_label("");setattr(self,f"history_{category}_page_label",label);pager=QHBoxLayout();pager.addWidget(label,1)
            for suffix,caption,delta in (("prev","上一页",-1),("next","下一页",1)):
                control=button(caption,lambda checked=False,c=category,d=delta:self._change_history_page(c,d));setattr(self,f"history_{category}_{suffix}",control);pager.addWidget(control)
            section.layout.addLayout(pager)
        content.addWidget(self.history_tabs,1)
        overview=SectionCard();footer=QHBoxLayout();self.history_asset_overview=muted_label("");footer.addWidget(self.history_asset_overview,1)
        self.history_baseline_report=button("查看基准报告",lambda:self._history_open_report("baseline_run_id"));self.history_comparison_report=button("查看对比报告",lambda:self._history_open_report("comparison_run_id"));footer.addWidget(self.history_baseline_report);footer.addWidget(self.history_comparison_report);overview.layout.addLayout(footer);content.addWidget(overview);content.addWidget(self.history_legacy_fold)
        layout.addWidget(self.history_content,1);return self._scroll_page(page)

    def _render_history_comparison(self,comparison):
        self._legacy_render_history_comparison(comparison)
        self.history_compare_button.setEnabled(bool(self.baseline_run_combo.count()>=2))
        for key,label in self.history_change_counts.items():label.setText(str(len(comparison.risk_changes.get(key,[]))) if comparison.state=="ready" else "—")
        parts=[]
        for key,title in (("vm","虚拟机"),("host","主机"),("datastore","存储")):
            delta=comparison.asset_counts.get(key);value=delta.delta if delta else None
            parts.append(f"{title}数量未变" if value==0 else f"{title}数量变化 {value:+g}" if isinstance(value,(int,float)) else f"{title}数量不可比")
        self.history_asset_overview.setText("资产变化概览："+" · ".join(parts))
        for button,key in ((self.history_baseline_report,"baseline_run_id"),(self.history_comparison_report,"comparison_run_id")):
            button.setEnabled(bool(self.service.desktop_report_formats(self._db_path(),getattr(comparison,key,""))))
    def _history_open_report(self,key):
        comparison=self._history_comparison
        if comparison:
            formats=self.service.desktop_report_formats(self._db_path(),getattr(comparison,key));self._open_path_safe(next(iter(formats.values()),None))

    def _render_history_page(self,category):
        groups=list(getattr(self,f"_history_{category}_groups",[]));widget=getattr(self,f"history_{category}_list");label=getattr(self,f"history_{category}_page_label")
        page_count=max(1,(len(groups)+49)//50);page=min(max(0,getattr(self,f"_history_{category}_page",0)),page_count-1);setattr(self,f"_history_{category}_page",page)
        label.setText(f"共 {len(groups)} 项 · 第 {page+1} / {page_count} 页");getattr(self,f"history_{category}_prev").setEnabled(page>0);getattr(self,f"history_{category}_next").setEnabled(page<page_count-1)
        shown=groups[page*50:(page+1)*50];values=[]
        for item in shown:
            if category=="risk":
                unit={"VirtualMachine":"台虚拟机","HostSystem":"台 ESXi 主机","ClusterComputeResource":"个集群","Datastore":"个数据存储"}.get(item.object_type,"个对象")
                reason={"new":"对比巡检中新增的记录","closed":"基准巡检存在，本次未再发现","persistent":"两次巡检均存在的记录"}.get(item.change_status,"")
                values.append([history_change(item.change_status),item.risk_level,item.title,item.object_name,reason,""])
            else:values.append([history_change(item.change_status),object_name(item.object_type),item.object_name,item.location])
        populate_table(widget,values)
        if category=="risk":
            widget.setWordWrap(False);widget.verticalHeader().setMinimumSectionSize(40)
            for row in range(widget.rowCount()):widget.setRowHeight(row,40)
            widget.setMinimumHeight(SIZES["table_header"]+8*40)
            for row,item in enumerate(shown):widget.item(row,3).setToolTip(object_name(item.object_type))
        for row,item in enumerate(shown):
            state="closed" if item.change_status in {"removed","closed"} else item.change_status
            marker=status_badge("change_"+state,history_change(item.change_status));marker.setFixedHeight(SIZES["change_marker_height"]);widget.setCellWidget(row,0,marker)
            if category=="risk":
                widget.setCellWidget(row,1,badge_cell(item.risk_level));widget.setCellWidget(row,5,button("查看",lambda checked=False,x=item:self._history_show_detail(x),quiet=True))
    def _history_show_detail(self,item):
        dialog=QDialog(self);dialog.setWindowTitle("问题变化详情");layout=QVBoxLayout(dialog);text=QTextEdit();text.setReadOnly(True);text.setPlainText(ui_text(f"变化：{history_change(item.change_status)}\n等级：{item.risk_level}\n问题：{item.title}\n对象：{item.object_name}\n当前值：{item.current_observed or '—'}\n建议值：{item.expected_state or '—'}"));layout.addWidget(text);dialog.resize(650,440);dialog.exec()

    def _populate_history_risk_changes(self):
        comparison=self._history_comparison;selected=self.history_risk_filter.currentText();groups=[]
        if comparison and comparison.state=="ready":
            for key in ("new","closed","persistent"):
                if selected in {"全部",history_change(key)}:groups.extend(comparison.risk_changes.get(key,[]))
        self._history_risk_groups=groups;self._render_history_page("risk")
    def _populate_history_asset_changes(self):
        comparison=self._history_comparison;self._history_asset_groups=[]
        if comparison and comparison.state=="ready":
            for key in ("new","removed","persistent"):self._history_asset_groups.extend(comparison.asset_changes.get(key,[]))
        self._render_history_page("asset")

    def _report_center_page(self):
        page,layout=page_layout("报告中心")
        filters=QGridLayout();self.report_filter_grid=filters;self.report_filter_boxes=[];self.report_filters={}
        for key,title,values in (("customer","客户",["全部客户"]),("environment","环境",["全部环境"]),("type","类型",["全部类型"]),("time","时间",["全部时间","最近30天","最近7天"])):
            control=NoWheelComboBox();control.addItems(values);control.currentIndexChanged.connect(self._populate_report_list);control.setSizeAdjustPolicy(NoWheelComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon);control.setMinimumContentsLength(6);control.setMinimumWidth(control.fontMetrics().horizontalAdvance("全部客户")+74);control.currentTextChanged.connect(control.setToolTip);box=QWidget();pair=QHBoxLayout(box);pair.setContentsMargins(0,0,0,0);pair.addWidget(QLabel(title+"："));pair.addWidget(control);box.setMinimumWidth(174);box.setSizePolicy(QSizePolicy.Preferred,QSizePolicy.Preferred);filters.addWidget(box,0,len(self.report_filter_boxes));filters.setColumnStretch(len(self.report_filter_boxes),1);self.report_filter_boxes.append(box);self.report_filters[key]=control
        self.report_search_input=QLineEdit();self.report_search_input.setMinimumWidth(100);self.report_search_input.setPlaceholderText("报告名或任务编号");self.report_search_input.addAction(navigation_icon("log_analysis"),QLineEdit.LeadingPosition);self.report_search_input.textChanged.connect(self._populate_report_list);filters.addWidget(self.report_search_input,0,4);filters.setColumnStretch(4,2);layout.addLayout(filters)
        self.report_center_table=table(self,["时间","类型","任务","可用格式"]);self.report_center_table.hide()
        self.report_list=table(self,["时间","类型","任务","可用格式"]);self.report_list.currentCellChanged.connect(self._report_selection_changed)
        self.report_center_empty=muted_label("尚无实际生成的报告");layout.addWidget(self.report_center_empty);self.report_empty_action=button("前往巡检中心",lambda:self.go_to_module("inspection_center"));layout.addWidget(self.report_empty_action,alignment=Qt.AlignLeft)
        self.report_detail=QTextEdit();self.report_detail.setReadOnly(True)
        panel=SectionCard();self.report_detail_panel=panel;panel.layout.setSizeConstraint(QLayout.SetMinimumSize)
        header=QHBoxLayout();strip=QFrame();strip.setObjectName("titleStrip");strip.setFixedSize(SIZES["title_strip_width"],SIZES["title_strip_height"]);header.addWidget(strip);self.report_title_label=ElidingLabel();self.report_title_label.setWordWrap(False);self.report_title_label.setObjectName("sectionTitle");header.addWidget(self.report_title_label,1);delivery=QWidget();self.report_delivery=delivery;delivery_layout=QVBoxLayout(delivery);delivery_layout.setContentsMargins(0,0,0,0);delivery_layout.addLayout(header);self.report_scope_label=ElidingLabel();self.report_scope_label.setObjectName("pageSubtitle");delivery_layout.addWidget(self.report_scope_label);layout.addWidget(delivery)
        self.report_kv_holder=QVBoxLayout()
        from vstacklens.desktop.widgets import NumberSummary
        self.report_numbers=NumberSummary();self.report_numbers.setStyleSheet("QLabel#largeNumber {font-size:24px;} QLabel#numberCaption {font-size:14px;}")
        self.report_files_layout=QHBoxLayout();delivery_layout.addLayout(self.report_files_layout)
        self.open_selected_report_button=button("打开报告",self._open_selected_history_report)
        self.open_selected_dir_button=button("打开交付目录",self._open_selected_history_dir);self.report_copy_path_button=button("复制路径",self._copy_selected_report_path)
        self.report_word_button=button("打开",self._open_selected_word_report);self.report_pdf_button=button("打开",self._open_selected_pdf_report)
        for control in (self.report_word_button,self.report_pdf_button):control.setParent(panel);control.hide()
        row=QHBoxLayout();row.addWidget(self.open_selected_dir_button);row.addWidget(self.report_copy_path_button);self.report_details_button=button("展开详情",self._toggle_report_details);row.addWidget(self.report_details_button);row.addStretch(1);delivery_layout.addLayout(row)
        panel.layout.addLayout(self.report_kv_holder);panel.layout.addWidget(self.report_numbers)
        diagnostic=QWidget();diagnostic_layout=QVBoxLayout(diagnostic);diagnostic_layout.addWidget(self.report_detail);diagnostic_layout.addWidget(self.open_selected_report_button)
        self.report_engineer_fold=FoldSection("工程师详细记录",diagnostic);panel.layout.addWidget(self.report_engineer_fold)
        footer=QHBoxLayout();self.report_task_button=button("查看任务",self._report_view_task,quiet=True);self.delete_report_button=button("从列表移除",self._remove_selected_report,quiet=True);self.delete_report_button.setToolTip("仅从报告中心隐藏选中项，不删除报告文件、巡检记录或资产快照。")
        footer.addWidget(self.report_task_button);footer.addWidget(self.delete_report_button);panel.layout.addLayout(footer);panel.layout.addWidget(muted_label("仅隐藏条目，不删除文件。",word_wrap=False))
        self.report_splitter=QSplitter(Qt.Horizontal);self.report_splitter.addWidget(self.report_list);self.report_splitter.addWidget(self._scroll_page(panel));self.report_splitter.setSizes([780,380]);self.report_splitter.widget(1).hide();self.report_list.setMinimumWidth(0);layout.addWidget(self.report_splitter,1);return page

    def _populate_reports(self,rows):
        self._report_items=rows[:80]
        for key,values in (("customer",{x.customer_name for x in self._report_items if x.customer_name}),("environment",{x.site_name for x in self._report_items if x.site_name}),("type",{x.report_type for x in self._report_items if x.report_type})):
            control=self.report_filters[key];old=control.currentText();control.blockSignals(True);first=control.itemText(0);control.clear();control.addItem(first)
            for value in sorted(values):control.addItem(value)
            control.setCurrentIndex(max(0,control.findText(old)));control.blockSignals(False);control.setVisible(bool(values))
            self.report_filter_boxes[("customer", "environment", "type").index(key)].setVisible(bool(values))
        self._populate_report_list()

    def _report_task_label(self,item):
        label=self._short_task(item.run_id)
        return label if label not in {"编号待确认","—"} else "任务 · "+hashlib.sha256(str(item.run_id or item.report_dir).encode()).hexdigest()[:8]

    def _report_formats(self,item):
        if self._is_product_report_item(item):return self._available_product_reports(item.run_id)
        if item.run_id and not self._is_log_report_item(item):return self.service.desktop_report_formats(self._db_path(),item.run_id)
        result={}
        for candidate in self._report_items:
            path=candidate.report_path
            if candidate.report_dir!=item.report_dir or not path or not path.is_file():continue
            label={".docx":"Word",".pdf":"PDF",".html":"HTML"}.get(path.suffix.lower())
            if label:result[label]=path
        return result

    def _display_report_kind(self,item):
        if self._is_product_report_item(item):return self._product_run_kind(self._integrated_report_runs[item.run_id])
        return "日志分析" if self._is_log_report_item(item) else "升级兼容性" if self._is_upgrade_report_item(item) else "标准巡检" if item.run_id else item.report_type

    def _populate_report_list(self,*args):
        if not hasattr(self,"report_list"):return
        from datetime import datetime,timedelta,timezone
        rows=[];indexes=[];keyword=self.report_search_input.text().casefold()
        for index,item in enumerate(self._report_items):
            if any(control.currentIndex()>0 and getattr(item,{"customer":"customer_name","environment":"site_name","type":"report_type"}[key])!=control.currentText() for key,control in self.report_filters.items() if key!="time"):continue
            if keyword and keyword not in (item.title+" "+self._report_task_label(item)+" "+item.customer_name).casefold():continue
            days=30 if self.report_filters["time"].currentIndex()==1 else 7 if self.report_filters["time"].currentIndex()==2 else None
            if days:
                try:
                    stamp=datetime.fromisoformat(item.assessment_time.replace("Z","+00:00"));stamp=stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)
                    if stamp<datetime.now(timezone.utc)-timedelta(days=days):continue
                except (ValueError,TypeError):continue
            task=self._report_task_label(item)
            prefix,separator,sequence=task.rpartition("-")
            task_display=task if task!="编号待确认" else "任务 · "+hashlib.sha256(str(item.run_id or item.report_path).encode()).hexdigest()[:8]
            rows.append([local_time(item.assessment_time,compact=True),self._display_report_kind(item),task_display," · ".join(self._report_formats(item)) or "—"]);indexes.append(index)
        self.report_list.blockSignals(True);populate_table(self.report_list,rows)
        for row,index in enumerate(indexes):
            self.report_list.item(row,0).setData(Qt.UserRole,index);self.report_list.item(row,2).setToolTip(self._report_task_label(self._report_items[index])+"\n"+(self._report_items[index].run_id or str(self._report_items[index].report_dir)))
            self.report_list.setRowHeight(row,max(SIZES["table_row"],self.report_list.fontMetrics().height()+14))
        self.report_list.blockSignals(False);self.report_center_empty.setVisible(not rows);self.report_empty_action.setVisible(not rows);self.report_delivery.setVisible(bool(rows));self.report_splitter.setVisible(bool(rows))
        if rows:self.report_list.setCurrentCell(0,0);self.report_list.selectRow(0)
        self._report_selection_changed()

    def _selected_report_item(self):
        row=self.report_list.currentRow()
        cell=self.report_list.item(row,0) if row>=0 else None
        index=cell.data(Qt.UserRole) if cell else None
        return self._report_items[index] if isinstance(index,int) and 0<=index<len(self._report_items) else None

    def _report_selection_changed(self,*args):
        self._engineer_report_selection_changed()
        item=self._selected_report_item()
        if not item:
            self.report_title_label.setText("请选择一条报告");self.report_scope_label.clear();self.report_task_button.setEnabled(False)
            clear_children(self.report_files_layout,(self.report_word_button,self.report_pdf_button))
            for control in (self.report_word_button,self.report_pdf_button,self.open_selected_dir_button,self.report_copy_path_button,self.report_details_button):control.hide()
            return
        for control in (self.open_selected_dir_button,self.report_copy_path_button,self.report_details_button):control.show()
        self.report_title_label.setText(item.title or item.report_type);self._clear_layout(self.report_kv_holder)
        metadata={}
        if item.payload_path and item.payload_path.is_file():
            try:metadata=json.loads(item.payload_path.read_text(encoding="utf-8")).get("metadata",{})
            except (ValueError,OSError):pass
        target=metadata.get("vcenter",metadata.get("vcenter_host",metadata.get("target_release","—")))
        if self._is_product_report_item(item):
            run=self._integrated_report_runs[item.run_id]
            target=" / ".join(f"{self._product_snapshot_name(run, t)} · {t.get('name', t.get('target_name', ''))}" for t in run.get("targets",[])) or "已选择产品目标"
        if target=="—":target=run_target(self._db_path(),item.run_id)
        self.report_scope_label.setText(f"客户：{metadata_text(item.customer_name)} · 环境：{metadata_text(item.site_name)} · 目标：{metadata_text(target)}")
        self.report_key_fields=[("任务编号",self._report_task_label(item)),("客户",metadata_text(item.customer_name)),("环境 / 范围",metadata_text(item.site_name)),("目标",metadata_text(target)),("时间",local_time(item.assessment_time))]
        self.report_kv_holder.addWidget(key_values(self,self.report_key_fields,wrap_values=True))
        caliber=item.customer_caliber;self.report_numbers.setVisible(bool(caliber));self.report_numbers.set_counts(caliber.get("problem_count","—"),caliber.get("affected_total","—"))
        for control in (self.report_word_button,self.report_pdf_button):control.setParent(self.report_detail_panel);control.hide()
        clear_children(self.report_files_layout,(self.report_word_button,self.report_pdf_button))
        formats=self._report_formats(item)
        for kind,path in formats.items():
            wrapper=QWidget();wrapper.setObjectName("inlineNumberGroup");wrapper.setFixedHeight(SIZES["report_file_row"]);line=QHBoxLayout(wrapper);line.setContentsMargins(0,0,0,0);icon=QLabel();icon.setPixmap(navigation_icon("report_center").pixmap(SIZES["navigation_icon"],SIZES["navigation_icon"]));
            control=self.report_word_button if kind=="Word" else self.report_pdf_button if kind=="PDF" else button("打开",lambda checked=False,p=path:self._open_path_safe(p))
            control.setText("打开 "+kind);control.setEnabled(True);control.show();line.addWidget(control);self.report_files_layout.addWidget(wrapper)
        self.report_task_button.setEnabled(bool(item.run_id and self._report_formats(item)))
    def _toggle_report_details(self):
        panel=self.report_splitter.widget(1);panel.setVisible(panel.isHidden())
        self.report_details_button.setText("展开详情" if panel.isHidden() else "收起详情")
        if not panel.isHidden():self.report_splitter.setSizes([max(360,self.report_splitter.width()-360),360])

    def _report_view_task(self):
        item=self._selected_report_item()
        if self._is_product_report_item(item):
            self._show_product_results(run_id=item.run_id)
            return
        if item:
            dialog=QDialog(self);dialog.setWindowTitle("巡检任务");layout=QVBoxLayout(dialog)
            layout.addWidget(key_values(self,[("任务编号",self._report_task_label(item)),("客户",item.customer_name),("时间",local_time(item.assessment_time)),("健康结论",self._caliber_label(item))]));dialog.setToolTip(item.run_id or "");dialog.resize(620,360);dialog.exec()

    def _resize_batch_pages(self):
        if not hasattr(self,"report_filter_grid"):return
        self.report_list.setWordWrap(False);self.report_list.setTextElideMode(Qt.ElideRight)
        compact=self.pages.width()<SIZES["compact_filter_threshold"]
        for index,box in enumerate(self.report_filter_boxes):self.report_filter_grid.addWidget(box,index//2 if compact else 0,index%2 if compact else index)
        self.report_filter_grid.addWidget(self.report_search_input,2 if compact else 0,0 if compact else 4,1,2 if compact else 1)
        for widget,shares in ((self.asset_table,SIZES["asset_table_shares"]),(self.report_list,SIZES["report_table_shares"]),(self.history_risk_list,SIZES["history_table_shares"])):
            if widget is not self.asset_table:
                if widget is self.report_list:widget.horizontalHeader().setMinimumSectionSize(70)
                width=widget.viewport().width()
                visible=[c for c in range(widget.columnCount()) if not widget.isColumnHidden(c)]
                weights={c:shares[c] if c<len(shares) else max(.08,1-sum(shares)) for c in visible}
                total=sum(weights.values()) or 1
                for column in visible:
                    widget.horizontalHeader().setSectionResizeMode(column,QHeaderView.Fixed)
                    minimum=max(160 if widget is self.report_list and column==2 else 0,widget.fontMetrics().horizontalAdvance(widget.horizontalHeaderItem(column).text())+24)
                    widget.setColumnWidth(column,max(minimum,round(width*weights[column]/total)))
                continue
            width=max(0,widget.viewport().width()-2)
            widget.horizontalHeader().setStretchLastSection(False)
            visible=[c for c in range(widget.columnCount()) if not widget.isColumnHidden(c)]
            minimum={c:widget.fontMetrics().horizontalAdvance(widget.horizontalHeaderItem(c).text())+36 for c in visible}
            weights={c:shares[c] if c<len(shares) else max(.08,1-sum(shares)) for c in visible}
            spare=max(0,width-sum(minimum.values()));total=sum(weights.values()) or 1;assigned=0
            for index,column in enumerate(visible):
                widget.horizontalHeader().setSectionResizeMode(column,QHeaderView.Fixed)
                size=minimum[column]+round(spare*weights[column]/total) if index<len(visible)-1 else max(minimum[column],width-assigned)
                widget.setColumnWidth(column,size);assigned+=size
            if widget is self.asset_table:
                for row in range(widget.rowCount()):
                    for column in visible:
                        cell=widget.item(row,column)
                        if cell:cell.setToolTip(cell.text())
