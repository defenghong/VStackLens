"""Task-scoped presentation only: one body scroller and stable actions."""
from PySide6.QtCore import QObject,QEvent,QTimer,Qt,Signal
from PySide6.QtWidgets import QWidget,QVBoxLayout,QHBoxLayout,QScrollArea,QFrame,QPushButton,QLabel,QTextEdit,QTreeWidget,QStyledItemDelegate
from shiboken6 import isValid
from vstacklens.desktop.theme import SIZES

class ContentHeight(QObject):
    """Let the surrounding task page own vertical reading, without trimming text."""
    def __init__(self,view):
        super().__init__(view);self.view=view;self.pending=False
        view.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff);view.installEventFilter(self)
        if isinstance(view,QTextEdit):
            view.textChanged.connect(self.queue)
        else:
            view.itemChanged.connect(self.queue)
            if isinstance(view,QTreeWidget):view.itemExpanded.connect(self.queue);view.itemCollapsed.connect(self.queue)
        self.queue()
    def eventFilter(self,obj,event):
        if event.type() in (QEvent.Resize,QEvent.Show):self.queue()
        return False
    def queue(self,*args):
        if self.pending:return
        self.pending=True;QTimer.singleShot(0,self.sync)
    def sync(self):
        self.pending=False;view=self.view
        if not isValid(view):return
        if isinstance(view,QTextEdit):height=max(60,int(view.document().size().height())+16)
        elif isinstance(view,QTreeWidget):
            def count(item):return 1+(sum(count(item.child(i)) for i in range(item.childCount())) if item.isExpanded() else 0)
            rows=sum(count(view.topLevelItem(i)) for i in range(view.topLevelItemCount()))
            height=view.header().height()+max(1,rows)*max(28,view.fontMetrics().height()+10)+4
        else:height=view.horizontalHeader().height()+sum(view.rowHeight(i) for i in range(view.rowCount()))+4
        height=min(16777215,height)
        if view.minimumHeight()!=height or view.maximumHeight()!=height:view.setFixedHeight(height)

class SingleStatusDelegate(QStyledItemDelegate):
    def __init__(self,view):super().__init__(view);self.view=view
    def initStyleOption(self,option,index):
        super().initStyleOption(option,index)
        if self.view.indexWidget(index) is not None:option.text=""

class TaskWorkspace(QWidget):
    phaseChanged=Signal(str)
    def __init__(self,config,progress,result):
        super().__init__();self.phase=None;self.config=config;self.progress=progress;self.result=result
        outer=QVBoxLayout(self);outer.setContentsMargins(0,0,0,0);outer.setSpacing(SIZES['card_gap'])
        row=QHBoxLayout();self.caption=QLabel('等待开始');row.addWidget(self.caption,1)
        self.config_toggle=QPushButton('收起配置');self.config_toggle.setObjectName('outlineButton');self.config_toggle.setFixedHeight(SIZES['secondary_button']);self.config_toggle.setCheckable(True);self.config_toggle.setChecked(True);row.addWidget(self.config_toggle)
        self.config_toggle.toggled.connect(self._show_config);outer.addLayout(row)
        self.body=QWidget();layout=QVBoxLayout(self.body);layout.setContentsMargins(0,0,0,0);layout.setSpacing(SIZES['card_gap'])
        for widget in (config,progress,result):layout.addWidget(widget)
        layout.addStretch(1);self.scroll=QScrollArea();self.scroll.setFrameShape(QFrame.NoFrame);self.scroll.setWidgetResizable(True);self.scroll.setWidget(self.body);self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff);outer.addWidget(self.scroll,1)
        self.set_phase('idle')
    def _show_config(self,visible):
        self.config.setVisible(visible);self.config_toggle.setText('收起配置' if visible else '查看配置')
    def set_phase(self,phase):
        if phase==self.phase:return
        self.phase=phase
        self.caption.setText({'idle':'等待开始','running':'进行中','completed':'已完成','failed':'失败：请查看原因','cancelled':'已取消'}.get(phase,phase))
        self.config_toggle.setChecked(phase=='idle');self._show_config(phase=='idle')
        self.progress.setVisible(phase=='running');self.result.setVisible(phase!='idle')
        self.scroll.verticalScrollBar().setValue(0);self.phaseChanged.emit(phase)
