from init.dashboard import Ui_Dialog
from PyQt5.QtWidgets import QApplication, QDialog,QTableWidgetItem
from PyQt5 import QtCore,QtWidgets,QtGui
from terminal_CLI.exec_cmd import *
from processing.packet_find import Packet_query
from processing.capture_pac import score
import sys
from datetime import datetime

commandtable = CommandTable()

def log_to_browser(level, message):
    now = datetime.now().strftime("%H:%M:%S")
    timestamp = f'<span style="color: #95a5a6;">[{now}]</span>'
    
    styles = {
        'success': ('#2ecc71', ' SUCCESS'),
        'block':   ('#e74c3c', ' BLOCK'),
        'info':    ('#3498db', ' INFO'),
        'error':   ('#f1c40f', ' ERROR'),
        'default': ('#ffffff', 'LOG')
    }
    color, prefix = styles.get(level, styles['default'])
    html_msg = f'{timestamp} <b style="color: {color};">{prefix}:</b> {message}'
    return html_msg

class Dashboard(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.plainTextEdit.installEventFilter(self)
        self.ui.tableWidget.itemClicked.connect(self.get_row_data)
        self.ui.tableWidget.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.ui.tableWidget.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)

    def eventFilter(self, obj, event):
        if obj is self.ui.plainTextEdit:
            if event.type() == QtCore.QEvent.KeyPress:
                if event.key() in (QtCore.Qt.Key_Return, QtCore.Qt.Key_Enter):
                    self.cmd = self.get_data()
                    level,msg = commandtable.exec_command(self.cmd.strip(),self.update_gui)
                    if level is not None or msg is not None: self.ui.textBrowser_3.append(log_to_browser(level,msg))
                    self.show_text()
                    return True
                elif event.key() == QtCore.Qt.Key_Up:
                    return True
            elif event.type() == QtCore.QEvent.FocusIn:
                if not self.ui.plainTextEdit.toPlainText().strip():
                    self.show_text()
                    return False
        return super().eventFilter(obj, event)
    
    def update_gui(self, after_score):
        self.ui.tableWidget.setRowCount(len(after_score))
        for i,(key,value) in enumerate(after_score.items(),0):
            score_val = value['score']
            if score_val > 90:
                color = QtGui.QColor(231, 76, 60, 100) 
            elif score_val > 50:
                color = QtGui.QColor(241, 196, 15, 100) 
            else:
                color = QtGui.QColor(46, 204, 113, 100)
            items = [QTableWidgetItem(f"{value['score']:.2f}%"),
                     QTableWidgetItem(str(value['src'])),
                     QTableWidgetItem(str(value['dst'])),
                     QTableWidgetItem(str(value['dport'])),
                     QTableWidgetItem(str(value['proto'])),
                     QTableWidgetItem(f"{value['pps']:.2f}")]
            for col, item in enumerate(items):
                item.setBackground(QtGui.QBrush(color))
                self.ui.tableWidget.setItem(i, col, item)
                item.setTextAlignment(QtCore.Qt.AlignCenter)
    def get_row_data(self,item):
        query = Packet_query()
        row = item.row()
        src_ip = self.ui.tableWidget.item(row, 1).text()
        protocol_ip = self.ui.tableWidget.item(row,4).text()
        if protocol_ip != "TCP" and protocol_ip != "UDP": protocol_ip = "default"
        self.ui.textBrowser_2.setPlainText(query.search_packet(src_ip,protocol_ip))

    def get_data(self):
        cur = self.ui.plainTextEdit.textCursor()
        text = cur.block().text()
        return text[3:]
    
    def show_text(self):
        self.ui.plainTextEdit.appendPlainText(">$ ")