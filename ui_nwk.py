from init.dashboard import Ui_Dialog
from PyQt5.QtWidgets import QApplication, QDialog
from PyQt5 import QtCore
from terminal_CLI.exec_cmd import CommandTable
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

    def eventFilter(self, obj, event):
        if obj is self.ui.plainTextEdit:
            if event.type() == QtCore.QEvent.KeyPress:
                if event.key() in (QtCore.Qt.Key_Return, QtCore.Qt.Key_Enter):
                    self.cmd = self.get_data()
                    level,msg = self.run_cmd()
                    self.ui.textBrowser_3.append(log_to_browser(level,msg))
                    self.show_text()
                    return True
                elif event.key() == QtCore.Qt.Key_Up:
                    return True
            elif event.type() == QtCore.QEvent.FocusIn:
                if not self.ui.plainTextEdit.toPlainText().strip():
                    self.show_text()
                    return False
        return super().eventFilter(obj, event)

    def get_data(self):
        cur = self.ui.plainTextEdit.textCursor()
        text = cur.block().text()
        return text[3:]
    
    def show_text(self):
        self.ui.plainTextEdit.appendPlainText(">$ ")

    def run_cmd(self):
        return commandtable.exec_command(self.cmd)