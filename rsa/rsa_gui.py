#-*-coding:utf-8-*-

from PyQt4.QtGui import *
from PyQt4.QtCore import *

import sys
from rsa import RSA
import ui

class MainWindow(QMainWindow, ui.Ui_MainWindow):
    
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.setupUi(self)
        
        p = 33478071698956898786044169848212690817704794983713768568912431388982883793878002287614711652531743087737814467999489
        q = 36746043666799590428244633799627952632279158164343087642676032283815739666511279233373417143396810270092798736308917
        self.rsa = RSA(p, q)
        
        self.connect(self.button_e, SIGNAL("clicked()"), self.encrypt)
        self.connect(self.button_d, SIGNAL("clicked()"), self.decrypt)
        #self.connect(self.button_e, SIGNAL("clicked()"), lambda:QMessageBox.information(self,"No",u"浮云"))
    
    def encrypt(self):
        message = unicode(self.line_e_m.text()).strip()
        if not message:
            QMessageBox.critical(self, u"错误", u"请输入明文")
        else:
            ciphertext = self.rsa.encryptString(message)
            self.text_e_c.setPlainText(QString(unicode(ciphertext)))
    
    def decrypt(self):
        ciphertext = unicode(self.text_d_c.toPlainText()).strip()
        if not ciphertext:
            QMessageBox.critical(self, u"错误", u"请输入密文")
        else:
            try:
                message = self.rsa.decrypt(ciphertext)
            except:
                self.line_d_m.setText(u"无法解密该密文")
            else:
                self.line_d_m.setText(unicode(message))
            
            

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec_()
