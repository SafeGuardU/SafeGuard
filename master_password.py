import sys
from PyQt6.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMainWindow, QStackedWidget


class LoginPage(QWidget):
    def __init__(self, stacked_widget):
        super().__init__()
        self.stacked_widget = stacked_widget
        self.init_ui()
        
    def init_ui(self):
        self.layout = QVBoxLayout()
        
        self.label = QLabel('Enter Password:')
        self.layout.addWidget(self.label)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.layout.addWidget(self.password_input)
        
        self.submit_button = QPushButton('Submit')
        self.submit_button.clicked.connect(self.check_password)
        self.layout.addWidget(self.submit_button)
        
        self.setLayout(self.layout)
    
    def check_password(self):
        if self.password_input.text() == 'pass':  # this function needs to involve hashing
            self.stacked_widget.setCurrentIndex(1)
        else:
            self.password_input.clear()
            self.label.setText('Incorrect password. Try again:')


class LoggedInPage(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        label = QLabel('You are logged in')
        layout.addWidget(label)
        self.setLayout(layout)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.stacked_widget = QStackedWidget()
        
        self.login_page = LoginPage(self.stacked_widget)
        self.logged_in_page = LoggedInPage()
        
        self.stacked_widget.addWidget(self.login_page)
        self.stacked_widget.addWidget(self.logged_in_page)
        
        self.setCentralWidget(self.stacked_widget)
        self.stacked_widget.setCurrentIndex(0)


app = QApplication(sys.argv)
window = MainWindow()
window.setWindowTitle('Login Page')
window.resize(300, 200)
window.show()
sys.exit(app.exec())
