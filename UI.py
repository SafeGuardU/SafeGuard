# UI.py
import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTableWidget, 
    QTableWidgetItem, QMessageBox, QDialog, QDialogButtonBox, QFormLayout, QComboBox, QInputDialog
)
from PyQt6.QtCore import Qt
from db import create_connection, create_tables
from registration import create_user
from login import authenticate_user
from password_storage import store_encrypted_password
from password_retrieval import retrieve_password
from password_generator import generate_password
from password_management import update_password, delete_password

class LoginWindow(QDialog):
    def __init__(self, conn, parent=None):
        super(LoginWindow, self).__init__(parent)
        self.conn = conn
        self.setWindowTitle("Login")
        self.setModal(True)
        
        self.username = QLineEdit(self)
        self.password = QLineEdit(self)
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        
        layout = QFormLayout(self)
        layout.addRow("Username", self.username)
        layout.addRow("Password", self.password)
        
        buttonBox = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, self)
        buttonBox.accepted.connect(self.accept)
        buttonBox.rejected.connect(self.reject)
        
        layout.addWidget(buttonBox)
        
    def accept(self):
        username = self.username.text()
        password = self.password.text()
        
        user_id = authenticate_user(self.conn, username, password)
        if user_id:
            self.parent().user_id = user_id
            super().accept()
        else:
            QMessageBox.critical(self, "Login Failed", "Invalid username or password")

class RegistrationWindow(QDialog):
    def __init__(self, conn, parent=None):
        super(RegistrationWindow, self).__init__(parent)
        self.conn = conn
        self.setWindowTitle("Register")
        self.setModal(True)
        
        self.username = QLineEdit(self)
        self.password = QLineEdit(self)
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        
        layout = QFormLayout(self)
        layout.addRow("Username", self.username)
        layout.addRow("Password", self.password)
        
        buttonBox = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, self)
        buttonBox.accepted.connect(self.accept)
        buttonBox.rejected.connect(self.reject)
        
        layout.addWidget(buttonBox)
        
    def accept(self):
        username = self.username.text()
        password = self.password.text()
        
        create_user(self.conn, username, password)
        QMessageBox.information(self, "Registration Successful", "User registered successfully")
        super().accept()

class PasswordManager(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.conn = create_connection()
        create_tables(self.conn)
        
        self.user_id = None
        
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle("Password Manager")
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.layout = QVBoxLayout(self.central_widget)
        
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.login)
        self.layout.addWidget(self.login_button)
        
        self.register_button = QPushButton("Register")
        self.register_button.clicked.connect(self.register)
        self.layout.addWidget(self.register_button)
        
        self.password_table = QTableWidget(0, 4)
        self.password_table.setHorizontalHeaderLabels(["Website", "Username", "Password", "Actions"])
        self.layout.addWidget(self.password_table)
        
        self.add_password_button = QPushButton("Add Password")
        self.add_password_button.clicked.connect(self.add_password)
        self.layout.addWidget(self.add_password_button)
        
        self.generate_password_button = QPushButton("Generate Password")
        self.generate_password_button.clicked.connect(self.generate_password)
        self.layout.addWidget(self.generate_password_button)
        
        self.logout_button = QPushButton("Logout")
        self.logout_button.clicked.connect(self.logout)
        self.layout.addWidget(self.logout_button)
        
        self.update_ui_state()
    
    def update_ui_state(self):
        logged_in = self.user_id is not None
        self.password_table.setEnabled(logged_in)
        self.add_password_button.setEnabled(logged_in)
        self.generate_password_button.setEnabled(logged_in)
        self.logout_button.setEnabled(logged_in)
        self.login_button.setEnabled(not logged_in)
        self.register_button.setEnabled(not logged_in)
        
    def login(self):
        login_dialog = LoginWindow(self.conn, self)
        if login_dialog.exec() == QDialog.DialogCode.Accepted:
            QMessageBox.information(self, "Login Successful", "You are now logged in.")
            self.load_passwords()
            self.update_ui_state()
        
    def register(self):
        reg_dialog = RegistrationWindow(self.conn, self)
        reg_dialog.exec()
    
    def load_passwords(self):
        self.password_table.setRowCount(0)
        cursor = self.conn.cursor()
        cursor.execute('SELECT WebsiteName, StoredUsername, EncryptedPassword FROM Passwords WHERE UserID = ?', (self.user_id,))
        rows = cursor.fetchall()
        for row in rows:
            self.add_password_row(row[0], row[1], row[2])
    
    def add_password_row(self, website, username, encrypted_password):
        row_position = self.password_table.rowCount()
        self.password_table.insertRow(row_position)
        
        self.password_table.setItem(row_position, 0, QTableWidgetItem(website))
        self.password_table.setItem(row_position, 1, QTableWidgetItem(username))
        self.password_table.setItem(row_position, 2, QTableWidgetItem("******"))
        
        actions_layout = QWidget()
        actions_layout_l = QVBoxLayout(actions_layout)
        
        view_button = QPushButton("View")
        view_button.clicked.connect(lambda: self.view_password(row_position))
        actions_layout_l.addWidget(view_button)
        
        edit_button = QPushButton("Edit")
        edit_button.clicked.connect(lambda: self.edit_password(row_position))
        actions_layout_l.addWidget(edit_button)
        
        delete_button = QPushButton("Delete")
        delete_button.clicked.connect(lambda: self.delete_password(row_position))
        actions_layout_l.addWidget(delete_button)
        
        self.password_table.setCellWidget(row_position, 3, actions_layout)
        
    def add_password(self):
        website, ok = QInputDialog.getText(self, "Website", "Enter the website name:")
        if not ok:
            return
        
        username, ok = QInputDialog.getText(self, "Username", "Enter the username:")
        if not ok:
            return
        
        password, ok = QInputDialog.getText(self, "Password", "Enter the password:")
        if not ok:
            return
        
        store_encrypted_password(self.conn, self.user_id, website, username, password)
        self.add_password_row(website, username, "******")
        
    def view_password(self, row):
        website = self.password_table.item(row, 0).text()
        username = self.password_table.item(row, 1).text()
        
        decrypted_password = retrieve_password(self.conn, self.user_id, website, username)
        if decrypted_password:
            QMessageBox.information(self, "Password", f"The password for {username} on {website} is: {decrypted_password}")
        else:
            QMessageBox.warning(self, "Error", "No matching credentials found.")
    
    def edit_password(self, row):
        website = self.password_table.item(row, 0).text()
        username = self.password_table.item(row, 1).text()
        
        new_password, ok = QInputDialog.getText(self, "Edit Password", "Enter the new password:")
        if not ok:
            return
        
        update_password(self.conn, self.user_id, website, username, new_password)
        QMessageBox.information(self, "Success", "Password updated successfully.")
    
    def delete_password(self, row):
        website = self.password_table.item(row, 0).text()
        username = self.password_table.item(row, 1).text()
        
        delete_password(self.conn, self.user_id, website, username)
        self.password_table.removeRow(row)
        QMessageBox.information(self, "Success", "Password deleted successfully.")
    
    def generate_password(self):
        length, ok = QInputDialog.getInt(self, "Generate Password", "Enter the desired password length:")
        if not ok:
            return
        
        complexities = ["low", "medium", "high"]
        complexity, ok = QInputDialog.getItem(self, "Generate Password", "Select the desired password complexity:", complexities, 0, False)
        if not ok:
            return
        
        generated_password = generate_password(length, complexity)
        QMessageBox.information(self, "Generated Password", f"Generated Password: {generated_password}")
    
    def logout(self):
        self.user_id = None
        self.password_table.setRowCount(0)
        self.update_ui_state()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PasswordManager()
    window.show()
    sys.exit(app.exec())
