# UI.py
import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTableWidget,
    QTableWidgetItem, QMessageBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout, QInputDialog,
    QSlider, QComboBox  
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QCursor
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
        self.setFixedSize(550, 625)
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
        self.setFixedSize(550, 625)
        
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
        self.password_table.setColumnWidth(3, 210)  # Set the width of the 4th column to 250 pixels
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
        
        self.password_table.itemDoubleClicked.connect(self.copy_to_clipboard)
    
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
            self.update_ui_state()
            self.load_passwords()
        
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

        website_item = QTableWidgetItem(website)
        website_item.setFlags(website_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        website_item.setData(Qt.ItemDataRole.UserRole, website)
        website_item.setToolTip("Double-click to copy")
        self.password_table.setItem(row_position, 0, website_item)

        username_item = QTableWidgetItem(username)
        username_item.setFlags(username_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        username_item.setData(Qt.ItemDataRole.UserRole, username)
        username_item.setToolTip("Double-click to copy")
        self.password_table.setItem(row_position, 1, username_item)

        password_item = QTableWidgetItem("******")
        password_item.setFlags(password_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self.password_table.setItem(row_position, 2, password_item)

        actions_layout = QWidget()
        actions_layout_l = QHBoxLayout(actions_layout)
        actions_layout_l.setContentsMargins(1, 1, 1, 1)
        actions_layout_l.setSpacing(1)

        view_button = QPushButton("View")
        view_button.setObjectName("view_button")
        view_button.setFixedSize(60, 25)
        view_button.clicked.connect(lambda: self.view_password(row_position))
        actions_layout_l.addWidget(view_button)

        edit_button = QPushButton("Edit")
        edit_button.setObjectName("edit_button")
        edit_button.setFixedSize(60, 25)
        edit_button.clicked.connect(lambda: self.edit_password(row_position))
        actions_layout_l.addWidget(edit_button)

        delete_button = QPushButton("Delete")
        delete_button.setObjectName("delete_button")
        delete_button.setFixedSize(60, 25)
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
            dialog = QDialog(self)
            dialog.setWindowTitle("Password")
            dialog.setFixedSize(400, 150)

            layout = QVBoxLayout(dialog)

            message_label = QLabel(dialog)
            message_label.setText(f"The password for {username} on {website} is:")
            layout.addWidget(message_label)

            password_label = QLabel(dialog)
            password_label.setText(decrypted_password)
            password_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            password_label.setStyleSheet("font-size: 14px; font-weight: bold;")
            layout.addWidget(password_label)

            copy_button = QPushButton("Copy to Clipboard", dialog)
            copy_button.clicked.connect(lambda: self.copy_password(decrypted_password))
            layout.addWidget(copy_button)

            close_button = QPushButton("Close", dialog)
            close_button.clicked.connect(dialog.accept)
            layout.addWidget(close_button)

            dialog.exec()
        else:
            QMessageBox.warning(self, "Error", "No matching credentials found.")
            
    def copy_password(self, password):
        clipboard = QApplication.clipboard()
        clipboard.setText(password)

        tooltip = QLabel(self)
        tooltip.setWindowFlags(Qt.WindowType.ToolTip)
        tooltip.setStyleSheet("""
            QLabel {
                background-color: #4CAF50;
                color: white;
                padding: 5px;
                border-radius: 3px;
            }
        """)
        tooltip.setText("✔ Password copied to clipboard")
        tooltip.move(QCursor.pos())
        tooltip.show()

        QTimer.singleShot(1000, tooltip.hide)
    
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
        
        for i in range(row, self.password_table.rowCount()):
            view_button = self.password_table.cellWidget(i, 3).findChild(QPushButton, "view_button")
            edit_button = self.password_table.cellWidget(i, 3).findChild(QPushButton, "edit_button")
            delete_button = self.password_table.cellWidget(i, 3).findChild(QPushButton, "delete_button")
        
            view_button.clicked.disconnect()
            edit_button.clicked.disconnect()
            delete_button.clicked.disconnect()
        
            view_button.clicked.connect(lambda _, r=i: self.view_password(r))
            edit_button.clicked.connect(lambda _, r=i: self.edit_password(r))
            delete_button.clicked.connect(lambda _, r=i: self.delete_password(r))
    
    def generate_password(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Generate Password")
        dialog.setFixedSize(400, 200)

        layout = QVBoxLayout(dialog)

        length_label = QLabel(dialog)
        length_label.setText("Select the desired password length:")
        layout.addWidget(length_label)

        length_slider = QSlider(Qt.Orientation.Horizontal, dialog)
        length_slider.setRange(8, 32)
        length_slider.setValue(12)
        length_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        length_slider.setTickInterval(4)
        layout.addWidget(length_slider)

        length_value_label = QLabel(dialog)
        length_value_label.setText(str(length_slider.value()))
        layout.addWidget(length_value_label)

        length_slider.valueChanged.connect(lambda value: length_value_label.setText(str(value)))

        complexity_label = QLabel(dialog)
        complexity_label.setText("Select the desired password complexity:")
        layout.addWidget(complexity_label)

        complexity_combo = QComboBox(dialog)
        complexity_combo.addItems(["Low", "Medium", "High"])
        complexity_combo.setCurrentIndex(1)  # Set default to "medium"
        layout.addWidget(complexity_combo)

        generate_button = QPushButton("Generate", dialog)
        generate_button.clicked.connect(lambda: self.show_generated_password(length_slider.value(), complexity_combo.currentText(), dialog))
        layout.addWidget(generate_button)

        dialog.exec()

    def show_generated_password(self, length, complexity, parent_dialog):
        generated_password = generate_password(length, complexity)

        dialog = QDialog(parent_dialog)
        dialog.setWindowTitle("Generated Password")
        dialog.setFixedSize(400, 150)

        layout = QVBoxLayout(dialog)

        message_label = QLabel(dialog)
        message_label.setText("The generated password is:")
        layout.addWidget(message_label)

        password_label = QLabel(dialog)
        password_label.setText(generated_password)
        password_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        password_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        layout.addWidget(password_label)

        copy_button = QPushButton("Copy to Clipboard", dialog)
        copy_button.clicked.connect(lambda: self.copy_password(generated_password))
        layout.addWidget(copy_button)

        close_button = QPushButton("Close", dialog)
        close_button.clicked.connect(dialog.accept)
        layout.addWidget(close_button)

        dialog.exec()
    
    def logout(self):
        self.user_id = None
        self.password_table.setRowCount(0)
        self.update_ui_state()
        
    def copy_to_clipboard(self, item):
        if item.column() in [0, 1]:  # Only copy website and username
            clipboard = QApplication.clipboard()
            clipboard.setText(item.data(Qt.ItemDataRole.UserRole))
        
            # Display a small dialog box or tooltip to indicate copying
            tooltip = QLabel(self)
            tooltip.setWindowFlags(Qt.WindowType.ToolTip)
            tooltip.setStyleSheet("""
                QLabel {
                    background-color: #4CAF50;
                    color: white;
                    padding: 5px;
                    border-radius: 3px;
                }
            """)
            tooltip.setText("✔ Copied to clipboard")
            tooltip.move(QCursor.pos())
            tooltip.show()
        
            QTimer.singleShot(1000, tooltip.hide)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PasswordManager()
    window.show()
    sys.exit(app.exec())
