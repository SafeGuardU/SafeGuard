import random
import string
import base64
import sqlite3
import os
import sys
import PyQt6.QtWidgets as qtw
import PyQt6.QtGui as qtg
import PyQt6.QtCore as qtc
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class LoginDialog(qtw.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Login")
        self.setFixedSize(400, 625)  # Match the dimensions of MainWindow
        layout = qtw.QFormLayout()

        self.username_input = qtw.QLineEdit()
        self.master_password_input = qtw.QLineEdit()
        self.master_password_input.setEchoMode(qtw.QLineEdit.EchoMode.Password)
        self.login_button = qtw.QPushButton("Login", clicked=self.verify_credentials)

        layout.addRow(qtw.QLabel("Username:"), self.username_input)
        layout.addRow(qtw.QLabel("Master Password:"), self.master_password_input)
        layout.addRow(self.login_button)

        self.setLayout(layout)


    def showEvent(self, event):
        self.center_on_screen()
        super().showEvent(event)

    def center_on_screen(self):
        screen = qtw.QApplication.primaryScreen().availableGeometry()
        size = self.geometry()
        self.move(
            (screen.width() - size.width()) // 2,
            (screen.height() - size.height()) // 2
        )

    def verify_credentials(self):
        username = self.username_input.text()
        master_password = self.master_password_input.text()
        if self.parent().verify_master_password(username, master_password):
            self.parent().logged_in_user = username
            self.accept()
        else:
            qtw.QMessageBox.critical(self, "Error", "Invalid username or master password.")

class MainWindow(qtw.QWidget):
    def __init__(self):
        super().__init__()
        self.logged_in_user = None
        self.setWindowTitle("PASSWORD MANAGER")
        self.setFixedSize(400, 625)
        self.setLayout(qtw.QVBoxLayout())

        self.tab_widget = qtw.QTabWidget()
        self.layout().addWidget(self.tab_widget)

        self.accounts_tab = qtw.QWidget()
        self.generator_tab = qtw.QWidget()
        self.settings_tab = qtw.QWidget()

        self.tab_widget.addTab(self.accounts_tab, "Accounts")
        self.tab_widget.addTab(self.generator_tab, "Generator")
        self.tab_widget.addTab(self.settings_tab, "Settings")

        self.accounts_tab.setLayout(qtw.QVBoxLayout())
        self.generator_tab.setLayout(qtw.QVBoxLayout())
        self.settings_tab.setLayout(qtw.QVBoxLayout())

        self.setup_generator_tab()
        self.setup_accounts_tab()
        self.setup_settings_tab()

        self.conn = sqlite3.connect('password_manager.db')
        self.cursor = self.conn.cursor()
        self.create_tables()

        self.login_dialog = LoginDialog(self)
        if self.login_dialog.exec() == qtw.QDialog.DialogCode.Accepted:
            self.load_accounts()
            self.show()
        else:
            sys.exit()

    def create_tables(self):
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS Users (
            UserID INTEGER PRIMARY KEY AUTOINCREMENT,
            Username TEXT NOT NULL,
            MasterPasswordHash TEXT NOT NULL,
            MasterPasswordSalt TEXT NOT NULL
        )
        ''')
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS Passwords (
            PasswordID INTEGER PRIMARY KEY AUTOINCREMENT,
            UserID INTEGER,
            WebsiteName TEXT NOT NULL,
            StoredUsername TEXT NOT NULL,
            EncryptedPassword TEXT NOT NULL,
            Salt TEXT NOT NULL,
            FOREIGN KEY (UserID) REFERENCES Users (UserID)
        )
        ''')
        self.conn.commit()

    def verify_master_password(self, username, master_password):
        self.cursor.execute('SELECT MasterPasswordHash, MasterPasswordSalt FROM Users WHERE LOWER(Username) = ?', (username.lower(),))
        result = self.cursor.fetchone()
        if result:
            stored_hash, stored_salt = result
            stored_hash = base64.b64decode(stored_hash)
            stored_salt = base64.b64decode(stored_salt)
            entered_hash = self.hash_password(master_password, stored_salt)
            return entered_hash == stored_hash
        return False

    def setup_generator_tab(self):
        self.my_slider = qtw.QSlider(qtc.Qt.Orientation.Horizontal)
        self.my_slider.setMinimum(8)
        self.my_slider.setMaximum(100)
        self.my_slider.setValue(12)
        self.my_slider.setTickInterval(10)
        self.my_slider.setTickPosition(qtw.QSlider.TickPosition.NoTicks)
        self.my_slider.valueChanged.connect(self.update_slider_label)

        self.generator_tab.layout().addWidget(self.my_slider)

        options_layout = qtw.QHBoxLayout()
        self.generator_tab.layout().addLayout(options_layout)

        self.include_special_chars = qtw.QCheckBox("Special Characters")
        options_layout.addWidget(self.include_special_chars)

        self.include_numbers = qtw.QCheckBox("Numbers")
        options_layout.addWidget(self.include_numbers)

        self.slider_input = qtw.QLineEdit()
        self.slider_input.setFixedWidth(50)
        self.slider_input.setText(str(self.my_slider.value()))
        self.slider_input.editingFinished.connect(self.update_slider_from_input)
        options_layout.addWidget(self.slider_input)

        self.my_button = qtw.QPushButton("Generate Password", clicked=self.press_it)
        self.generator_tab.layout().addWidget(self.my_button)

        self.password_display = qtw.QTextEdit()
        self.password_display.setReadOnly(True)
        self.generator_tab.layout().addWidget(self.password_display)

        self.copy_button = qtw.QPushButton("Copy to Clipboard", clicked=self.copy_to_clipboard)
        self.generator_tab.layout().addWidget(self.copy_button)

    def setup_accounts_tab(self):
        self.store_button = qtw.QPushButton("Store New Password", clicked=self.show_store_form)
        self.accounts_tab.layout().addWidget(self.store_button)

        self.accounts_list = qtw.QListWidget()
        self.accounts_tab.layout().addWidget(self.accounts_list)
        self.accounts_list.itemClicked.connect(self.prompt_master_password)

    def setup_settings_tab(self):
        pass

    def load_accounts(self):
        self.accounts_list.clear()
        self.cursor.execute('''
        SELECT p.WebsiteName, p.StoredUsername 
        FROM Passwords p
        JOIN Users u ON p.UserID = u.UserID
        WHERE LOWER(u.Username) = ?
        ''', (self.logged_in_user.lower(),))
        
        rows = self.cursor.fetchall()
        if rows:
            for row in rows:
                self.accounts_list.addItem(f"{row[0]} - {row[1]}")

    def prompt_master_password(self, item):
        website_name, stored_username = item.text().split(" - ")
        master_password, ok = qtw.QInputDialog.getText(self, "Master Password Required", "Re-enter Master Password:", qtw.QLineEdit.EchoMode.Password)
        if ok and self.verify_master_password(self.logged_in_user, master_password):
            self.retrieve_password(website_name, stored_username, master_password)
        else:
            qtw.QMessageBox.critical(self, "Error", "Invalid master password.")

    def show_store_form(self):
        form_dialog = StoreFormDialog(self)
        if form_dialog.exec() == qtw.QDialog.DialogCode.Accepted:
            self.load_accounts()

    def retrieve_password(self, website_name, stored_username, master_password):
        self.cursor.execute('''
        SELECT p.EncryptedPassword, p.Salt, u.MasterPasswordHash, u.MasterPasswordSalt
        FROM Passwords p
        JOIN Users u ON p.UserID = u.UserID
        WHERE LOWER(u.Username) = ? AND LOWER(p.WebsiteName) = ? AND LOWER(p.StoredUsername) = ?
        ''', (self.logged_in_user.lower(), website_name.lower(), stored_username.lower()))
        
        row = self.cursor.fetchone()
        if row:
            encrypted_password, salt, stored_hash, stored_salt = row
            stored_hash = base64.b64decode(stored_hash)
            stored_salt = base64.b64decode(stored_salt)
            salt_bytes = base64.b64decode(salt)

            entered_hash = self.hash_password(master_password, stored_salt)
            if entered_hash != stored_hash:
                qtw.QMessageBox.critical(self, "Error", "Master password verification failed.")
                return
            
            encryption_key = self.generate_encryption_key(stored_hash, salt_bytes)
            decrypted_password = self.decrypt_encrypted_password(encrypted_password, encryption_key)
            qtw.QMessageBox.information(self, "Retrieved Password", f"The password for {stored_username} on {website_name} is: {decrypted_password}")
        else:
            qtw.QMessageBox.critical(self, "Error", "No matching credentials found.")

    def store_encrypted_password(self, user_id, website_name, stored_username, encrypted_password, salt):
        self.cursor.execute('''
        INSERT INTO Passwords (UserID, WebsiteName, StoredUsername, EncryptedPassword, Salt)
        VALUES (?, ?, ?, ?, ?)
        ''', (user_id, website_name, stored_username, encrypted_password, salt))
        self.conn.commit()

    def generate_encryption_key(self, master_password_hash, salt):
        return base64.urlsafe_b64encode(master_password_hash + salt)[:32]

    def hash_password(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_password(self, password, encryption_key):
        aesgcm = AESGCM(encryption_key)
        nonce = os.urandom(12)
        encrypted_password = aesgcm.encrypt(nonce, password.encode(), None)
        return base64.b64encode(nonce + encrypted_password).decode()

    def decrypt_encrypted_password(self, encrypted_password, encryption_key):
        encrypted_password_bytes = base64.b64decode(encrypted_password)
        nonce = encrypted_password_bytes[:12]
        ciphertext = encrypted_password_bytes[12:]
        aesgcm = AESGCM(encryption_key)
        return aesgcm.decrypt(nonce, ciphertext, None).decode()

    def update_slider_label(self):
        self.slider_input.setText(str(self.my_slider.value()))

    def update_slider_from_input(self):
        try:
            value = int(self.slider_input.text())
            self.my_slider.setValue(value)
        except ValueError:
            pass

    def press_it(self):
        length = self.my_slider.value()
        include_special_chars = self.include_special_chars.isChecked()
        include_numbers = self.include_numbers.isChecked()
        generated_password = self.generate_password(length, include_special_chars, include_numbers)
        self.password_display.setText(generated_password)

    def generate_password(self, length, include_special_chars, include_numbers):
        characters = string.ascii_letters
        if include_numbers:
            characters += string.digits
        if include_special_chars:
            characters += string.punctuation

        password = ''.join(random.choice(characters) for _ in range(length))
        return password

    def copy_to_clipboard(self):
        clipboard = qtw.QApplication.clipboard()
        clipboard.setText(self.password_display.toPlainText())

class StoreFormDialog(qtw.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Store New Password")
        layout = qtw.QFormLayout()

        self.website_input = qtw.QLineEdit()
        self.stored_username_input = qtw.QLineEdit()
        self.stored_password_input = qtw.QLineEdit()
        self.stored_password_input.setEchoMode(qtw.QLineEdit.EchoMode.Password)
        self.store_button = qtw.QPushButton("Store", clicked=self.store_password)

        layout.addRow(qtw.QLabel("Website Name:"), self.website_input)
        layout.addRow(qtw.QLabel("Stored Username:"), self.stored_username_input)
        layout.addRow(qtw.QLabel("Stored Password:"), self.stored_password_input)
        layout.addRow(self.store_button)

        self.setLayout(layout)


    def store_password(self):
        website_name = self.website_input.text()
        stored_username = self.stored_username_input.text()
        stored_password = self.stored_password_input.text()
        master_password, ok = qtw.QInputDialog.getText(self, "Master Password Required", "Re-enter Master Password:", qtw.QLineEdit.EchoMode.Password)
        if ok and self.parent().verify_master_password(self.parent().logged_in_user, master_password):
            user_id = self.parent().get_user_id(self.parent().logged_in_user)
            salt = os.urandom(16)
            encryption_key = self.parent().generate_encryption_key(self.parent().hash_password(master_password, salt), salt)
            encrypted_password = self.parent().encrypt_password(stored_password, encryption_key)
            self.parent().store_encrypted_password(user_id, website_name, stored_username, encrypted_password, base64.b64encode(salt).decode())
            self.accept()
        else:
            qtw.QMessageBox.critical(self, "Error", "Master password verification failed.")

if __name__ == '__main__':
    app = qtw.QApplication(sys.argv)
    main_window = MainWindow()
    sys.exit(app.exec())
