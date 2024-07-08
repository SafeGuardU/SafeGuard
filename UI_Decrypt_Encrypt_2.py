import random
import string
import base64
import sqlite3
import os
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
        self.setFixedSize(300, 150)
        layout = qtw.QVBoxLayout()

        self.username_input = qtw.QLineEdit()
        self.master_password_input = qtw.QLineEdit()
        self.master_password_input.setEchoMode(qtw.QLineEdit.EchoMode.Password)
        self.login_button = qtw.QPushButton("Login", clicked=self.verify_credentials)

        layout.addWidget(qtw.QLabel("Username:"))
        layout.addWidget(self.username_input)
        layout.addWidget(qtw.QLabel("Master Password:"))
        layout.addWidget(self.master_password_input)
        layout.addWidget(self.login_button)

        self.setLayout(layout)

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

        self.include_special_chars = qtw.QCheckBox("Include special characters")
        options_layout.addWidget(self.include_special_chars)

        self.include_numbers = qtw.QCheckBox("Include numbers")
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
        ''', (user_id, website_name, stored_username, encrypted_password, base64.b64encode(salt).decode()))
        self.conn.commit()

    def generate_salt(self):
        return os.urandom(16)

    def hash_password(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def generate_encryption_key(self, master_password_hash, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(master_password_hash)

    def encrypt_plaintext_password(self, plaintext_password, encryption_key):
        aesgcm = AESGCM(encryption_key)
        nonce = os.urandom(12)  # AES-GCM nonce
        encrypted_password = aesgcm.encrypt(nonce, plaintext_password.encode(), None)
        return base64.b64encode(nonce + encrypted_password).decode()

    def decrypt_encrypted_password(self, encrypted_password, encryption_key):
        encrypted_data = base64.b64decode(encrypted_password)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        aesgcm = AESGCM(encryption_key)
        decrypted_password = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_password.decode()

    def generate_password(self, length, include_special_chars, include_numbers):
        lowercase_letters = string.ascii_lowercase
        uppercase_letters = string.ascii_uppercase
        digits = string.digits if include_numbers else ''
        symbols = string.punctuation if include_special_chars else ''

        if not (lowercase_letters or uppercase_letters or digits or symbols):
            raise ValueError("At least one character set must be enabled.")
        
        all_characters = lowercase_letters + uppercase_letters + digits + symbols
        
        password = ''
        if lowercase_letters:
            password += random.choice(lowercase_letters)
        if uppercase_letters:
            password += random.choice(uppercase_letters)
        if digits:
            password += random.choice(digits)
        if symbols:
            password += random.choice(symbols)
        
        password += ''.join(random.choice(all_characters) for _ in range(length - len(password)))
        
        password_list = list(password)
        random.shuffle(password_list)
        password = ''.join(password_list)
        
        return password

    def press_it(self):
        length = self.my_slider.value()
        include_special_chars = self.include_special_chars.isChecked()
        include_numbers = self.include_numbers.isChecked()
        password = self.generate_password(length, include_special_chars, include_numbers)
        self.password_display.setText(password)

    def update_slider_label(self):
        value = self.my_slider.value()
        self.slider_input.setText(str(value))

    def update_slider_from_input(self):
        value = self.slider_input.text()
        if value.isdigit():
            self.my_slider.setValue(int(value))

    def copy_to_clipboard(self):
        clipboard = qtw.QApplication.clipboard()
        clipboard.setText(self.password_display.toPlainText())

    def get_user_id(self, username):
        self.cursor.execute('SELECT UserID FROM Users WHERE LOWER(Username) = ?', (username.lower(),))
        return self.cursor.fetchone()[0]

    def get_master_password_data(self, user_id):
        self.cursor.execute('SELECT MasterPasswordHash, MasterPasswordSalt FROM Users WHERE UserID = ?', (user_id,))
        stored_hash, stored_salt = self.cursor.fetchone()
        return base64.b64decode(stored_hash), base64.b64decode(stored_salt)

class StoreFormDialog(qtw.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Store New Password")
        self.setFixedSize(300, 300)
        layout = qtw.QVBoxLayout()

        self.website_name_input = qtw.QLineEdit()
        self.stored_username_input = qtw.QLineEdit()
        self.password_input = qtw.QLineEdit()
        self.password_input.setEchoMode(qtw.QLineEdit.EchoMode.Password)
        self.save_button = qtw.QPushButton("Save Password", clicked=self.save_password)

        layout.addWidget(qtw.QLabel("Website Name:"))
        layout.addWidget(self.website_name_input)
        layout.addWidget(qtw.QLabel("Stored Username:"))
        layout.addWidget(self.stored_username_input)
        layout.addWidget(qtw.QLabel("Password:"))
        layout.addWidget(self.password_input)
        layout.addWidget(self.save_button)

        self.setLayout(layout)

    def save_password(self):
        website_name = self.website_name_input.text()
        stored_username = self.stored_username_input.text()
        plaintext_password = self.password_input.text()

        user_id = self.parent().get_user_id(self.parent().logged_in_user)
        stored_hash, stored_salt = self.parent().get_master_password_data(user_id)

        salt = self.parent().generate_salt()
        encryption_key = self.parent().generate_encryption_key(stored_hash, salt)
        encrypted_password = self.parent().encrypt_plaintext_password(plaintext_password, encryption_key)

        self.parent().store_encrypted_password(user_id, website_name, stored_username, encrypted_password, salt)
        qtw.QMessageBox.information(self, "Success", "Password saved successfully.")
        self.accept()

app = qtw.QApplication([])
mw = MainWindow()
app.exec()
