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

class MainWindow(qtw.QWidget):
    def __init__(self):
        super().__init__()
        # set title
        self.setWindowTitle("PASSWORD MANAGER")
        
        # set fixed size
        self.setFixedSize(400, 625)
    
        # set vertical layout
        self.setLayout(qtw.QVBoxLayout())

        # create a tab widget
        self.tab_widget = qtw.QTabWidget()
        self.layout().addWidget(self.tab_widget)

        # create tabs
        self.accounts_tab = qtw.QWidget()
        self.generator_tab = qtw.QWidget()
        self.settings_tab = qtw.QWidget()

        # add tabs to tab widget
        self.tab_widget.addTab(self.accounts_tab, "Accounts")
        self.tab_widget.addTab(self.generator_tab, "Generator")
        self.tab_widget.addTab(self.settings_tab, "Settings")

        # set layouts for tabs
        self.accounts_tab.setLayout(qtw.QVBoxLayout())
        self.generator_tab.setLayout(qtw.QVBoxLayout())
        self.settings_tab.setLayout(qtw.QVBoxLayout())

        # add generator functionality to generator tab
        self.setup_generator_tab()

        # add accounts functionality to accounts tab
        self.setup_accounts_tab()

        # add settings functionality to settings tab
        self.setup_settings_tab()

        # show the app
        self.show()

        # Connect to SQLite database
        self.conn = sqlite3.connect('password_manager.db')
        self.cursor = self.conn.cursor()
        self.create_tables()

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

    def setup_generator_tab(self):
        # create a slider
        self.my_slider = qtw.QSlider(qtc.Qt.Orientation.Horizontal)
        self.my_slider.setMinimum(8)
        self.my_slider.setMaximum(100)
        self.my_slider.setValue(12)
        self.my_slider.setTickInterval(10)
        self.my_slider.setTickPosition(qtw.QSlider.TickPosition.NoTicks)
        self.my_slider.valueChanged.connect(self.update_slider_label)

        # put slider on screen
        self.generator_tab.layout().addWidget(self.my_slider)

        # create a horizontal layout for checkbox options
        options_layout = qtw.QHBoxLayout()
        self.generator_tab.layout().addLayout(options_layout)

        # add include special characters option
        self.include_special_chars = qtw.QCheckBox("Include special characters")
        options_layout.addWidget(self.include_special_chars)

        # add include numbers option
        self.include_numbers = qtw.QCheckBox("Include numbers")
        options_layout.addWidget(self.include_numbers)

        # create a line edit for slider input
        self.slider_input = qtw.QLineEdit()
        self.slider_input.setFixedWidth(50)
        self.slider_input.setText(str(self.my_slider.value()))
        self.slider_input.editingFinished.connect(self.update_slider_from_input)
        options_layout.addWidget(self.slider_input)

        # create a button
        self.my_button = qtw.QPushButton("Generate Password", clicked=self.press_it)
        self.generator_tab.layout().addWidget(self.my_button)

        # create a text box for password display
        self.password_display = qtw.QTextEdit()
        self.password_display.setReadOnly(True)
        self.generator_tab.layout().addWidget(self.password_display)

        # create a copy to clipboard button
        self.copy_button = qtw.QPushButton("Copy to Clipboard", clicked=self.copy_to_clipboard)
        self.generator_tab.layout().addWidget(self.copy_button)

    def setup_accounts_tab(self):
        form_layout = qtw.QFormLayout()
        
        self.username_input = qtw.QLineEdit()
        self.master_password_input = qtw.QLineEdit()
        self.master_password_input.setEchoMode(qtw.QLineEdit.EchoMode.Password)
        self.website_name_input = qtw.QLineEdit()
        self.stored_username_input = qtw.QLineEdit()
        self.password_input = qtw.QLineEdit()
        self.password_input.setEchoMode(qtw.QLineEdit.EchoMode.Password)
        
        form_layout.addRow("Username:", self.username_input)
        form_layout.addRow("Master Password:", self.master_password_input)
        form_layout.addRow("Website Name:", self.website_name_input)
        form_layout.addRow("Stored Username:", self.stored_username_input)
        form_layout.addRow("Password:", self.password_input)
        
        self.save_button = qtw.QPushButton("Save Password", clicked=self.save_password)
        self.retrieve_button = qtw.QPushButton("Retrieve Password", clicked=self.retrieve_password)
        
        form_layout.addRow(self.save_button)
        form_layout.addRow(self.retrieve_button)
        
        self.accounts_tab.layout().addLayout(form_layout)

    def setup_settings_tab(self):
        # Add any settings related UI elements here
        pass

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

    def create_user(self, username):
        salt = self.generate_salt()
        master_password_hash = self.hash_password(self.master_password_input.text(), salt)
        
        self.cursor.execute('''
        INSERT INTO Users (Username, MasterPasswordHash, MasterPasswordSalt)
        VALUES (?, ?, ?)
        ''', (username, base64.b64encode(master_password_hash).decode(), base64.b64encode(salt).decode()))
        
        self.conn.commit()
        return self.cursor.lastrowid

    def store_encrypted_password(self, user_id, website_name, stored_username, encrypted_password, salt):
        self.cursor.execute('''
        INSERT INTO Passwords (UserID, WebsiteName, StoredUsername, EncryptedPassword, Salt)
        VALUES (?, ?, ?, ?, ?)
        ''', (user_id, website_name, stored_username, encrypted_password, base64.b64encode(salt).decode()))
        self.conn.commit()

    def save_password(self):
        username = self.username_input.text()
        master_password = self.master_password_input.text()
        website_name = self.website_name_input.text()
        stored_username = self.stored_username_input.text()
        plaintext_password = self.password_input.text()

        # Create user if not exists and get user_id
        user_id = self.create_user(username)

        # Retrieve the stored master password hash and salt
        self.cursor.execute('SELECT MasterPasswordHash, MasterPasswordSalt FROM Users WHERE UserID = ?', (user_id,))
        stored_hash, stored_salt = self.cursor.fetchone()
        stored_hash = base64.b64decode(stored_hash)
        stored_salt = base64.b64decode(stored_salt)

        # Verify the entered master password
        entered_hash = self.hash_password(master_password, stored_salt)

        if entered_hash != stored_hash:
            qtw.QMessageBox.critical(self, "Error", "Master password verification failed.")
            return

        # Generate salt for encryption
        salt = self.generate_salt()

        # Generate encryption key using the master password hash and the newly generated salt
        encryption_key = self.generate_encryption_key(stored_hash, salt)

        # Encrypt the plaintext password
        encrypted_password = self.encrypt_plaintext_password(plaintext_password, encryption_key)

        # Store the encrypted password and salt in the database
        self.store_encrypted_password(user_id, website_name, stored_username, encrypted_password, salt)
        qtw.QMessageBox.information(self, "Success", "Password saved successfully.")

    def retrieve_password(self):
        username = self.username_input.text()
        master_password = self.master_password_input.text()
        website_name = self.website_name_input.text()
        stored_username = self.stored_username_input.text()

        self.cursor.execute('''
        SELECT p.EncryptedPassword, p.Salt, u.MasterPasswordHash, u.MasterPasswordSalt
        FROM Passwords p
        JOIN Users u ON p.UserID = u.UserID
        WHERE LOWER(u.Username) = ? AND LOWER(p.WebsiteName) = ? AND LOWER(p.StoredUsername) = ?
        ''', (username.lower(), website_name.lower(), stored_username.lower()))
        
        row = self.cursor.fetchone()
        
        if row:
            encrypted_password, salt, stored_hash, stored_salt = row
            stored_hash = base64.b64decode(stored_hash)
            stored_salt = base64.b64decode(stored_salt)
            salt_bytes = base64.b64decode(salt)

            # Verify the entered master password
            entered_hash = self.hash_password(master_password, stored_salt)

            if entered_hash != stored_hash:
                qtw.QMessageBox.critical(self, "Error", "Master password verification failed.")
                return
            
            encryption_key = self.generate_encryption_key(stored_hash, salt_bytes)
            decrypted_password = self.decrypt_encrypted_password(encrypted_password, encryption_key)
            qtw.QMessageBox.information(self, "Retrieved Password", f"The password for {stored_username} on {website_name} is: {decrypted_password}")
        else:
            qtw.QMessageBox.critical(self, "Error", "No matching credentials found.")

    def generate_password(self, length, include_special_chars, include_numbers):
        lowercase_letters = string.ascii_lowercase
        uppercase_letters = string.ascii_uppercase
        digits = string.digits if include_numbers else ''
        symbols = string.punctuation if include_special_chars else ''

        # Ensure at least one character set is selected
        if not (lowercase_letters or uppercase_letters or digits or symbols):
            raise ValueError("At least one character set must be enabled.")
        
        # Combine selected character sets
        all_characters = lowercase_letters + uppercase_letters + digits + symbols
        
        # Ensure the password includes at least one character from each enabled set
        password = ''
        if lowercase_letters:
            password += random.choice(lowercase_letters)
        if uppercase_letters:
            password += random.choice(uppercase_letters)
        if digits:
            password += random.choice(digits)
        if symbols:
            password += random.choice(symbols)
        
        # Fill the rest of the password with random characters from all_characters
        password += ''.join(random.choice(all_characters) for _ in range(length - len(password)))
        
        # Shuffle the password to make it more random
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

app = qtw.QApplication([])
mw = MainWindow()
app.exec()
