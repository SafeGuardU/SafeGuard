import sys
import os
import base64
from PyQt6.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QMessageBox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Function to create a random encryption key
def generate_random_key(salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(b"fixed_random_string")

# Function to decrypt the encrypted password using AES-256
def decrypt_encrypted_password(encrypted_password, encryption_key):
    encrypted_data = base64.b64decode(encrypted_password)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(encryption_key)
    decrypted_password = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted_password.decode()

# Function to retrieve and decrypt the password
def retrieve_password(username, website_name):
    filename = "encrypted_passwords.txt"
    
    try:
        with open(filename, "r") as file:
            lines = file.readlines()
            
            # Initialize variables to hold the extracted data
            current_username = ""
            current_website = ""
            encrypted_password = ""
            salt = ""
            
            # Read the file line by line
            for line in lines:
                if line.startswith("Username:"):
                    current_username = line.split(": ")[1].strip()
                elif line.startswith("Website:"):
                    current_website = line.split(": ")[1].strip()
                elif line.startswith("EncryptedPassword:"):
                    encrypted_password = line.split(": ")[1].strip()
                elif line.startswith("Salt:"):
                    salt = line.split(": ")[1].strip()
                    
                    # Check if we found the matching username and website
                    if current_username == username and current_website == website_name:
                        # Convert the base64-encoded salt back to bytes
                        salt_bytes = base64.b64decode(salt)
                        
                        # Generate the encryption key
                        encryption_key = generate_random_key(salt_bytes)
                        
                        # Decrypt the password
                        decrypted_password = decrypt_encrypted_password(encrypted_password, encryption_key)
                        
                        # Return the decrypted password
                        return decrypted_password
            
            # If no matching credentials are found
            return None
    
    except FileNotFoundError:
        print(f"The file {filename} does not exist.")
        return None

class PasswordRetriever(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('Password Retriever')

        self.username_label = QLabel('Username:')
        self.username_input = QLineEdit()

        self.website_label = QLabel('Website:')
        self.website_input = QLineEdit()

        self.retrieve_button = QPushButton('Retrieve Password')
        self.retrieve_button.clicked.connect(self.retrieve_password)

        layout = QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.website_label)
        layout.addWidget(self.website_input)
        layout.addWidget(self.retrieve_button)

        self.setLayout(layout)

    def retrieve_password(self):
        username = self.username_input.text()
        website = self.website_input.text()
        
        if not username or not website:
            QMessageBox.warning(self, 'Input Error', 'Please enter both username and website.')
            return

        password = retrieve_password(username, website)

        if password:
            QMessageBox.information(self, 'Password Retrieved', f'The password is: {password}')
        else:
            QMessageBox.warning(self, 'No Match', 'No matching credentials found.')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PasswordRetriever()
    window.show()
    sys.exit(app.exec())
