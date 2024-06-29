import os
import base64
import sqlite3
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Connect to the SQLite database
conn = sqlite3.connect('password_manager.db')
cursor = conn.cursor()

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
def retrieve_password(username, website_name, stored_username):
    cursor.execute('''
    SELECT p.EncryptedPassword, p.Salt
    FROM Passwords p
    JOIN Users u ON p.UserID = u.UserID
    WHERE u.Username = ? AND p.WebsiteName = ? AND p.StoredUsername = ?
    ''', (username, website_name, stored_username))
    
    row = cursor.fetchone()
    
    if row:
        encrypted_password, salt = row
        salt_bytes = base64.b64decode(salt)
        encryption_key = generate_random_key(salt_bytes)
        decrypted_password = decrypt_encrypted_password(encrypted_password, encryption_key)
        return decrypted_password
    else:
        return None

# Main function to handle user input and process decryption
def main():
    # Collect user input
    username = input("Enter your Username: ")
    website_name = input("Enter the Website Name: ")
    stored_username = input("Enter the Username for the stored account: ")
    
    # Retrieve and decrypt the password
    decrypted_password = retrieve_password(username, website_name, stored_username)
    
    if decrypted_password:
        print(f"The password for {stored_username} on {website_name} is: {decrypted_password}")
    else:
        print("No matching credentials found.")

if __name__ == "__main__":
    main()

conn.close()
