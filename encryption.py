import os
import base64
import sqlite3
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Create or connect to the SQLite database
conn = sqlite3.connect('password_manager.db')
cursor = conn.cursor()

# Create Users and Passwords tables
cursor.execute('''
CREATE TABLE IF NOT EXISTS Users (
    UserID INTEGER PRIMARY KEY AUTOINCREMENT,
    Username TEXT NOT NULL,
    MasterPasswordHash TEXT NOT NULL,
    MasterPasswordSalt TEXT NOT NULL
)
''')

cursor.execute('''
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

conn.commit()

# Function to generate a random salt
def generate_salt():
    return os.urandom(16)

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

# Function to encrypt the plaintext password using AES-256
def encrypt_plaintext_password(plaintext_password, encryption_key):
    aesgcm = AESGCM(encryption_key)
    nonce = os.urandom(12)  # AES-GCM nonce
    encrypted_password = aesgcm.encrypt(nonce, plaintext_password.encode(), None)
    return base64.b64encode(nonce + encrypted_password).decode()

# Function to create a user if it doesn't exist
def create_user(username):
    # Check if user already exists
    cursor.execute('SELECT UserID FROM Users WHERE Username = ?', (username,))
    user = cursor.fetchone()
    if user:
        return user[0]
    else:
        master_password_hash = base64.b64encode(b"dummy_hash").decode()
        master_password_salt = base64.b64encode(b"dummy_salt").decode()
        cursor.execute('''
        INSERT INTO Users (Username, MasterPasswordHash, MasterPasswordSalt)
        VALUES (?, ?, ?)
        ''', (username, master_password_hash, master_password_salt))
        conn.commit()
        return cursor.lastrowid

# Function to store the encrypted password and salt into the database
def store_encrypted_password(user_id, website_name, stored_username, encrypted_password, salt):
    cursor.execute('''
    INSERT INTO Passwords (UserID, WebsiteName, StoredUsername, EncryptedPassword, Salt)
    VALUES (?, ?, ?, ?, ?)
    ''', (user_id, website_name, stored_username, encrypted_password, base64.b64encode(salt).decode()))
    conn.commit()
    print("Password stored successfully.")

# Main function to handle user input and process encryption
def main():
    # Collect user input
    username = input("Enter your Username: ")
    website_name = input("Enter the Website Name: ")
    stored_username = input("Enter the Username for the stored account: ")
    plaintext_password = input("Enter the Password to store: ")

    # Create user if not exists and get user_id
    user_id = create_user(username)

    # Generate salt for encryption
    salt = generate_salt()

    # Generate encryption key using the generated salt
    encryption_key = generate_random_key(salt)

    # Encrypt the plaintext password
    encrypted_password = encrypt_plaintext_password(plaintext_password, encryption_key)

    # Store the encrypted password and salt in the database
    store_encrypted_password(user_id, website_name, stored_username, encrypted_password, salt)

    # Debug output to check stored data
    cursor.execute('SELECT * FROM Passwords')
    rows = cursor.fetchall()
    for row in rows:
        print(f"Debug: Stored row in Passwords - {row}")

    cursor.execute('SELECT * FROM Users')
    rows = cursor.fetchall()
    for row in rows:
        print(f"Debug: Stored row in Users - {row}")

if __name__ == "__main__":
    main()

conn.close()
