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

# Function to hash a password with a given salt
def hash_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Function to create an encryption key based on a master password hash and a salt
def generate_encryption_key(master_password_hash, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(master_password_hash)

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
        master_password = "dummy_password"
        fixed_salt = b"fixed_salt"
        master_password_hash = hash_password(master_password, fixed_salt)
        cursor.execute('''
        INSERT INTO Users (Username, MasterPasswordHash, MasterPasswordSalt)
        VALUES (?, ?, ?)
        ''', (username, base64.b64encode(master_password_hash).decode(), base64.b64encode(fixed_salt).decode()))
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
    master_password = input("Enter your Master Password: ")
    website_name = input("Enter the Website Name: ")
    stored_username = input("Enter the Username for the stored account: ")
    plaintext_password = input("Enter the Password to store: ")

    # Create user if not exists and get user_id
    user_id = create_user(username)

    # Retrieve the stored master password hash and salt
    cursor.execute('SELECT MasterPasswordHash, MasterPasswordSalt FROM Users WHERE UserID = ?', (user_id,))
    stored_hash, stored_salt = cursor.fetchone()
    stored_hash = base64.b64decode(stored_hash)
    stored_salt = base64.b64decode(stored_salt)

    # Verify the entered master password
    entered_hash = hash_password(master_password, stored_salt)
    
    # Debug information
    print(f"Debug: Stored hash: {stored_hash}")
    print(f"Debug: Entered hash: {entered_hash}")
    print(f"Debug: Stored salt: {stored_salt}")

    if entered_hash != stored_hash:
        print("Master password verification failed.")
        return

    # Generate salt for encryption
    salt = generate_salt()

    # Generate encryption key using the master password hash and the newly generated salt
    encryption_key = generate_encryption_key(stored_hash, salt)

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
