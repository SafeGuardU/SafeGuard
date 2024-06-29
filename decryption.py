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

# Function to decrypt the encrypted password using AES-256
def decrypt_encrypted_password(encrypted_password, encryption_key):
    encrypted_data = base64.b64decode(encrypted_password)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(encryption_key)
    decrypted_password = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted_password.decode()

# Function to retrieve and decrypt the password
def retrieve_password(username, website_name, stored_username, master_password):
    cursor.execute('''
    SELECT p.EncryptedPassword, p.Salt, u.MasterPasswordHash, u.MasterPasswordSalt
    FROM Passwords p
    JOIN Users u ON p.UserID = u.UserID
    WHERE LOWER(u.Username) = ? AND LOWER(p.WebsiteName) = ? AND LOWER(p.StoredUsername) = ?
    ''', (username.lower(), website_name.lower(), stored_username.lower()))
    
    row = cursor.fetchone()
    
    if row:
        encrypted_password, salt, stored_hash, stored_salt = row
        stored_hash = base64.b64decode(stored_hash)
        stored_salt = base64.b64decode(stored_salt)
        salt_bytes = base64.b64decode(salt)

        # Verify the entered master password
        entered_hash = hash_password(master_password, stored_salt)

        # Debug information
        print(f"Debug: Stored hash: {stored_hash}")
        print(f"Debug: Entered hash: {entered_hash}")
        print(f"Debug: Stored salt: {stored_salt}")

        if entered_hash != stored_hash:
            print("Master password verification failed.")
            return None
        
        encryption_key = generate_encryption_key(stored_hash, salt_bytes)
        decrypted_password = decrypt_encrypted_password(encrypted_password, encryption_key)
        return decrypted_password
    else:
        return None

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

# Main function to handle user input and process decryption
def main():
    # Collect user input
    username = input("Enter your Username: ")
    master_password = input("Enter your Master Password: ")
    website_name = input("Enter the Website Name: ")
    stored_username = input("Enter the Username for the stored account: ")
    
    print(f"Debug: Inputs - Username: {username}, Website: {website_name}, StoredUsername: {stored_username}")
    
    # Retrieve and decrypt the password
    decrypted_password = retrieve_password(username, website_name, stored_username, master_password)
    
    if decrypted_password:
        print(f"The password for {stored_username} on {website_name} is: {decrypted_password}")
    else:
        print("No matching credentials found.")

    # Debug output to check stored data in Passwords table
    cursor.execute('SELECT * FROM Passwords')
    rows = cursor.fetchall()
    for row in rows:
        print(f"Debug: Stored row in Passwords - {row}")

    # Debug output to check stored data in Users table
    cursor.execute('SELECT * FROM Users')
    rows = cursor.fetchall()
    for row in rows:
        print(f"Debug: Stored row in Users - {row}")

if __name__ == "__main__":
    main()

conn.close()
