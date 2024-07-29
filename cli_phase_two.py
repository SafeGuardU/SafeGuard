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

# Function to decrypt the encrypted password using AES-256
def decrypt_encrypted_password(encrypted_password, encryption_key):
    encrypted_data = base64.b64decode(encrypted_password)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(encryption_key)
    decrypted_password = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted_password.decode()

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

        if entered_hash != stored_hash:
            print("Master password verification failed.")
            return None
        
        encryption_key = generate_encryption_key(stored_hash, salt_bytes)
        decrypted_password = decrypt_encrypted_password(encrypted_password, encryption_key)
        return decrypted_password
    else:
        return None

# Function to update an existing password
def update_password(user_id, website_name, stored_username, new_password):
    salt = generate_salt()
    cursor.execute('SELECT MasterPasswordHash FROM Users WHERE UserID = ?', (user_id,))
    stored_hash = cursor.fetchone()[0]
    stored_hash = base64.b64decode(stored_hash)
    encryption_key = generate_encryption_key(stored_hash, salt)
    encrypted_password = encrypt_plaintext_password(new_password, encryption_key)
    cursor.execute('''
    UPDATE Passwords
    SET EncryptedPassword = ?, Salt = ?
    WHERE UserID = ? AND WebsiteName = ? AND StoredUsername = ?
    ''', (encrypted_password, base64.b64encode(salt).decode(), user_id, website_name, stored_username))
    conn.commit()
    print("Password updated successfully.")

# Function to delete a password
def delete_password(user_id, website_name, stored_username):
    cursor.execute('''
    DELETE FROM Passwords
    WHERE UserID = ? AND WebsiteName = ? AND StoredUsername = ?
    ''', (user_id, website_name, stored_username))
    conn.commit()
    print("Password deleted successfully.")

# Main function to handle user input and process encryption, decryption, updating, and deleting passwords
def main():
    while True:
        print("\nPassword Manager")
        print("1. Store a new password")
        print("2. Retrieve a password")
        print("3. Update a password")
        print("4. Delete a password")
        print("5. Exit")
        choice = input("Enter your choice (1-5): ")

        if choice == '1':
            # Store a new password
            username = input("Enter your Username: ")
            master_password = input("Enter your Master Password: ")
            website_name = input("Enter the Website Name: ")
            stored_username = input("Enter the Username for the stored account: ")
            plaintext_password = input("Enter the Password to store: ")

            user_id = create_user(username)

            cursor.execute('SELECT MasterPasswordHash, MasterPasswordSalt FROM Users WHERE UserID = ?', (user_id,))
            stored_hash, stored_salt = cursor.fetchone()
            stored_hash = base64.b64decode(stored_hash)
            stored_salt = base64.b64decode(stored_salt)

            entered_hash = hash_password(master_password, stored_salt)

            if entered_hash != stored_hash:
                print("Master password verification failed.")
                continue

            salt = generate_salt()
            encryption_key = generate_encryption_key(stored_hash, salt)
            encrypted_password = encrypt_plaintext_password(plaintext_password, encryption_key)
            store_encrypted_password(user_id, website_name, stored_username, encrypted_password, salt)

        elif choice == '2':
            # Retrieve a password
            username = input("Enter your Username: ")
            master_password = input("Enter your Master Password: ")
            website_name = input("Enter the Website Name: ")
            stored_username = input("Enter the Username for the stored account: ")

            decrypted_password = retrieve_password(username, website_name, stored_username, master_password)

            if decrypted_password:
                print(f"The password for {stored_username} on {website_name} is: {decrypted_password}")
            else:
                print("No matching credentials found.")

        elif choice == '3':
            # Update a password
            username = input("Enter your Username: ")
            master_password = input("Enter your Master Password: ")
            website_name = input("Enter the Website Name: ")
            stored_username = input("Enter the Username for the stored account: ")
            new_password = input("Enter the new password: ")

            cursor.execute('SELECT UserID FROM Users WHERE Username = ?', (username,))
            user_id = cursor.fetchone()[0]

            cursor.execute('SELECT MasterPasswordHash, MasterPasswordSalt FROM Users WHERE UserID = ?', (user_id,))
            stored_hash, stored_salt = cursor.fetchone()
            stored_hash = base64.b64decode(stored_hash)
            stored_salt = base64.b64decode(stored_salt)

            entered_hash = hash_password(master_password, stored_salt)

            if entered_hash != stored_hash:
                print("Master password verification failed.")
                continue

            update_password(user_id, website_name, stored_username, new_password)

        elif choice == '4':
            # Delete a password
            username = input("Enter your Username: ")
            master_password = input("Enter your Master Password: ")
            website_name = input("Enter the Website Name: ")
            stored_username = input("Enter the Username for the stored account: ")

            cursor.execute('SELECT UserID FROM Users WHERE Username = ?', (username,))
            user_id = cursor.fetchone()[0]

            cursor.execute('SELECT MasterPasswordHash, MasterPasswordSalt FROM Users WHERE UserID = ?', (user_id,))
            stored_hash, stored_salt = cursor.fetchone()
            stored_hash = base64.b64decode(stored_hash)
            stored_salt = base64.b64decode(stored_salt)

            entered_hash = hash_password(master_password, stored_salt)

            if entered_hash != stored_hash:
                print("Master password verification failed.")
                continue

            delete_password(user_id, website_name, stored_username)

        elif choice == '5':
            # Exit the program
            break

        else:
            print("Invalid choice. Please try again.")

    conn.close()

if __name__ == "__main__":
    main()