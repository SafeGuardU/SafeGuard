import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from utils import generate_salt, hash_password

def create_user(conn, username, master_password):
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) FROM Users WHERE Username = ?', (username,))
    count = cursor.fetchone()[0]

    if count > 0:
        print("Username already exists. Please choose a different username.")
        return

    salt = generate_salt()
    master_password_hash = hash_password(master_password, salt)
    cursor.execute('''
    INSERT INTO Users (Username, MasterPasswordHash, MasterPasswordSalt)
    VALUES (?, ?, ?)
    ''', (username, base64.b64encode(master_password_hash).decode(), base64.b64encode(salt).decode()))
    conn.commit()
    print("User created successfully.")