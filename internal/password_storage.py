import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from internal.utils import generate_salt, generate_encryption_key, encrypt_plaintext_password

def store_encrypted_password(conn, user_id, website_name, stored_username, plaintext_password):
    cursor = conn.cursor()

    salt = generate_salt()
    cursor.execute('SELECT MasterPasswordHash FROM Users WHERE UserID = ?', (user_id,))
    stored_hash = cursor.fetchone()[0]
    stored_hash = base64.b64decode(stored_hash)
    encryption_key = generate_encryption_key(stored_hash, salt)
    encrypted_password = encrypt_plaintext_password(plaintext_password, encryption_key)
    cursor.execute('''
    INSERT INTO Passwords (UserID, WebsiteName, StoredUsername, EncryptedPassword, Salt)
    VALUES (?, ?, ?, ?, ?)
    ''', (user_id, website_name, stored_username, encrypted_password, base64.b64encode(salt).decode()))
    conn.commit()
    print("Password stored successfully.")
