import base64
from utils import generate_encryption_key, decrypt_encrypted_password

def retrieve_password(conn, user_id, website_name, stored_username):
    cursor = conn.cursor()

    cursor.execute('''
    SELECT p.EncryptedPassword, p.Salt, u.MasterPasswordHash, u.MasterPasswordSalt
    FROM Passwords p
    JOIN Users u ON p.UserID = u.UserID
    WHERE p.UserID = ? AND LOWER(p.WebsiteName) = ? AND LOWER(p.StoredUsername) = ?
    ''', (user_id, website_name.lower(), stored_username.lower()))
    
    row = cursor.fetchone()
    
    if row:
        encrypted_password, salt, stored_hash, stored_salt = row
        stored_hash = base64.b64decode(stored_hash)
        stored_salt = base64.b64decode(stored_salt)
        salt_bytes = base64.b64decode(salt)
        
        encryption_key = generate_encryption_key(stored_hash, salt_bytes)
        decrypted_password = decrypt_encrypted_password(encrypted_password, encryption_key)
        return decrypted_password
    else:
        return None
