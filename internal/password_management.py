import base64
from internal.utils import generate_salt, generate_encryption_key, encrypt_plaintext_password

def update_password(conn, user_id, website_name, stored_username, new_password):
    cursor = conn.cursor()

    # Check if the password exists for the given website name and stored username
    cursor.execute('''
    SELECT COUNT(*)
    FROM Passwords
    WHERE UserID = ? AND WebsiteName = ? AND StoredUsername = ?
    ''', (user_id, website_name, stored_username))
    count = cursor.fetchone()[0]

    if count == 0:
        print("No password found for the given website name and stored username.")
        return

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

def delete_password(conn, user_id, website_name, stored_username):
    cursor = conn.cursor()

    cursor.execute('''
    DELETE FROM Passwords
    WHERE UserID = ? AND WebsiteName = ? AND StoredUsername = ?
    ''', (user_id, website_name, stored_username))
    conn.commit()
    print("Password deleted successfully.")
