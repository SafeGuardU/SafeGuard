import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from internal.utils import generate_salt, hash_password

#Creates a new user in the database with a unique username and a securely hashed master password
def create_user(conn, username, master_password):
    cursor = conn.cursor()

    # Check if the username already exists in the database
    cursor.execute('SELECT COUNT(*) FROM Users WHERE Username = ?', (username,))
    count = cursor.fetchone()[0]

    if count > 0:
        return "Username already exists. Please choose a different username."

    # Check password complexity
    if len(master_password) < 8:
        return "Password must be at least 8 characters long."

    # Generates a unique salt for the user
    salt = generate_salt()
    master_password_hash = hash_password(master_password, salt)

    # Registers the new user into the database with the hashed password and salt
    cursor.execute('''
    INSERT INTO Users (Username, MasterPasswordHash, MasterPasswordSalt)
    VALUES (?, ?, ?)
    ''', (username, base64.b64encode(master_password_hash).decode(), base64.b64encode(salt).decode()))

    # Saves the changes to the database
    conn.commit()
    return True
