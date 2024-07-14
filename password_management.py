import sqlite3
import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class PasswordManager:
    def __init__(self, db_path='passwords.db'):
        self.db_path = db_path
        self._initialize_database()
    
    def _initialize_database(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER,
                    website TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    salt TEXT NOT NULL
                )
            ''')
            conn.commit()

    def _hash_password(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def _generate_encryption_key(self, hashed_password):
        return AESGCM.generate_key(bit_length=128)

    def _encrypt_password(self, password, key):
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        encrypted_password = aesgcm.encrypt(nonce, password.encode(), None)
        return base64.b64encode(nonce + encrypted_password).decode()

    def _decrypt_password(self, encrypted_password, key):
        data = base64.b64decode(encrypted_password.encode())
        nonce = data[:12]
        encrypted_password = data[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, encrypted_password, None).decode()

    def add_password(self, user_id, master_password, website, username, password):
        salt = os.urandom(16)
        hashed_password = self._hash_password(master_password, salt)
        encryption_key = self._generate_encryption_key(hashed_password)
        encrypted_password = self._encrypt_password(password, encryption_key)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO passwords (user_id, website, username, password, salt)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, website, username, encrypted_password, base64.b64encode(salt).decode()))
            conn.commit()

    def remove_password(self, user_id, website):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                DELETE FROM passwords
                WHERE user_id = ? AND website = ?
            ''', (user_id, website))
            conn.commit()

    def update_password(self, user_id, master_password, website, new_password):
        salt = os.urandom(16)
        hashed_password = self._hash_password(master_password, salt)
        encryption_key = self._generate_encryption_key(hashed_password)
        encrypted_password = self._encrypt_password(new_password, encryption_key)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE passwords
                SET password = ?, salt = ?
                WHERE user_id = ? AND website = ?
            ''', (encrypted_password, base64.b64encode(salt).decode(), user_id, website))
            conn.commit()

    def retrieve_password(self, user_id, master_password, website):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT username, password, salt
                FROM passwords
                WHERE user_id = ? AND website = ?
            ''', (user_id, website))
            result = cursor.fetchone()
            if result:
                username, encrypted_password, salt = result
                salt = base64.b64decode(salt)
                hashed_password = self._hash_password(master_password, salt)
                encryption_key = self._generate_encryption_key(hashed_password)
                decrypted_password = self._decrypt_password(encrypted_password, encryption_key)
                return username, decrypted_password
            else:
                return None
