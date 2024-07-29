import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_salt():
    return os.urandom(16)

def hash_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def generate_encryption_key(master_password_hash, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(master_password_hash)

def encrypt_plaintext_password(plaintext_password, encryption_key):
    aesgcm = AESGCM(encryption_key)
    nonce = os.urandom(12)
    encrypted_password = aesgcm.encrypt(nonce, plaintext_password.encode(), None)
    return base64.b64encode(nonce + encrypted_password).decode()

def decrypt_encrypted_password(encrypted_password, encryption_key):
    encrypted_data = base64.b64decode(encrypted_password)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(encryption_key)
    decrypted_password = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted_password.decode()