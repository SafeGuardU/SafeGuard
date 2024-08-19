# Importing all relevant modules around encryption/decryption
import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_salt():
    # Returns a crypographically suitable string of 16 bits.
    return os.urandom(16)

def hash_password(password, salt):
    # Use PBKDF2 with SHA256 to derive a 32-byte key from the password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), #Use SHA-256 as the underlying hash function
        length=32, #Generates a 32-byte key
        salt=salt, #Use the provided salt value
        iterations=100000, #Perform 100,000 iterations to make brute-force attacks more difficult for bad actors
        backend=default_backend() #Use the default cryptographic backend
    )
    return kdf.derive(password.encode())

def generate_encryption_key(master_password_hash, salt):
    #Derive a 32-byte encryption key from the master password hash and salt using PBKDF2-HMAC-SHA256

    #Set up the key derivation function (KDF) using PBKDF2-HMAC-SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), #Use SHA-256 as the underlying hash function
        length=32, #Generates a 32-byte key
        salt=salt, #Use the provided salt value
        iterations=100000, #Perform 100,000 iterations to make brute-force attacks more difficult for bad actors
        backend=default_backend() #Use the default cryptographic backend
    )
    #return the encryption key from the master password hash
    return kdf.derive(master_password_hash)

def encrypt_plaintext_password(plaintext_password, encryption_key):
    # Encrypt the plaintext password using AES-GCM with a random 12-byte nonce
    aesgcm = AESGCM(encryption_key)
    nonce = os.urandom(12)
    encrypted_password = aesgcm.encrypt(nonce, plaintext_password.encode(), None)
    # Combine nonce and encrypted password, then base64 encode for storage
    return base64.b64encode(nonce + encrypted_password).decode()

def decrypt_encrypted_password(encrypted_password, encryption_key):
    # Decode the base64 encrypted password and extract the nonce and ciphertext
    encrypted_data = base64.b64decode(encrypted_password)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    # Decrypt the password using AES-GCM with the provided encryption key and nonce
    aesgcm = AESGCM(encryption_key)
    decrypted_password = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted_password.decode()
