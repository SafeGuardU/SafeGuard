import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Function to generate a random salt
def generate_salt():
    return os.urandom(16)

# Function to create a random encryption key
def generate_random_key(salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    # Using a fixed random string as a key source for prototype purposes
    return kdf.derive(b"fixed_random_string")

# Function to encrypt the plaintext password using AES-256
def encrypt_plaintext_password(plaintext_password, encryption_key):
    aesgcm = AESGCM(encryption_key)
    nonce = os.urandom(12)  # AES-GCM nonce
    encrypted_password = aesgcm.encrypt(nonce, plaintext_password.encode(), None)
    return base64.b64encode(nonce + encrypted_password).decode()

# Function to store the encrypted password, salt, username, and website name into a text file
def store_encrypted_password(username, website_name, encrypted_password, salt):
    filename = "encrypted_passwords.txt"
    with open(filename, "a") as file:
        file.write(f"Username: {username}\n")
        file.write(f"Website: {website_name}\n")
        file.write(f"EncryptedPassword: {encrypted_password}\n")
        file.write(f"Salt: {base64.b64encode(salt).decode()}\n")
        file.write("\n")  # New line to separate entries
    print("Password stored successfully.")

# Main function to handle user input and process encryption
def main():
    # Collect user input
    username = input("Enter your Usernamee: ")
    website_name = input("Enter the Website Name: ")
    plaintext_password = input("Enter the Password to store: ")

    # Generate salt for encryption
    salt = generate_salt()

    # Generate encryption key using the generated salt
    encryption_key = generate_random_key(salt)

    # Encrypt the plaintext password
    encrypted_password = encrypt_plaintext_password(plaintext_password, encryption_key)

    # Store the encrypted password, salt, username, and website name in a text file
    store_encrypted_password(username, website_name, encrypted_password, salt)

if __name__ == "__main__":
    main()