import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Function to create a random encryption key
def generate_random_key(salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(b"fixed_random_string")

# Function to decrypt the encrypted password using AES-256
def decrypt_encrypted_password(encrypted_password, encryption_key):
    encrypted_data = base64.b64decode(encrypted_password)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(encryption_key)
    decrypted_password = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted_password.decode()

# Function to retrieve and decrypt the password
def retrieve_password(username, website_name):
    filename = "encrypted_passwords.txt"
    
    try:
        with open(filename, "r") as file:
            lines = file.readlines()
            
            # Initialize variables to hold the extracted data
            current_username = ""
            current_website = ""
            encrypted_password = ""
            salt = ""
            
            # Read the file line by line
            for line in lines:
                if line.startswith("Username:"):
                    current_username = line.split(": ")[1].strip()
                elif line.startswith("Website:"):
                    current_website = line.split(": ")[1].strip()
                elif line.startswith("EncryptedPassword:"):
                    encrypted_password = line.split(": ")[1].strip()
                elif line.startswith("Salt:"):
                    salt = line.split(": ")[1].strip()
                    
                    # Check if we found the matching username and website
                    if current_username == username and current_website == website_name:
                        # Convert the base64-encoded salt back to bytes
                        salt_bytes = base64.b64decode(salt)
                        
                        # Generate the encryption key
                        encryption_key = generate_random_key(salt_bytes)
                        
                        # Decrypt the password
                        decrypted_password = decrypt_encrypted_password(encrypted_password, encryption_key)
                        
                        # Return the decrypted password
                        return decrypted_password
            
            # If no matching credentials are found
            return None
    
    except FileNotFoundError:
        print(f"The file {filename} does not exist.")
        return None

# Main function to handle user input and process decryption
def main():
    # Collect user input
    username = input("Enter your Username: ")
    website_name = input("Enter the Website Name: ")
    
    # Retrieve and decrypt the password
    decrypted_password = retrieve_password(username, website_name)
    
    if decrypted_password:
        print(f"The password for {username} on {website_name} is: {decrypted_password}")
    else:
        print("No matching credentials found.")

if __name__ == "__main__":
    main()
