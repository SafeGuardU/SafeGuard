import base64
from utils import hash_password

def authenticate_user(conn, username, master_password):
    cursor = conn.cursor()
# Execute an SQL query that retrieves the user ID, hashed password, and salt for the given username inputed
    cursor.execute('SELECT UserID, MasterPasswordHash, MasterPasswordSalt FROM Users WHERE Username = ?', (username,))
    row = cursor.fetchone()
    
# Check if a user with the provided username exists
    if row:
        user_id, stored_hash, stored_salt = row
        # Decode the stored hash and salt from Base64 format
        stored_hash = base64.b64decode(stored_hash)
        stored_salt = base64.b64decode(stored_salt)

        # Hash the entered master password using the stored salt
        entered_hash = hash_password(master_password, stored_salt)

        # Compare the entered hash with the stored hash
        if entered_hash == stored_hash:
            return user_id # Return the user ID if authentication is successful
        else:
            print("Master password verification failed.")
            return None # Return None if the password verification fails
    else:
        print("User not found.")
        return None # Return None if the user does not exist
