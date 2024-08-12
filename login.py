import base64
from utils import hash_password
# Got to annotate (Lachlan)
def authenticate_user(conn, username, master_password):
    cursor = conn.cursor()

    cursor.execute('SELECT UserID, MasterPasswordHash, MasterPasswordSalt FROM Users WHERE Username = ?', (username,))
    row = cursor.fetchone()

    if row:
        user_id, stored_hash, stored_salt = row
        stored_hash = base64.b64decode(stored_hash)
        stored_salt = base64.b64decode(stored_salt)

        entered_hash = hash_password(master_password, stored_salt)

        if entered_hash == stored_hash:
            return user_id
        else:
            print("Master password verification failed.")
            return None
    else:
        print("User not found.")
        return None
