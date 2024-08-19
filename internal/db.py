import sqlite3


def create_connection():
    # Connecting to the mentioned .db file
    conn = sqlite3.connect('password_manager.db')
    return conn

def create_tables(conn):
    cursor = conn.cursor()

    # Creating the "Users" table as outlined in the password manager documentation
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Users (
        UserID INTEGER PRIMARY KEY AUTOINCREMENT,
        Username TEXT NOT NULL,
        MasterPasswordHash TEXT NOT NULL,
        MasterPasswordSalt TEXT NOT NULL
    )
    ''')

    # Creating the "Passwords" table as outlined in the password manager documentation
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Passwords (
        PasswordID INTEGER PRIMARY KEY AUTOINCREMENT,
        UserID INTEGER,
        WebsiteName TEXT NOT NULL,
        StoredUsername TEXT NOT NULL,
        EncryptedPassword TEXT NOT NULL,
        Salt TEXT NOT NULL,
        FOREIGN KEY (UserID) REFERENCES Users (UserID)
    )
    ''')

    conn.commit()
