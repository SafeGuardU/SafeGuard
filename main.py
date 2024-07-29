from db import create_connection, create_tables
from registration import create_user
from login import authenticate_user
from password_storage import store_encrypted_password
from password_retrieval import retrieve_password
from password_generator import generate_password
from password_management import update_password, delete_password

def main():
    conn = create_connection()
    create_tables(conn)

    while True:
        print("\nPassword Manager")
        print("1. Sign Up")
        print("2. Login")
        print("3. Exit")
        choice = input("Enter your choice (1-3): ")

        if choice == '1':
            username = input("Enter a username: ")
            master_password = input("Enter a master password: ")
            create_user(conn, username, master_password)

        elif choice == '2':
            username = input("Enter your username: ")
            master_password = input("Enter your master password: ")
            user_id = authenticate_user(conn, username, master_password)

            if user_id:
                print("Login successful.")

                while True:
                    print("\nPassword Manager")
                    print("1. Store a new password")
                    print("2. Retrieve a password")
                    print("3. Update a password")
                    print("4. Delete a password")
                    print("5. Generate a password")
                    print("6. Logout")
                    choice = input("Enter your choice (1-6): ")

                    if choice == '1':
                        website_name = input("Enter the Website Name: ")
                        stored_username = input("Enter the Username for the stored account: ")
                        plaintext_password = input("Enter the Password to store: ")
                        store_encrypted_password(conn, user_id, website_name, stored_username, plaintext_password)

                    elif choice == '2':
                        website_name = input("Enter the Website Name: ")
                        stored_username = input("Enter the Username for the stored account: ")
                        decrypted_password = retrieve_password(conn, user_id, website_name, stored_username)

                        if decrypted_password:
                            print(f"The password for {stored_username} on {website_name} is: {decrypted_password}")
                        else:
                            print("No matching credentials found.")

                    elif choice == '3':
                        website_name = input("Enter the Website Name: ")
                        stored_username = input("Enter the Username for the stored account: ")
                        new_password = input("Enter the new password: ")
                        update_password(conn, user_id, website_name, stored_username, new_password)

                    elif choice == '4':
                        website_name = input("Enter the Website Name: ")
                        stored_username = input("Enter the Username for the stored account: ")
                        delete_password(conn, user_id, website_name, stored_username)

                    elif choice == '5':
                        length = int(input("Enter the desired password length: "))
                        complexity = input("Enter the desired password complexity (low/medium/high): ")
                        generated_password = generate_password(length, complexity)
                        print("Generated Password:", generated_password)

                    elif choice == '6':
                        print("Logged out successfully.")
                        break

                    else:
                        print("Invalid choice. Please try again.")

            else:
                print("Login failed.")

        elif choice == '3':
            break

        else:
            print("Invalid choice. Please try again.")

    conn.close()

if __name__ == "__main__":
    main()