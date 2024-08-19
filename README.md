# SafeGuard Password Manager

SafeGuard is a secure and user-friendly password manager built with Python. It provides a robust solution for storing, retrieving, and managing your passwords with strong encryption.

## Features

- User Registration and Login
- Master Password Protection
- Secure SQLite Database
  - Master Password hashing (SHA256)
  - Stored password encryption (AES256 with Salt)
- Password Storage
- Password Retrieval
- Password Generation with Complexity Options
- Password Updating
- Password Deletion

## Dependencies

- Python 3.x

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/safeguard-password-manager.git
   cd safeguard-password-manager
   ```

2. Install the required packages:
   ```
   pip3 install -r requirements.txt
   ```

## Usage

To run SafeGuard:

```
python safeguard.py
```

Follow the on-screen prompts to register, login, and manage your passwords.

## Security

SafeGuard takes your security seriously:

- Master passwords are hashed using SHA256 before storage.
- All stored passwords are encrypted using AES256 with a unique salt for each entry.
- The database is protected by the master password.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

While SafeGuard implements strong security measures, no system is 100% secure. Use at your own risk and always maintain backups of your important passwords.
