import random
import string


def generate_password(length=15):
    
    # Define character sets for password generation
    lowercase_letters = string.ascii_lowercase
    uppercase_letters = string.ascii_uppercase
    digits = string.digits
    symbols = string.punctuation
    
    # Combine all character sets
    all_characters = lowercase_letters + uppercase_letters + digits + symbols
    
    # Generate a password with at least one character from each character set
    password = random.choice(lowercase_letters) + random.choice(uppercase_letters) + random.choice(digits) + random.choice(symbols)
    
    # Fill the rest of the password with random characters from all_characters
    password += ''.join(random.choice(all_characters) for _ in range(length - 4))
    
    # Shuffle the password to make it more random
    password_list = list(password)
    random.shuffle(password_list)
    password = ''.join(password_list)
    
    return password


# Example usage
password = generate_password()
print("Generated Password:", password)
