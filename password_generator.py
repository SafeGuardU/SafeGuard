import string
import secrets

def generate_password(length, include_numbers, include_special_chars):
    # Character set includes both lowercase and uppercase letters by default
    character_set = string.ascii_letters
    
    # Add numbers if requested
    if include_numbers:
        character_set += string.digits
    
    # Add special characters if requested
    if include_special_chars:
        character_set += string.punctuation
    
    # Generate password using secure random choice
    password = ''.join(secrets.choice(character_set) for _ in range(length))
    
    return password
