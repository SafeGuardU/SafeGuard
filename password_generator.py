import string
import random

def generate_password(length, include_numbers, include_special_chars):
    character_set = string.ascii_lowercase
    
    if include_numbers:
        character_set += string.digits
    
    if include_special_chars:
        character_set += string.punctuation
    
    # Ensure there's always a mix of the chosen character sets in the password
    password = ''.join(random.choice(character_set) for _ in range(length))
    
    return password
