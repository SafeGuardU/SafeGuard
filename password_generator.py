import string
import random

def generate_password(length, complexity):
    if complexity == "low":
        character_set = string.ascii_lowercase + string.digits
    elif complexity == "medium":
        character_set = string.ascii_letters + string.digits
    else:  # high complexity
        character_set = string.ascii_letters + string.digits + string.punctuation

    password = ''.join(random.choice(character_set) for _ in range(length))
    return password