import re
import math

def assess_password_strength(password):
    if len(password) < 8:
        return "Weak Password", None

    uppercase_criteria = any(char.isupper() for char in password)
    lowercase_criteria = any(char.islower() for char in password)
    digit_criteria = any(char.isdigit() for char in password)
    special_char_criteria = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

    if not (uppercase_criteria and lowercase_criteria and digit_criteria and special_char_criteria):
        return "Weak Password", None

    character_set = 0
    if uppercase_criteria:
        character_set += 26
    if lowercase_criteria:
        character_set += 26
    if digit_criteria:
        character_set += 10
    if special_char_criteria:
        character_set += 32

    entropy = math.log2(character_set ** len(password))
    time_to_crack_seconds = 0.5 * (2 ** entropy)

    time_units = [
        (60, "second"),
        (60, "minute"),
        (24, "hour"),
        (30, "day"),
        (12, "month"),
        (1000000000, "year")
    ]

    for i in range(len(time_units) - 1):
        unit_seconds, unit_name = time_units[i]
        next_unit_seconds, next_unit_name = time_units[i + 1]
        if time_to_crack_seconds < next_unit_seconds:
            time_to_crack = time_to_crack_seconds / unit_seconds
            if time_to_crack < 2:
                return "Strong Password", f"{time_to_crack:.2f} {unit_name}"
            else:
                return "Strong Password", f"{time_to_crack:.0f} {unit_name}s"

    return "Strong Password", f"{time_to_crack_seconds:.0f} seconds"

def main():
    password = input("Enter your password: ")
    strength, time_to_crack = assess_password_strength(password)
    print(f"Password strength: {strength}, Time to crack: {time_to_crack}")

if __name__ == "__main__":
    main()
