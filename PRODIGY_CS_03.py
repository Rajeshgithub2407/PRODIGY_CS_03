import re

def assess_password_strength(password):
    # Criteria for password strength
    length_criteria = len(password) >= 8
    uppercase_criteria = re.search(r'[A-Z]', password) is not None
    lowercase_criteria = re.search(r'[a-z]', password) is not None
    digit_criteria = re.search(r'\d', password) is not None
    special_char_criteria = re.search(r'[!@#$%^&*(),.?":{}|<>]', password) is not None

    # Count how many criteria are met
    criteria_met = sum([length_criteria, uppercase_criteria, lowercase_criteria, digit_criteria, special_char_criteria])

    # Assess password strength
    if criteria_met == 5:
        strength = "Very Strong"
    elif criteria_met == 4:
        strength = "Strong"
    elif criteria_met == 3:
        strength = "Medium"
    elif criteria_met == 2:
        strength = "Weak"
    else:
        strength = "Very Weak"

    # Provide feedback
    feedback = []
    if not length_criteria:
        feedback.append("Password should be at least 8 characters long.")
    if not uppercase_criteria:
        feedback.append("Password should include at least one uppercase letter.")
    if not lowercase_criteria:
        feedback.append("Password should include at least one lowercase letter.")
    if not digit_criteria:
        feedback.append("Password should include at least one digit.")
    if not special_char_criteria:
        feedback.append("Password should include at least one special character (e.g., !@#$%^&*).")

    return strength, feedback

def main():
    while True:
        print("Password Strength Assessment Tool")
        password = input("Enter a password to assess its strength (or 'exit' to quit): ")

        if password.lower() == 'exit':
            print("Exiting the program.")
            break

        strength, feedback = assess_password_strength(password)
        print(f"Password Strength: {strength}")
        if feedback:
            print("Feedback:")
            for item in feedback:
                print(f"- {item}")
        print()

if __name__ == "__main__":
    main()
