password = input("Enter a password: ")

if len(password) >= 8:
    if any(char.isdigit() for char in password):
        print("Strong password.")
    else:
        print("Add at least one number.")
else:
    print("Password is too short.")