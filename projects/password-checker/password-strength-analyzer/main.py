password = input("enter your password:")
special_characters = "!@#$%^&*()_-+=<>?/\\|{}[]"
score = 0
has_upper = False 
has_lower = False 
has_digit = False
has_special = False 
if len(password) >= 8:
    for char in password:
       if char .isupper():
          has_upper = True
       if char .islower():
          has_lower = True
       if char .isdigit():
          has_digit = True 
       if char in special_characters:
          has_special = True 
    print("Password Analysis:")
    print("------------------")
    if has_lower:
       score += 1
       print("✔ Lowercase")
    else:
        print("✘ Lowercase")
    if has_upper:
       score += 1
       print("✔ Uppercase")
    else:
       print("✘ Uppercase")
    if has_digit:
       score += 1
       print("✔ Number")
    else:
       print("✘ Number")
    if has_special:
       score += 1
       print("✔ Special character")
    else:
       print("✘ Special character")
    print()
    print("score:",score,"/4")
    print()
    if score<= 2:
       print("weak password")
    elif score== 3:
       print("good password")
    else:
       print("Strong password")
else:
    print("password is too short!")



        
           
