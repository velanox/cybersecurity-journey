password = input()
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
else:
    print("Add at least one number.")
if has_lower == True:
   score = int(score+1)
if has_upper == True:
   score = int(score+1)
if has_digit == True:
   score = int(score+1)
if has_special == True:
   score = int(score+1)
if int(score)<= 2:
   print("weak password")
if int(score)== 3:
   print("good password")
if int(score) == 4:
   print("Strong password")
if int(score) == 5:
   print("very strong password")


        
           
