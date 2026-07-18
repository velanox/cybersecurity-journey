# Password Strength Analyzer

A simple Python project that analyzes the strength of a password based on common security rules.

## Features

* Checks password length (minimum 8 characters)
* Detects uppercase letters
* Detects lowercase letters
* Detects numbers
* Detects special characters
* Displays a detailed password analysis
* Calculates a security score (/4)
* Classifies the password as:

  * Weak
  * Good
  * Strong

## Technologies

* Python 3

## Concepts Practiced

This project helped me practice:

* Variables
* Boolean values
* Conditional statements (`if`, `elif`, `else`)
* `for` loops
* String methods
* Membership operator (`in`)
* Code organization
* Basic algorithm design

## How to Run

```bash
python main.py
```

Then enter a password when prompted.

## Example Output

```text
Password Analysis
-----------------
✔ Lowercase
✔ Uppercase
✔ Number
✔ Special character

Score: 4/4

Strong password
```

## Author

Created by Velanox as part of my Cybersecurity Journey.
## Future Improvements

- Add password entropy calculation
- Detect common passwords
- Generate security recommendations
- Export analysis results
- Build a graphical user interface (GUI)