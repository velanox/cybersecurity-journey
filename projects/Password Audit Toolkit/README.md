#  Password Audit Toolkit

An educational command-line toolkit for exploring password security, password hashing, and common password auditing techniques.

>  This project was developed **for educational purposes only**. It is designed to help understand how password attacks work in ethical hacking and cybersecurity training.

---

# Features

- Interactive CLI interface
- Multiple hashing algorithms
    - MD5
    - SHA-1
    - SHA-256
    - SHA-384
    - SHA-512
    - SHA3
    - Blake2

- Multiple hashing modes
    - Standard hashing
    - Salted hashing
    - Salted + stretched hashing

- Hash generation

- Dictionary attack

- Automatic benchmark

- Adaptive hash-rate calibration

- Estimated attack duration before execution

- Modular command system

---

# Project Structure

```
Password-Audit-Toolkit/

├── hash_cracker.py
├── wordlists/
│   ├── common.txt
│   └── ...
└── README.md
```

---

# Installation

Clone the repository

```bash
git clone https://github.com/velanox/cybersecurity-journey.git
```

Move into the project

```bash
cd cybersecurity-journey/projects/password-audit-toolkit
```

Run

```bash
python3 hash_cracker.py
```

---

# Available Commands

| Command | Description |
|----------|-------------|
| `/help` | Show help menu |
| `/algo` | Select hashing algorithm |
| `/mode` | Select hashing mode |
| `/hash <text>` | Generate a hash |
| `/dict <hash> <wordlist>` | Launch dictionary attack |
| `/quit` | Exit program |

---

# Example

Generate a hash

```
/algo sha256

/hash password123
```

Launch a dictionary attack

```
/dict ef92b778bafe771e89245b89ecbc08a44... wordlists/common.txt
```

The toolkit will automatically

- calibrate your machine
- estimate attack duration
- ask for confirmation
- execute the attack
- display benchmark statistics

---

# Educational Concepts

This project demonstrates

- Cryptographic hashing
- Salting
- Hash stretching
- Password storage
- Dictionary attacks
- Benchmarking
- Hash-rate estimation
- Command-Line Interface (CLI) design

---

# Current Limitations

Currently implemented

- Dictionary attack

Planned

- Rule-based attack
- Mask attack
- Guided brute-force attack
- Rainbow table attack
- Performance comparison
- Exportable benchmark reports

---

# Disclaimer

This software is intended **only for educational purposes** and for testing systems that you own or are explicitly authorized to audit.

The author is not responsible for any misuse of this software.

---

# Future Improvements

- Multi-threading
- GPU benchmark support
- Larger built-in wordlists
- Session management
- Plugin attack system
- Colored terminal output
- Progress bar
- Resume interrupted attacks

---

# License

MIT License