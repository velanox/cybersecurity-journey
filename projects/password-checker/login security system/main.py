import hashlib
import hmac
import os
import sys
import json
import logging

# --- Masked password input: works on Windows (msvcrt) and Unix (termios) ---
try:
    import msvcrt  # Available only on Windows

    def get_masked_password(prompt="Password: "):
        print(prompt, end="", flush=True)
        password = ""
        while True:
            char = msvcrt.getch()
            if char in (b"\r", b"\n"):
                print()
                break
            elif char == b"\x08":  # Backspace
                if password:
                    password = password[:-1]
                    print("\b \b", end="", flush=True)
            else:
                password += char.decode("utf-8", errors="ignore")
                print("*", end="", flush=True)
        return password

except ImportError:
    import termios
    import tty

    def get_masked_password(prompt="Password: "):
        # Fallback for non-interactive stdin (e.g. automated tests, pipes)
        if not sys.stdin.isatty():
            return input(prompt)

        print(prompt, end="", flush=True)
        password = ""
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while True:
                char = sys.stdin.read(1)
                if char in ("\r", "\n"):
                    print()
                    break
                elif char == "\x7f":  # Backspace
                    if password:
                        password = password[:-1]
                        sys.stdout.write("\b \b")
                        sys.stdout.flush()
                else:
                    password += char
                    sys.stdout.write("*")
                    sys.stdout.flush()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return password


# --- Logging setup ---
logging.basicConfig(
    filename="auth.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

SPECIAL_CHARACTERS = "!@#$%^&*()_-+=<>?/\\|{}[]"
ACCOUNTS_FILE = "accounts.json"

# PBKDF2 parameters
HASH_ALGORITHM = "sha256"
ITERATIONS = 200_000
SALT_SIZE = 16
MAX_LOGIN_ATTEMPTS = 3

# Dictionary: {username: (salt_bytes, password_hash_bytes)}
accounts = {}


def hash_password(password, salt=None):
    """Turn a plain password into a (salt, hash) pair using PBKDF2."""
    if salt is None:
        salt = os.urandom(SALT_SIZE)

    password_hash = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode("utf-8"),
        salt,
        ITERATIONS,
    )
    return salt, password_hash


def load_accounts():
    """Load accounts from disk into memory at program start."""
    global accounts
    if not os.path.exists(ACCOUNTS_FILE):
        accounts = {}
        return

    with open(ACCOUNTS_FILE, "r") as f:
        raw_data = json.load(f)

    accounts = {
        username: (bytes.fromhex(entry["salt"]), bytes.fromhex(entry["hash"]))
        for username, entry in raw_data.items()
    }


def save_accounts():
    """Persist the current accounts dictionary to disk as JSON."""
    raw_data = {
        username: {"salt": salt.hex(), "hash": pw_hash.hex()}
        for username, (salt, pw_hash) in accounts.items()
    }
    with open(ACCOUNTS_FILE, "w") as f:
        json.dump(raw_data, f, indent=2)


def ask_username():
    """Ask for a valid username (>=4 characters, not already taken)."""
    while True:
        username = input("Choose a username (min 4 characters): ").strip()
        if len(username) < 4:
            print("X Username must contain at least 4 characters.")
            continue
        if username in accounts:
            print("X This username is already taken.")
            continue
        return username


def ask_password():
    """Ask for a valid password (>=8 chars, upper, lower, digit, special)."""
    while True:
        password = get_masked_password(
            "Choose a password (min 8 characters, "
            "1 uppercase, 1 lowercase, 1 digit, 1 special): "
        )

        if len(password) < 8:
            print("X Password must contain at least 8 characters.")
            continue

        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in SPECIAL_CHARACTERS for c in password)

        if not has_upper:
            print("X Password must contain at least one uppercase letter.")
        elif not has_lower:
            print("X Password must contain at least one lowercase letter.")
        elif not has_digit:
            print("X Password must contain at least one digit.")
        elif not has_special:
            print("X Password must contain at least one special character.")
        else:
            return password


def register():
    username = ask_username()
    password = ask_password()

    salt, password_hash = hash_password(password)
    accounts[username] = (salt, password_hash)
    save_accounts()

    print(f" Welcome {username}, your account has been created successfully!")
    logging.info(f"New account registered: {username}")


def login():
    username = input("Username: ").strip()

    if username not in accounts:
        print("X This username does not exist.")
        logging.warning(f"Login attempt with unknown username: {username}")
        return

    stored_salt, stored_hash = accounts[username]

    for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
        password = get_masked_password("Password: ")
        _, attempt_hash = hash_password(password, salt=stored_salt)

        if hmac.compare_digest(attempt_hash, stored_hash):
            print(f" Welcome back, {username}!")
            logging.info(f"Successful login: {username}")
            return

        remaining = MAX_LOGIN_ATTEMPTS - attempt
        if remaining > 0:
            print(f"X Incorrect password. {remaining} attempt(s) remaining.")
        else:
            print("X Too many failed attempts.")

    logging.warning(f"Failed login (wrong password, max attempts reached): {username}")


def main():
    load_accounts()

    print("Already have an account? type: /login")
    print("Don't have an account? type: /register")
    print("(type /quit to exit)\n")

    while True:
        choice = input("> ").strip()

        if choice == "/register":
            register()
        elif choice == "/login":
            login()
        elif choice == "/quit":
            print("See you soon!")
            break
        else:
            print("X Unknown command. Use /register, /login or /quit.")


if __name__ == "__main__":
    main()
