import sqlite3
import bcrypt
from cryptography.fernet import Fernet
from rich import style
from generate_key import load_key
from rich.console import Console
from rich.table import Table


conn = sqlite3.connect("users.db")
cursor = conn.cursor()


# create user table
cursor.execute(""" 
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT
)
""")

# create products table
cursor.execute("""
    CREATE TABLE IF NOT EXISTS product_passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        password TEXT NOT NULL,
        user_id INTEGER,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
""")
conn.commit()


def user_exists(username):
    cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    return cursor.fetchone() is not None


def register_user():
    print("Register a new user")
    username = input("Enter a new username: ")

    if user_exists(username):
        print("username already exists. Pease choose another one.")
        return

    password = input("Enter a new password: ")
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        conn.commit()
        print(f"User {username} registered succesfully")
    except sqlite3.IntegrityError:
        print("Error: Username already exists")


def store_product_password(user_id):
    print("Store a new product password")
    key = load_key()
    cipher_suite = Fernet(key)

    product_name = input("Enter a product name: ")
    product_password = input("Enter a product password: ")

    encrypted_password = cipher_suite.encrypt(product_password.encode("utf-8"))

    cursor.execute(
        """
        INSERT into product_passwords (name, password, user_id)
        VALUES (?, ?, ?)
        """,
        (product_name, encrypted_password, user_id),
    )
    conn.commit()
    print(f"Product password for {product_name} has been stored succesfully.")


def retrieve_product_passwords(user_id):
    print("Your stored product passwords:")
    cursor.execute(
        """ 
        SELECT name, password FROM product_passwords where user_id = ?  
    """,
        (user_id,),
    )
    rows = cursor.fetchall()
    key = load_key()
    cipher_suite = Fernet(key)
    table = Table(title="Passwords")

    table.add_column("Product Name", justify="right", style="cyan", no_wrap=True)
    table.add_column("Password", style="magenta")

    if rows:
        for row in rows:
            # table.add_row(
            #    f"Product: {row[0]}, password: {cipher_suite.decrypt(row[1]).decode('utf-8')}"
            ###)
            table.add_row(row[0], cipher_suite.decrypt(row[1]).decode("utf-8"))
        console = Console()
        console.print(table)
    else:
        print("No product password found")


def authenticate_user():
    print("Log in to your account")

    username = input("Enter username: ")

    if not user_exists(username):
        print("User not found. Please register first")
        return False

    password = input("Enter a password: ")

    cursor.execute(
        "SELECT id, password_hash FROM users WHERE username = ?", (username,)
    )
    result = cursor.fetchone()
    print(result)
    user_id, stored_password_hash = result

    # Compare the input password with the stored hash
    if bcrypt.checkpw(password.encode("utf-8"), stored_password_hash):
        print(f"Access granted! Welcome, {username}.")
        while True:
            print("\n1. Store a product password")
            print("2. Retrieve product passwords")
            print("3. Log out")
            option = input("choose an option")
            if option == "1":
                store_product_password(user_id)
            elif option == "2":
                retrieve_product_passwords(user_id)
            elif option == "3":
                print("Logging out....")
                break
            else:
                print("invalid option")
        return True
    else:
        print("Invalid password. Access denied.")
        return False


def main():
    print("1. Register")
    print("2. Log in")
    option = input("Choose an option: ")

    if option == "1":
        register_user()
    elif option == "2":
        authenticate_user()
    else:
        print("Invalid option")


if __name__ == "__main__":
    main()

# Close the database connection when done
conn.close()
