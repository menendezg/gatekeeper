from cryptography.fernet import Fernet

# Generate a key for encryption and decryption (this key must be kept secret)
# You should save the key somewhere secure and load it when needed

def generate_key():
    key = Fernet.generate_key()

    # Save the key to a file
    with open("secret.key", "wb") as key_file:
        key_file.write(key)


def load_key():
    with open("secret.key", "rb") as key_file:
        key = key_file.read()

    return key

if __name__ == "__main__":
    generate_key()
