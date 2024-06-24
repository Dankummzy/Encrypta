from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64
from sympy import isprime
import sys

def convert(txt):
    char_to_num = {
        "A": 1, "B": 2, "C": 3, "D": 4, "E": 5,
        "+": 74, "/": 75, "!": 63, "@": 64, "#": 65,
        "$": 66, "%": 67, "^": 68, "&": 69, "*": 70,
        "(": 71, ")": 72, "-": 73, " ": 76, "\n": 77
    }
    return char_to_num.get(txt, -1)

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    with open("private_key.pem", "wb") as key_file:
        key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    return private_key, public_key

def encrypt_text(public_key, text):
    encrypted_values = []
    for char in text:
        numeric_value = convert(char)
        if numeric_value == -1:
            print(f"Unsupported character '{char}' found in text.")
            continue
        byte_value = bytes([numeric_value])
        encrypted_byte = public_key.encrypt(
            byte_value,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_values.append(base64.b64encode(encrypted_byte).decode('utf-8'))
    return encrypted_values

if __name__ == "__main__":
    try:
        p = int(input('Enter the value of p (prime) = '))
        q = int(input('Enter the value of q (prime) = '))
        if not (isprime(p) and isprime(q)):
            raise ValueError("Both p and q must be prime numbers.")
        if p == q:
            raise ValueError("p and q must be distinct prime numbers.")
    except ValueError as e:
        print(e)
        sys.exit(1)

    private_key, public_key = generate_rsa_keypair()
    try:
        with open("s1.txt", "r") as file:
            text = file.read()
    except FileNotFoundError:
        print("File s1.txt not found.")
        sys.exit(1)

    encrypted_values = encrypt_text(public_key, text)
    with open("sample1.txt", "w") as file:
        file.write(" ".join(encrypted_values))
    print("Encryption completed and file saved.")
