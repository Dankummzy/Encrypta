from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64
import sys

def convert(txt):
    char_to_num = {}
    for i in range(256):  # Handle all ASCII characters
        char_to_num[chr(i)] = i + 1
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
        byte_value = char.encode('utf-8')
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
        private_key, public_key = generate_rsa_keypair()
        with open("s1.txt", "r") as file:
            text = file.read()
    except FileNotFoundError:
        print("File s1.txt not found.")
        sys.exit(1)

    encrypted_values = encrypt_text(public_key, text)
    with open("sample1.txt", "w") as file:
        file.write(" ".join(encrypted_values))
    print("Encryption completed and file saved.")