from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
import base64

def convert_back(num):
    num_to_char = {}
    for i in range(256):  # Handle all ASCII characters
        num_to_char[i + 1] = chr(i)
    return num_to_char.get(num, '')

def decrypt_rsa(encrypted_bytes, private_key):
    decrypted_bytes = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_bytes

def load_private_key(file_path):
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def load_encrypted_data(file_path):
    with open(file_path, "r") as file:
        encrypted_data = file.read()
    return encrypted_data.split()

if __name__ == "__main__":
    try:
        private_key = load_private_key("private_key.pem")
        encrypted_values = load_encrypted_data("sample1.txt")

        decrypted_text = []
        for encoded_value in encrypted_values:
            encrypted_bytes = base64.b64decode(encoded_value)
            decrypted_text.append(decrypt_rsa(encrypted_bytes, private_key))

        decrypted_text = ''.join(decrypted_text)
        print("Decrypted Text:", decrypted_text)

    except FileNotFoundError as e:
        print(f"File not found: {e.filename}")
    except Exception as e:
        print("Error during decryption:", e)
