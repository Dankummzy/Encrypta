from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
import base64

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

def convert_back(num):
    num_to_char = {
        1: "A", 2: "B", 3: "C", 4: "D", 5: "E",
        74: "+", 75: "/", 63: "!", 64: "@", 65: "#",
        66: "$", 67: "%", 68: "^", 69: "&", 70: "*",
        71: "(", 72: ")", 73: "-", 76: " ", 77: "\n"
    }
    return num_to_char.get(num, '')

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

        decrypted_chars = []
        for encoded_value in encrypted_values:
            encrypted_bytes = base64.b64decode(encoded_value)
            decrypted_bytes = decrypt_rsa(encrypted_bytes, private_key)
            for byte in decrypted_bytes:
                decrypted_chars.append(convert_back(byte))

        decrypted_text = ''.join(decrypted_chars)
        print("Decrypted Text:", decrypted_text)

    except FileNotFoundError as e:
        print(f"File not found: {e.filename}")
    except Exception as e:
        print("Error during decryption:", e)
       
