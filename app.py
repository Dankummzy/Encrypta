from flask import Flask, request, render_template, redirect, url_for, flash, send_file
from werkzeug.utils import secure_filename
import os
from rsa_encryption import generate_rsa_keypair, encrypt_text
from rsa_decryption import decrypt_rsa, convert_back
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

from steganography_encryption import embed_message
from steganography_decryption import extract_message

import logging
import traceback


# Initialize logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads/'

# Ensure the upload directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted_files'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted_files'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'images'), exist_ok=True)

def decrypt_text(private_key, encrypted_data):
    decrypted_chars = []
    for encoded_value in encrypted_data:
        encrypted_bytes = base64.b64decode(encoded_value)
        decrypted_bytes = decrypt_rsa(encrypted_bytes, private_key)
        for byte in decrypted_bytes:
            decrypted_chars.append(convert_back(byte))
    return ''.join(decrypted_chars)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file:
            flash('No file part', 'danger')
            return redirect(request.url)
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            private_key, public_key = generate_rsa_keypair()
            with open(filepath, 'r') as f:
                text = f.read()

            encrypted_values = encrypt_text(public_key, text)
            encrypted_filename = f'encrypted_{filename}'
            encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted_files', encrypted_filename)
            with open(encrypted_filepath, 'w') as f:
                for value in encrypted_values:
                    f.write(value + "\n")

            with open("private_key.pem", "wb") as key_file:
                key_file.write(
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                )

            flash('File encrypted successfully!', 'success')
            return render_template('encrypt.html', encrypted_file=encrypted_filename)

    return render_template('encrypt.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted_files', filename)
        file.save(filepath)

        try:
            with open("private_key.pem", "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )

            with open(filepath, 'r') as f:
                encrypted_data = f.read().splitlines()

            decrypted_text = decrypt_text(private_key, encrypted_data)

            decrypted_filename = f'decrypted_{filename}'
            decrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted_files', decrypted_filename)
            with open(decrypted_filepath, 'w') as f:
                f.write(decrypted_text)

            flash('File decrypted successfully!', 'success')
            return render_template('decrypt.html', decrypted_file=decrypted_filename)

        except FileNotFoundError as e:
            print(f"File not found: {e.filename}")
            flash(f"File not found: {e.filename}", 'danger')
        except Exception as e:
            print("Error during decryption:", e)
            flash(f"Error during decryption: {str(e)}", 'danger')

    return render_template('decrypt.html')

@app.route('/embed', methods=['GET', 'POST'])
def embed():
    if request.method == 'POST':
        image = request.files['image']
        message_file = request.files['message_file']
        if image and message_file:
            try:
                image_filename = secure_filename(image.filename)
                message_filename = secure_filename(message_file.filename)
                image_filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'images', image_filename)
                message_filepath = os.path.join(app.config['UPLOAD_FOLDER'], message_filename)
                image.save(image_filepath)
                message_file.save(message_filepath)

                logging.debug(f"Uploaded image file path: {image_filepath}")
                logging.debug(f"Uploaded message file path: {message_filepath}")

                # Embedding message into the image
                embed_message(image_filepath, message_filepath)
                new_image_filename = f"{os.path.splitext(image_filename)[0]}_stego.png"
                new_image_path = os.path.join(app.config['UPLOAD_FOLDER'], 'images', new_image_filename)

                logging.debug(f"Embedded image file path: {new_image_path}")

                flash('Message embedded successfully!', 'success')
                return render_template('embed.html', embedded_image=new_image_filename)

            except Exception as e:
                flash(f"Error: {str(e)}", 'danger')
                logging.error(f"Error during embedding: {traceback.format_exc()}")

        else:
            flash('No image or message file uploaded.', 'danger')
            logging.error("No image or message file uploaded.")

    return render_template('embed.html')

@app.route('/extract', methods=['GET', 'POST'])
def extract():
    if request.method == 'POST':
        image = request.files['image']
        if image:
            image_filename = secure_filename(image.filename)
            image_filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'images', image_filename)
            image.save(image_filepath)

            extracted_message = extract_message(image_filepath)
            if extracted_message:
                message_filename = f"extracted_message_{os.path.splitext(image_filename)[0]}.txt"
                message_filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted_files', message_filename)
                with open(message_filepath, 'w') as message_file:
                    message_file.write(extracted_message)
                flash('Message extracted successfully!', 'success')
                return render_template('extract.html', extracted_message_file=message_filename)
            else:
                flash('Error extracting message.', 'danger')
                return redirect(url_for('extract'))

    return render_template('extract.html')

@app.route('/uploads/<filename>')
def download_file(filename):
    if filename.startswith('encrypted_'):
        folder = 'encrypted_files'
    elif filename.startswith('decrypted_'):
        folder = 'decrypted_files'
    elif filename.endswith('_stego.png'):
        folder = 'images'
    elif filename.startswith('extracted_message_'):
        folder = 'decrypted_files'
    else:
        folder = ''
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], folder, filename), as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
