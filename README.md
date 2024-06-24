# Encrypta

## Encrypta Web Application
This project is a web application that allows users to embed and extract messages from images using steganography. It also provides functionality for RSA encryption and decryption of text files. The application is built using Flask and includes features for uploading, embedding, extracting, encrypting, and decrypting files.

## Features
Embed Messages: Hide a message inside an image file.
Extract Messages: Retrieve a hidden message from an image file.
RSA Encryption: Encrypt text files using RSA encryption.
RSA Decryption: Decrypt encrypted text files using RSA decryption.
## Requirements
Python 3.9
Flask
cryptography
Pillow
## Installation
#### Clone the repository:
git clone https://github.com/Dankummzy/encrypta.git
cd encrypta
#### Create a virtual environment and activate it:
python3 -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
#### Install the required packages:
pip install -r requirements.txt
## Usage
#### Run the Flask application:
flask run
Open your web browser and go to:
http://127.0.0.1:5000/
## Project Structure
## encrypta/
###### ├── app.py                  # Main Flask application
###### ├── rsa_encryption.py       # RSA encryption functions
###### ├── rsa_decryption.py       # RSA decryption functions
###### ├── steganography_encryption.py  # Steganography embedding functions
###### ├── steganography_decryption.py  # Steganography extraction functions
#### ├── templates/
###### │   ├── base.html           # Base template
###### │   ├── index.html          # Index page template
###### │   ├── encrypt.html        # Encryption page template
###### │   ├── decrypt.html        # Decryption page template
###### │   ├── embed.html          # Embed page template
###### │   ├── extract.html        # Extract page template
#### ├── uploads/                # Directory for uploaded files
###### │   ├── encrypted_files/
###### │   ├── decrypted_files/
###### │   ├── images/
#### ├── requirements.txt        # Python dependencies
#### └── README.md               # This README file
## Endpoints
#### /: Home page.
#### /encrypt: Page to upload and encrypt a text file.
#### /decrypt: Page to upload and decrypt a text file.
#### /embed: Page to upload an image and a message file to embed the message into the image.
#### /extract: Page to upload an image to extract the hidden message.
#### /uploads/<filename>: Endpoint to download the processed files (encrypted, decrypted, embedded images, extracted messages).
## How to Use
#### Embedding a Message
Navigate to the Embed page.
Upload an image file.
Upload a message text file.
Click the "Embed Message" button.
Download the embedded image from the provided link.
#### Extracting a Message
Navigate to the Extract page.
Upload an image file with a hidden message.
Click the "Extract Message" button.
Download the extracted message file from the provided link.
#### Encrypting a File
Navigate to the Encrypt page.
Upload a text file.
Click the "Encrypt" button.
Download the encrypted file from the provided link.
#### Decrypting a File
Navigate to the Decrypt page.
Upload an encrypted text file.
Click the "Decrypt" button.
Download the decrypted file from the provided link.
## License
This project is licensed under the MIT License. See the LICENSE file for details.
## Contributing
Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.
## Contact
For any questions or inquiries, please contact **danterkum16@gmail.com**.
