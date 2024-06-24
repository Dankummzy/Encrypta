from PIL import Image
import base64

def extract_message(image_path):
    """
    Extracts a message hidden in an image.

    Args:
        image_path (str): Path to the image file containing the hidden message.

    Returns:
        str: The extracted message.
    """
    try:
        # Open the image
        img = Image.open(image_path)
        width, height = img.size

        # Extract the message bits from the least significant bit of each pixel
        message_bits = []
        pixels = list(img.getdata())
        for r, g, b in pixels:
            message_bits.append(f"{r:08b}"[-1])
            message_bits.append(f"{g:08b}"[-1])
            message_bits.append(f"{b:08b}"[-1])

        # Join the bits to form a binary string
        message_bits = ''.join(message_bits)

        # Split the bits into 8-bit chunks
        byte_list = [message_bits[i:i+8] for i in range(0, len(message_bits), 8)]
        
        # Convert the bits to characters
        message = ''.join([chr(int(byte, 2)) for byte in byte_list])

        # Find the delimiter and extract the encoded message
        delimiter_index = message.find("===")
        if delimiter_index != -1:
            encoded_message = message[:delimiter_index]
            # Add padding if necessary
            encoded_message += '=' * ((4 - len(encoded_message) % 4) % 4)
            # Decode the message from base64
            decoded_message = base64.b64decode(encoded_message).decode("utf-8")
            return decoded_message
        else:
            raise ValueError("No valid encoded message found.")

    except (FileNotFoundError, ValueError, base64.binascii.Error) as e:
        print(f"Error: {e}")
        return None  # Indicate error by returning None

if __name__ == "__main__":
    # Replace with the path to your steganographic image
    image_path = "firstRQ_stego.png"
    extracted_message = extract_message(image_path)

    if extracted_message:
        print("Extracted Message:", extracted_message)
    else:
        print("Error extracting message.")
