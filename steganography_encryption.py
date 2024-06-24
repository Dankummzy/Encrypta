from PIL import Image
import base64

def embed_message(image_path, message_path):
    """
    Embeds a message from a text file into an image.

    Args:
        image_path (str): Path to the image file.
        message_path (str): Path to the text file containing the message.
    """
    try:
        # Open the image and convert it to RGB format
        img = Image.open(image_path).convert("RGB")
        width, height = img.size

        # Read the message from the text file
        with open(message_path, "r") as message_file:
            message = message_file.read()

        # Encode the message as base64
        encoded_message = base64.b64encode(message.encode("utf-8")).decode("utf-8")

        # Add a delimiter to indicate the end of the message
        encoded_message += "==="

        # Convert the encoded message to binary string
        message_bits = ''.join([f"{ord(char):08b}" for char in encoded_message])

        # Check if the message can fit in the image
        if len(message_bits) > width * height * 3:
            raise ValueError("Message is too large for the image.")

        # Create a list of pixels to modify
        pixels = list(img.getdata())

        # Embed the message into the least significant bit of each pixel
        message_index = 0
        for i in range(len(pixels)):
            if message_index < len(message_bits):
                # Get the pixel value
                r, g, b = pixels[i]

                # Convert the pixel value to binary strings
                r_bin = f"{r:08b}"
                g_bin = f"{g:08b}"
                b_bin = f"{b:08b}"

                # Replace the least significant bit with the message bit
                if message_index < len(message_bits):
                    r_bin = r_bin[:-1] + message_bits[message_index]
                    message_index += 1
                if message_index < len(message_bits):
                    g_bin = g_bin[:-1] + message_bits[message_index]
                    message_index += 1
                if message_index < len(message_bits):
                    b_bin = b_bin[:-1] + message_bits[message_index]
                    message_index += 1

                # Convert the binary strings back to integer values
                new_r = int(r_bin, 2)
                new_g = int(g_bin, 2)
                new_b = int(b_bin, 2)

                # Update the pixel value
                pixels[i] = (new_r, new_g, new_b)

        # Create a new image with the modified pixels
        new_img = Image.new("RGB", (width, height))
        new_img.putdata(pixels)

        # Save the modified image with a new name
        new_image_path = f"{image_path[:-4]}_stego.png"
        new_img.save(new_image_path)
        print(f"Message embedded successfully in {new_image_path}")

    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    image_path = "firstRQ.jpg"  # Replace with your image path
    message_path = "s2.txt"  # Replace with your message path
    embed_message(image_path, message_path)
