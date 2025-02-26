from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import io

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Required for Flask flash messages

# AES Encryption Key (32 bytes for AES-256)
AES_KEY = os.urandom(32)

def encrypt_message(message):
    """Encrypt a message using AES."""
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
    return iv + encrypted_message  # Return IV + encrypted message

def decrypt_message(encrypted_message):
    """Decrypt a message using AES."""
    iv = encrypted_message[:16]  # Extract IV
    encrypted_message = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    return decrypted_message.decode()

def hide_message_in_image(image, message):
    """Hide a message in an image using LSB steganography."""
    binary_message = ''.join(format(byte, '08b') for byte in message)
    binary_message += '1111111111111110'  # Add a delimiter to mark the end of the message

    pixels = list(image.getdata())
    if len(binary_message) > len(pixels) * 3:
        raise ValueError("Message too long to hide in the image.")

    index = 0
    for i in range(len(pixels)):
        pixel = list(pixels[i])
        for j in range(3):  # RGB channels
            if index < len(binary_message):
                pixel[j] = pixel[j] & ~1 | int(binary_message[index])
                index += 1
        pixels[i] = tuple(pixel)

    new_image = Image.new(image.mode, image.size)
    new_image.putdata(pixels)
    return new_image

def extract_message_from_image(image):
    """Extract a hidden message from an image using LSB steganography."""
    pixels = list(image.getdata())
    binary_message = ''
    for pixel in pixels:
        for value in pixel[:3]:  # RGB channels
            binary_message += str(value & 1)
    
    delimiter = '1111111111111110'
    delimiter_index = binary_message.find(delimiter)
    if delimiter_index == -1:
        return ""

    binary_message = binary_message[:delimiter_index]
    message_bytes = [int(binary_message[i:i+8], 2) for i in range(0, len(binary_message), 8)]
    return bytes(message_bytes)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        try:
            action = request.form.get('action')
            if action not in ['hide', 'extract']:
                flash("Invalid action selected.", "error")
                return redirect(url_for('index'))

            image_file = request.files.get('image')
            if not image_file:
                flash("No image file uploaded.", "error")
                return redirect(url_for('index'))

            image = Image.open(image_file)
            if action == 'hide':
                message = request.form.get('message')
                if not message:
                    flash("No message entered.", "error")
                    return redirect(url_for('index'))

                # Encrypt the message
                encrypted_message = encrypt_message(message)

                # Hide the encrypted message in the image
                new_image = hide_message_in_image(image, encrypted_message)

                # Save the new image to a byte stream
                img_byte_arr = io.BytesIO()
                new_image.save(img_byte_arr, format=image.format)
                img_byte_arr.seek(0)

                return send_file(img_byte_arr, mimetype=f'image/{image.format.lower()}', as_attachment=True, download_name=f'secret_image.{image.format.lower()}')

            elif action == 'extract':
                # Extract the encrypted message from the image
                encrypted_message = extract_message_from_image(image)

                # Decrypt the message
                decrypted_message = decrypt_message(encrypted_message)

                flash(f"Extracted Message: {decrypted_message}", "success")
                return redirect(url_for('index'))

        except Exception as e:
            flash(f"An error occurred: {str(e)}", "error")
            return redirect(url_for('index'))

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)