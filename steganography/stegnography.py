from PIL import Image
import os

END_MARKER = "1111111111111110"  # Unique end marker


# ----------------------------
# Convert message to binary
# ----------------------------
def message_to_binary(message):
    return ''.join(format(ord(char), '08b') for char in message)


# ----------------------------
# Convert binary to message
# ----------------------------
def binary_to_message(binary_data):
    chars = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    message = ''
    for char in chars:
        if len(char) == 8:
            message += chr(int(char, 2))
    return message


# ----------------------------
# Encode message
# ----------------------------
def encode_image(image_name, message, output_name):

    image_name = image_name.strip()
    output_name = output_name.strip()

    if not os.path.exists(image_name):
        print("❌ Image not found in this folder.")
        return

    image = Image.open(image_name)

    # Convert to RGB (important fix)
    if image.mode != "RGB":
        image = image.convert("RGB")

    binary_message = message_to_binary(message) + END_MARKER

    pixels = list(image.getdata())

    # Capacity check
    max_capacity = len(pixels) * 3
    if len(binary_message) > max_capacity:
        print("❌ Message too large for this image.")
        return

    data_index = 0
    new_pixels = []

    for pixel in pixels:
        r, g, b = pixel

        if data_index < len(binary_message):
            r = (r & ~1) | int(binary_message[data_index])
            data_index += 1

        if data_index < len(binary_message):
            g = (g & ~1) | int(binary_message[data_index])
            data_index += 1

        if data_index < len(binary_message):
            b = (b & ~1) | int(binary_message[data_index])
            data_index += 1

        new_pixels.append((r, g, b))

    image.putdata(new_pixels)
    image.save(output_name)

    print("✅ Message successfully hidden inside", output_name)


# ----------------------------
# Decode message
# ----------------------------
def decode_image(image_name):

    image_name = image_name.strip()

    if not os.path.exists(image_name):
        print("❌ Image not found in this folder.")
        return

    image = Image.open(image_name)

    if image.mode != "RGB":
        image = image.convert("RGB")

    pixels = list(image.getdata())

    binary_data = ""

    for pixel in pixels:
        r, g, b = pixel
        binary_data += str(r & 1)
        binary_data += str(g & 1)
        binary_data += str(b & 1)

    message_binary = binary_data.split(END_MARKER)[0]

    message = binary_to_message(message_binary)

    print("🔓 Hidden message:")
    print(message)


# ----------------------------
# MAIN PROGRAM
# ----------------------------

print("\nSteganography Tool")
print("-------------------")
print("1. Encode Message")
print("2. Decode Message")

choice = input("Enter your choice (1/2): ").strip()

if choice == '1':
    img = input("Enter image name (example sample.png): ")
    msg = input("Enter secret message: ")
    output = input("Enter output image name (example encoded.png): ")

    encode_image(img, msg, output)

elif choice == '2':
    img = input("Enter image name (example encoded.png): ")
    decode_image(img)

else:
    print("❌ Invalid choice.")