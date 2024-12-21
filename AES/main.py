import numpy as np
from PIL import Image
from shiftrow import shift_rows, inv_shift_rows
from mix_column import mix_columns, inv_mix_columns
from subbyte import sub_bytes, inv_sub_bytes
from key_addition import add_round_key

def aes_encrypt_block(block, round_keys):
    state = [list(block[i:i + 4]) for i in range(0, len(block), 4)]
    state = add_round_key(state, round_keys[0])
    for round in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    return [byte for row in state for byte in row]

def aes_decrypt_block(block, round_keys):
    state = [list(block[i:i + 4]) for i in range(0, len(block), 4)]
    state = add_round_key(state, round_keys[10])
    for round in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[round])
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    return [byte for row in state for byte in row]

def pad_image_data(image_data):
    flat_image_data = image_data.flatten().tolist()
    block_size = 16
    padding_length = block_size - (len(flat_image_data) % block_size)
    padding = [padding_length] * padding_length
    flat_image_data += padding
    return flat_image_data, padding_length

def unpad_image_data(flat_image_data):
    last_byte = flat_image_data[-1]
    if last_byte > 16:
        raise ValueError("Invalid padding")
    return flat_image_data[:-last_byte]

def encrypt_image_to_file(image_path, encrypted_file, shape_file, encrypted_image_file, round_keys):
    image = Image.open(image_path)
    image_data = np.array(image)
    flat_image_data, padding_length = pad_image_data(image_data)
    encrypted_data = []
    for i in range(0, len(flat_image_data), 16):
        block = flat_image_data[i:i + 16]
        encrypted_block = aes_encrypt_block(block, round_keys)
        encrypted_data.extend(encrypted_block)
    with open(encrypted_file, 'wb') as f:
        f.write(bytearray(encrypted_data))
    with open(shape_file, 'w') as f:
        f.write(f"{image_data.shape[0]} {image_data.shape[1]} {image_data.shape[2]}")
   
    encrypted_image_data = np.array(encrypted_data[:np.prod(image_data.shape)], dtype=np.uint8).reshape(image_data.shape)
    encrypted_image = Image.fromarray(encrypted_image_data)
    encrypted_image.save(encrypted_image_file)
    print(f"Image encrypted and saved to {encrypted_file}, shape saved to {shape_file}, encrypted image saved to {encrypted_image_file}")

def decrypt_image_from_file(encrypted_file, shape_file, output_image, round_keys):
    with open(shape_file, 'r') as f:
        original_shape = tuple(map(int, f.read().split()))
    with open(encrypted_file, 'rb') as f:
        encrypted_data = list(f.read())
    decrypted_data = []
    for i in range(0, len(encrypted_data), 16):
        block = encrypted_data[i:i + 16]
        decrypted_block = aes_decrypt_block(block, round_keys)
        decrypted_data.extend(decrypted_block)
    decrypted_data = unpad_image_data(decrypted_data)
    decrypted_image_data = np.array(decrypted_data, dtype=np.uint8).reshape(original_shape)
    decrypted_image = Image.fromarray(decrypted_image_data)
    decrypted_image.save(output_image)
    print(f"Image decrypted and saved to {output_image}")


round_keys = [
    [[0x01, 0x02, 0x03, 0x04], [0x05, 0x06, 0x07, 0x08], [0x09, 0x0a, 0x0b, 0x0c], [0x0d, 0x0e, 0x0f, 0x10]],
    [[0x11, 0x12, 0x13, 0x14], [0x15, 0x16, 0x17, 0x18], [0x19, 0x1a, 0x1b, 0x1c], [0x1d, 0x1e, 0x1f, 0x20]],
    [[0x21, 0x22, 0x23, 0x24], [0x25, 0x26, 0x27, 0x28], [0x29, 0x2a, 0x2b, 0x2c], [0x2d, 0x2e, 0x2f, 0x30]],
    [[0x31, 0x32, 0x33, 0x34], [0x35, 0x36, 0x37, 0x38], [0x39, 0x3a, 0x3b, 0x3c], [0x3d, 0x3e, 0x3f, 0x40]],
    [[0x41, 0x42, 0x43, 0x44], [0x45, 0x46, 0x47, 0x48], [0x49, 0x4a, 0x4b, 0x4c], [0x4d, 0x4e, 0x4f, 0x50]],
    [[0x51, 0x52, 0x53, 0x54], [0x55, 0x56, 0x57, 0x58], [0x59, 0x5a, 0x5b, 0x5c], [0x5d, 0x5e, 0x5f, 0x60]],
    [[0x61, 0x62, 0x63, 0x64], [0x65, 0x66, 0x67, 0x68], [0x69, 0x6a, 0x6b, 0x6c], [0x6d, 0x6e, 0x6f, 0x70]],
    [[0x71, 0x72, 0x73, 0x74], [0x75, 0x76, 0x77, 0x78], [0x79, 0x7a, 0x7b, 0x7c], [0x7d, 0x7e, 0x7f, 0x80]],
    [[0x81, 0x82, 0x83, 0x84], [0x85, 0x86, 0x87, 0x88], [0x89, 0x8a, 0x8b, 0x8c], [0x8d, 0x8e, 0x8f, 0x90]],
    [[0x91, 0x92, 0x93, 0x94], [0x95, 0x96, 0x97, 0x98], [0x99, 0x9a, 0x9b, 0x9c], [0x9d, 0x9e, 0x9f, 0xa0]],
    [[0xa1, 0xa2, 0xa3, 0xa4], [0xa5, 0xa6, 0xa7, 0xa8], [0xa9, 0xaa, 0xab, 0xac], [0xad, 0xae, 0xaf, 0xb0]],
]

# Encrypt the image 
encrypt_image_to_file('pic.jpg', 'encrypted_image.bin', 'image_shape.txt', 'encrypted_image.jpg', round_keys)

# Decrypt the image 
decrypt_image_from_file('encrypted_image.bin', 'image_shape.txt', 'decrypted_image.jpg', round_keys)


encrypted_image = Image.open('encrypted_image.jpg')
encrypted_image.show()

decrypted_image = Image.open('decrypted_image.jpg')
decrypted_image.show()
