import hashlib
import base64

def encrypt_message(message):
    # Encode the message to bytes
    message_bytes = message.encode('utf-8')

    # Create a SHA-256 hash object
    hash_object = hashlib.sha256()

    # Update the hash object with the bytes
    hash_object.update(message_bytes)

    # Get the hexadecimal representation of the digest
    hashed_message_hex = hash_object.hexdigest()

    # Convert the hexadecimal representation to an integer
    hashed_message_int = int(hashed_message_hex, 16)

    # Perform XOR operation with the original message's integer representation
    result_int = hashed_message_int ^ int.from_bytes(message_bytes, byteorder='big')

    # Convert the result back to bytes
    result_bytes = result_int.to_bytes((result_int.bit_length() + 7) // 8, byteorder='big')

    # Encode the result bytes using base64 for display purposes
    encrypted_message = base64.b64encode(result_bytes).decode('utf-8')

    return encrypted_message, hashed_message_int

def decrypt_message(encrypted_message, key):
    # Decode the base64-encoded string to bytes for actual decryption
    encrypted_bytes = base64.b64decode(encrypted_message.encode('utf-8'))

    # Convert the bytes to an integer
    result_int = int.from_bytes(encrypted_bytes, byteorder='big')

    # Reverse the XOR operation with the original message's integer representation
    hashed_message_int = result_int ^ key

    # Convert the hashed message back to bytes
    hashed_message_bytes = hashed_message_int.to_bytes((hashed_message_int.bit_length() + 7) // 8, byteorder='big')

    # Decode the bytes to get the original message
    decrypted_message = hashed_message_bytes.decode('utf-8')

    return decrypted_message

if __name__ == "__main__":
    message = 'qian176: qwe'

    # Encrypt the message
    encrypted_message, key = encrypt_message(message)

    # Decrypt the message using the key
    decrypted_message = decrypt_message(encrypted_message, key)

    print("Original Message:", message)
    print("Encrypted Message:", encrypted_message)
    print("Decrypted Message:", decrypted_message)

