'Chat Room Connection - Client-To-Client'
import base64
import threading
import socket
import hashlib
host = '127.0.0.1'
port = 59000
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()
clients = []
aliases = []
key_dictionary=[]

def broadcast(message):
    for client in clients:
        client.send(message)

# Function to handle clients'connections

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
def handle_client(client):
    while True:
        try:
            message = client.recv(1024)
            encrypted_message, key = encrypt_message(message.decode('utf-8'))

            broadcast(encrypted_message.encode('utf-8'))
        except:
            index = clients.index(client)
            clients.remove(client)
            client.close()
            alias = aliases[index]
            broadcast(f'{alias} has left the chat room!'.encode('utf-8'))
            aliases.remove(alias)
            break
# Main function to receive the clients connection


def receive():
    while True:
        print('Server is running and listening ...')
        client, address = server.accept()
        print(f'connection is established with {str(address)}')
        client.send('alias?'.encode('utf-8'))
        alias = client.recv(1024)
        aliases.append(alias)
        clients.append(client)
        print(f'The alias of this client is {alias}'.encode('utf-8'))
        broadcast(f'{alias} has connected to the chat room'.encode('utf-8'))
        client.send('you are now connected!'.encode('utf-8'))
        thread = threading.Thread(target=handle_client, args=(client,))
        thread.start()


if __name__ == "__main__":
    receive()