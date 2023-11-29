'Chat Room Connection - Client-To-Client'
import base64
import threading
import socket
import hashlib
from cryptography.fernet import Fernet
host = '127.0.0.1'
port = 59000
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()
clients = []
aliases = []
key_dictionary=[]
file_dict = {}
key_dict = {}

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
            file_name = client.recv(1024).decode()
            file_size = int(client.recv(1024).decode())
            print(f"Receiving file: {file_name}, Size: {file_size} bytes, Alias: {aliases[-1]}")

            # Receive the file data
            while file_size > 0:
                data = client.recv(1024)
                if not data:
                    break
                # file.write(data)
                encrypted_message,key = encrypt_mess_new(data.decode('utf-8'))
                print(data)
                if aliases[-1] in file_dict:
                    file_dict[aliases[-1]].append(encrypted_message)
                    key_dict[encrypted_message] = key
                else:
                    file_dict[aliases[-1]] = [encrypted_message]
                    key_dict[encrypted_message] = key
                # print(file_dict[aliases[-1]])
                file_size -= len(data)
                broadcast(encrypted_message)
                # print(file_dict)
            compare()

            # print("File received successfully")


        except:
            index = clients.index(client)
            clients.remove(client)
            client.close()
            alias = aliases[index]
            broadcast(f'{alias} has left the chat room!'.encode('utf-8'))
            aliases.remove(alias)
            break
# Main function to receive the clients connection

def encrypt_mess_new(message):
    key = Fernet.generate_key()
    fernet = Fernet(key)
    encMessage = fernet.encrypt(message.encode('utf-8'))
    return encMessage, key

def decrypt_mess_new(message,key):
    fernet = Fernet(key)
    decMessage = fernet.decrypt(message).decode()
    return decMessage

def compare():
    found = 0
    for i in file_dict[aliases[0]]:
        if aliases[0] != aliases[-1]:
            for j in file_dict[aliases[-1]]:
                key_i = key_dict[i]
                key_j = key_dict[j]
                if decrypt_mess_new(i,key_i) == decrypt_mess_new(j,key_j):
                    broadcast(f"Files from clients are identical".encode('utf-8'))
                    found = 1
                    break

        if aliases[0] == aliases[-1]:
            found = 1
            broadcast(f"Waiting for files from other clients".encode('utf-8'))
            break
        if found == 1:
            break
    if found == 0:
        broadcast(f"Files from clients are different".encode('utf-8'))


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