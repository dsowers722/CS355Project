import threading
import socket
import os

alias = input('Choose a username >>> ')
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 59000))


def client_receive():
    while True:
        try:
            message = client.recv(1024).decode('utf-8')
            if message == "alias?":
                client.send(alias.encode('utf-8'))
            else:
                print(message)
        except:
            print('Error!')
            client.close()
            break


def client_send():
    while True:
        # Prompt user for file path
        file_path = input('Enter the path of the file you want to send: ')

        # Check if the file exists
        if not os.path.isfile(file_path):
            print('File not found. Please enter a valid file path.')
            continue

        # Send the file name and size
        file_name = file_path.split('/')[-1]
        file_size = str(os.path.getsize(file_path))
        client.send(file_name.encode('utf-8'))
        client.send(file_size.encode())

        # Send the file data
        with open(file_path, 'rb') as file:
            data = file.read(1024)
            while data:
                client.send(data)
                data = file.read(1024)


receive_thread = threading.Thread(target=client_receive)
receive_thread.start()

send_thread = threading.Thread(target=client_send)
send_thread.start()