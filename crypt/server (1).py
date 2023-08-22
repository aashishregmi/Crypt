from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread


def accept_incoming_connections():
    while True:
        client, client_address = SERVER.accept()
        print("%s:%s has connected." % client_address)
        client.send(bytes("TYPE YOUR [ NAME ] AND PRESS ENTER", "utf8"))
        addresses[client] = client_address
        Thread(target=handle_client, args=(client,)).start()


def handle_client(client):  # Takes client socket as argument.
    name = client.recv(BUFSIZ).decode("utf8")
    welcome = 'Welcome %s! If you ever want to quit, type {quit} to exit.' % name
    client.send(bytes(welcome, "utf8"))
    message = "%s has joined the chat!" % name
    broadcast(bytes(message, "utf8"))
    clients[client] = name

    while True:
        message = client.recv(BUFSIZ)
        if message != bytes("{quit}", "utf8"):
            broadcast(message, name+": ")
        else:
            client.send(bytes("{quit}", "utf8"))
            client.close()
            del clients[client]
            broadcast(bytes("%s has left the chat." % name, "utf8"))
            break


def broadcast(message, prefix=""):  # prefix is for name identification.
    string_message = message.decode('utf-8')

    import os
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes

    def generate_rsa_key_pair(key_size=2048, private_key_path="private_key.pem", public_key_path="public_key.pem"):
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            return

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )

        with open(private_key_path, "wb") as private_key_file:
            private_key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        public_key = private_key.public_key()

        with open(public_key_path, "wb") as public_key_file:
            public_key_file.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    def encrypt_text(public_key_path, message):
        with open(public_key_path, "rb") as public_key_file:
            public_key = serialization.load_pem_public_key(public_key_file.read())

        ciphertext = public_key.encrypt(
            message.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return ciphertext

    def decrypt_text(private_key_path, ciphertext):
        with open(private_key_path, "rb") as private_key_file:
            private_key = serialization.load_pem_private_key(private_key_file.read(), password=None)

        message = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return message.decode("utf-8")

    if __name__ == "__main__":
        generate_rsa_key_pair()

        public_key_path = "public_key.pem"
        private_key_path = "private_key.pem"

        client_message = string_message

        ciphertext = encrypt_text(public_key_path, client_message)

        decryptedtext = decrypt_text(private_key_path, ciphertext)

        decrypted_message = decryptedtext.encode('utf-8')

    for sock in clients:
        sock.send(bytes(prefix, "utf8")+decrypted_message)


clients = {}
addresses = {}

HOST = '127.0.0.1'
PORT = 33000
BUFSIZ = 1024
ADDR = (HOST, PORT)

SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)

if __name__ == "__main__":
    SERVER.listen(5)
    print("Listening for connection...")
    ACCEPT_THREAD = Thread(target=accept_incoming_connections)
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
    SERVER.close()
