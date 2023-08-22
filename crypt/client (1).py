from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import tkinter


def receive():
    """Handles receiving of messages."""
    while True:
        try:
            msg = client_socket.recv(BUFSIZ).decode("utf8")
            msg_list.insert(tkinter.END, msg)
        except OSError:  
            break


def send(event=None):  # event is passed by binders.
    msg = my_msg.get()

    #-----------------------------------------------

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

        message = msg

        ciphertext = encrypt_text(public_key_path, message)

        decrypted_text = decrypt_text(private_key_path, ciphertext)


    #-----------------------------------------------

    my_msg.set("")  # Clears input field.
    client_socket.send(bytes(message, "utf8"))
    if msg == "{quit}":
        client_socket.close()
        top.quit()


def on_closing(event=None):
    """This function is to be called when the window is closed."""
    my_msg.set("{quit}")
    send()

top = tkinter.Tk()
top.title("CMessaging app")

# Center the window on the desktop screen
def center_window(window, width, height):
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()

    x = (screen_width - width) // 2
    y = (screen_height - height) // 2

    window.geometry('{}x{}+{}+{}'.format(width, height, x, y))

center_window(top, 500, 600)

messages_frame = tkinter.Frame(top)
my_msg = tkinter.StringVar()  # For the messages to be sent.
my_msg.set("")
scrollbar = tkinter.Scrollbar(messages_frame)  # To see through previous messages.
# this will contain the messages.
msg_list = tkinter.Listbox(messages_frame, height=30, width=65, yscrollcommand=scrollbar.set)
scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
msg_list.pack(padx=10, pady=5)
messages_frame.pack(padx=10, pady=5)

entry_field = tkinter.Entry(top, textvariable=my_msg)
entry_field.bind("<Return>", send)
entry_field.pack(padx=10, pady=5)
send_button = tkinter.Button(top, text="Send", command=send)
send_button.pack(padx=10, pady=5)

top.protocol("WM_DELETE_WINDOW", on_closing)

#Socket part
HOST = '127.0.0.1' 
PORT = 33000
BUFSIZ = 1024
ADDR = (HOST, PORT)

client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(ADDR)

receive_thread = Thread(target=receive)
receive_thread.start()

tkinter.mainloop()  