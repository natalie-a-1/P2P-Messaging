import sys
import socket
import threading
from PyQt5.QtWidgets import QApplication, QMainWindow, QTextEdit, QPushButton, QVBoxLayout, QWidget, QComboBox, QLabel, QHBoxLayout
from PyQt5.QtCore import pyqtSignal, QObject, Qt, QEvent
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

# Signal class for updating the GUI from a different thread
class Signal(QObject):
    # Define a custom signal that passes a string
    received = pyqtSignal(str)

def get_key(password):
    # Function to generate a symmetric encryption key from a password
    salt = get_random_bytes(16)  # Generate a new random salt
    # Use PBKDF2 (Password-Based Key Derivation Function 2) with the password and salt
    key = PBKDF2(password, salt, dkLen=16, count=1000000)
    return key, salt

def encrypt_message(plaintext, key):
    # Function to encrypt a message using AES encryption
    cipher = AES.new(key, AES.MODE_EAX)  # AES in EAX mode for confidentiality and integrity
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    # Return the encrypted message with nonce, tag, and ciphertext
    return b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

def decrypt_message(ciphertext, key):
    # Function to decrypt a message using AES decryption
    try:
        # Decode the base64 encoded string and extract nonce, tag, and ciphertext
        data = b64decode(ciphertext)
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        # Decrypt and verify the message
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except ValueError as e:
        # Catch and print the error if decryption fails
        print("Incorrect decryption or tag does not match")
        return ""

# Client class that handles sending and receiving messages
class ChatClient:
    def __init__(self, signal, host='127.0.0.1', port=12345, username="Alice"):
        # Set up the client socket and connect to the server
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))
        self.signal = signal
        self.username = username
        # Secure password for key derivation
        self.password = "secure_password"
        self.key, self.salt = get_key(self.password)
        # Start a thread to handle incoming messages
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def send_message(self, message):
        # Encrypt the message before sending
        encrypted_message = encrypt_message(f"{self.username}: {message}", self.key)
        try:
            # Send the encrypted message to the server
            self.client_socket.send(encrypted_message.encode('utf-8'))
        except Exception as e:
            # Print the error if the message sending fails
            print(f"Error sending message: {e}")

    def receive_messages(self):
        while True:
            try:
                # Receive encrypted messages from the server
                encrypted_message = self.client_socket.recv(1024).decode('utf-8')
                # Decrypt the message and emit the signal to update the GUI
                message = decrypt_message(encrypted_message, self.key)
                self.signal.received.emit(message)
            except Exception as e:
                # Print the error if message reception fails and close the socket
                print(f"Error receiving messages: {e}")
                self.client_socket.close()
                break

# Main window class for the chat application
class MessagingApp(QMainWindow):
    # Initialization of the main window
    def __init__(self, chat_client):
        super().__init__()
        self.chat_client = chat_client
        # Set up the user interface
        self.init_ui()

    def init_ui(self):
        # Set the window title and geometry
        self.setWindowTitle('Secure Messaging App')
        self.setGeometry(100, 100, 480, 640)

        # Create a read-only text edit to display messages
        self.messages_display = QTextEdit(self)
        self.messages_display.setReadOnly(True)

        # Create a text edit for message input
        self.message_input = QTextEdit(self)
        self.message_input.setFixedHeight(100)
        # Set up an event filter to send messages on enter key press
        self.message_input.installEventFilter(self)

        # Create a button to send messages
        self.send_button = QPushButton('Send', self)
        # Connect the button click to the send_message function
        self.send_button.clicked.connect(self.send_message)

        # Create a combo box for user selection (Alice or Bob)
        self.user_select = QComboBox(self)
        self.user_select.addItems(["Alice", "Bob"])
        # Set the initial user and connect changes to the switch_user function
        self.user_select.setCurrentText(self.chat_client.username)
        self.user_select.currentIndexChanged.connect(self.switch_user)

        # Set up the layout for the GUI components
        user_layout = QHBoxLayout()
        user_layout.addWidget(QLabel("User:"))
        user_layout.addWidget(self.user_select)

        layout = QVBoxLayout()
        layout.addLayout(user_layout)
        layout.addWidget(self.messages_display)
        layout.addWidget(self.message_input)
        layout.addWidget(self.send_button)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def send_message(self):
        # Get the text from the input field and send it as a message
        message_text = self.message_input.toPlainText().strip()
        if message_text:
            # Send the message using the ChatClient instance
            self.chat_client.send_message(message_text)
            # Append the message to the message display in the GUI
            self.messages_display.append(f"{self.chat_client.username}: {message_text}")
            # Clear the message input field
            self.message_input.clear()

    def switch_user(self):
        # Switch the username in the ChatClient instance when the selection changes
        self.chat_client.username = self.user_select.currentText()

    def eventFilter(self, source, event):
        # Filter events to catch the enter key press in the message input field
        if (event.type() == QEvent.KeyRelease and source is self.message_input):
            if event.key() == Qt.Key_Return and not event.isAutoRepeat():
                # If enter is pressed without any modifier keys, send the message
                if not event.modifiers():
                    self.send_message()
                    return True
        # Pass other events to the base class event handler
        return super(MessagingApp, self).eventFilter(source, event)

def main():
    # Set up the application, create a ChatClient instance, and start the GUI
    signal = Signal()
    app = QApplication(sys.argv)
    chat_client = ChatClient(signal)
    main_window = MessagingApp(chat_client)
    # Connect the received signal to append messages to the display
    signal.received.connect(main_window.messages_display.append)
    main_window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
