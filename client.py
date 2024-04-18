import sys
import ssl
import socket
import threading
from PyQt5.QtWidgets import QApplication, QMainWindow, QTextEdit, QPushButton, QVBoxLayout, QWidget, QComboBox, QLabel, QHBoxLayout
from PyQt5.QtCore import pyqtSignal, QObject, Qt, QEvent
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Signal class for updating the GUI from a different thread
class Signal(QObject):
    received = pyqtSignal(str)

def get_key(password):
    salt = get_random_bytes(16)  # Generate a secure random salt
    key = PBKDF2(password, salt, dkLen=16, count=1000, hmac_hash_module=SHA256)
    return key, salt

def encrypt_message(plaintext, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    encrypted_msg = b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')
    return encrypted_msg

def decrypt_message(encrypted_msg, key):
    try:
        data = b64decode(encrypted_msg)
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except (ValueError, KeyError) as e:
        return "[Decryption failed]"

# Client class that handles sending and receiving messages
class ChatClient:
    def __init__(self, signal, host='127.0.0.1', port=12345, username="Alice"):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Create SSL context
        context = ssl.create_default_context()
        context.load_verify_locations('/Users/nataliehill/cert.pem')  # Specify the correct path to your certificate

        # Wrap the socket with SSL
        self.secure_socket = context.wrap_socket(self.client_socket, server_hostname=host)
        self.secure_socket.connect((host, port))

        self.signal = signal
        self.username = username
        self.password = "secure_password"
        self.key, self.salt = get_key(self.password)
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def send_message(self, message):
        # Encrypt the message before sending
        encrypted_message = encrypt_message(f"{self.username}: {message}", self.key)
        try:
            self.secure_socket.send(encrypted_message.encode('utf-8'))
        except Exception as e:
            print(f"Error sending message: {e}")

    def receive_messages(self):
        while True:
            try:
                encrypted_message = self.secure_socket.recv(1024).decode('utf-8')
                message = decrypt_message(encrypted_message, self.key)
                self.signal.received.emit(message)
            except Exception as e:
                print(f"Error receiving messages: {e}")
                self.secure_socket.close()
                break

# Main window class for the chat application
class MessagingApp(QMainWindow):
    def __init__(self, chat_client):
        super().__init__()
        self.chat_client = chat_client
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Secure Messaging App')
        self.setGeometry(100, 100, 480, 640)

        self.messages_display = QTextEdit(self)
        self.messages_display.setReadOnly(True)

        self.message_input = QTextEdit(self)
        self.message_input.setFixedHeight(100)
        self.message_input.installEventFilter(self)

        self.send_button = QPushButton('Send', self)
        self.send_button.clicked.connect(self.send_message)

        # Dropdown menu to select the user
        self.user_select = QComboBox(self)
        self.user_select.addItems(["Alice", "Bob"])
        self.user_select.setCurrentText(self.chat_client.username)  # Set initial user
        self.user_select.currentIndexChanged.connect(self.switch_user)  # Auto-switch user on selection

        # Layout for the user selection
        user_layout = QHBoxLayout()
        user_layout.addWidget(QLabel("User:"))
        user_layout.addWidget(self.user_select)

        # Layout for the widgets
        layout = QVBoxLayout()
        layout.addLayout(user_layout)
        layout.addWidget(self.messages_display)
        layout.addWidget(self.message_input)
        layout.addWidget(self.send_button)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def send_message(self):
        message_text = self.message_input.toPlainText().strip()
        if message_text:
            self.chat_client.send_message(message_text)
            self.messages_display.append(f"{self.chat_client.username}: {message_text}")
            self.message_input.clear()

    def switch_user(self):
        self.chat_client.username = self.user_select.currentText()

    def eventFilter(self, source, event):
        if (event.type() == QEvent.KeyRelease and source is self.message_input):
            if event.key() == Qt.Key_Return and not event.isAutoRepeat():
                if not event.modifiers():
                    self.send_message()
                    return True
        return super(MessagingApp, self).eventFilter(source, event)

def main():
    signal = Signal()
    app = QApplication(sys.argv)
    chat_client = ChatClient(signal)
    main_window = MessagingApp(chat_client)
    signal.received.connect(main_window.messages_display.append)
    main_window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()