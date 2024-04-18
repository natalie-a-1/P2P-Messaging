import socket
import threading
import ssl

# Server class that handles incoming connections and messages
class ChatServer:
    def __init__(self, host='127.0.0.1', port=12345):
        self.clients = []
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Create SSL context
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(certfile='/Users/nataliehill/cert.pem', keyfile='/Users/nataliehill/key.pem')  # Adjust these paths

        self.server_socket = self.context.wrap_socket(self.server_socket, server_side=True)
        self.server_socket.bind((host, port))
        self.server_socket.listen()

    def broadcast(self, message, source):
        for client in self.clients:
            if client != source:
                try:
                    # Here you must send data through the secure socket
                    client.send(message)
                except Exception as e:
                    print(f"Error broadcasting message: {e}")
                    self.clients.remove(client)
                    client.close()

    def handle_client(self, client):
        while True:
            try:
                message = client.recv(1024)
                if message:
                    self.broadcast(message, client)
            except Exception as e:
                print(f"Error handling message from a client: {e}")
                self.clients.remove(client)
                client.close()
                break

    def receive(self):
        while True:
            try:
                client, address = self.server_socket.accept()
                print(f"Connected with {str(address)}")
                self.clients.append(client)
                thread = threading.Thread(target=self.handle_client, args=(client,))
                thread.start()
            except Exception as e:
                print(f"Error accepting connections: {e}")

    def start(self):
        print('Server is running and listening for connections...')
        self.receive()

if __name__ == '__main__':
    server = ChatServer()
    server.start()