import socket
import threading

# Server class that handles incoming connections and messages
class ChatServer:
    def __init__(self, host='127.0.0.1', port=12345):
        self.clients = []
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen()

    def broadcast(self, message, source):
        for client in self.clients:
            if client != source:
                try:
                    client.send(message)
                except Exception as e:
                    print(f"Error broadcasting message: {e}")
                    self.clients.remove(client)

    def handle_client(self, client):
        while True:
            try:
                message = client.recv(1024)
                self.broadcast(message, client)
            except Exception as e:
                print(f"Error handling message from a client: {e}")
                self.clients.remove(client)
                client.close()
                break

    def receive(self):
        while True:
            client, address = self.server_socket.accept()
            print(f"Connected with {str(address)}")
            self.clients.append(client)
            thread = threading.Thread(target=self.handle_client, args=(client,))
            thread.start()

    def start(self):
        print('Server is running and listening for connections...')
        self.receive()

if __name__ == '__main__':
    server = ChatServer()
    server.start()
