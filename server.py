import socket
import threading

# Server class that handles incoming connections and messages
class ChatServer:
    def __init__(self, host='127.0.0.1', port=12345):
        # List to keep track of connected client sockets
        self.clients = []
        # Initialize server socket using IPv4 and TCP protocol
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind server socket to a host and port and listen for incoming connections
        self.server_socket.bind((host, port))
        self.server_socket.listen()

    def broadcast(self, message, source):
        # Send a message to all clients except the source of the message
        for client in self.clients:
            if client != source:
                try:
                    # Attempt to send the message to a client
                    client.send(message)
                except Exception as e:
                    # If sending fails, remove the client from the list and close the socket
                    print(f"Error broadcasting message: {e}")
                    self.clients.remove(client)
                    client.close()

    def handle_client(self, client):
        # Handle messages from a client socket in a separate thread
        while True:
            try:
                # Receive data from the client
                message = client.recv(1024)
                # Broadcast the received message to other clients
                self.broadcast(message, client)
            except Exception as e:
                # If an error occurs (e.g., client disconnects), remove the client
                print(f"Error handling message from a client: {e}")
                self.clients.remove(client)
                client.close()
                break

    def receive(self):
        # Continuously accept new connections
        while True:
            # Accept a new client connection
            client, address = self.server_socket.accept()
            print(f"Connected with {str(address)}")
            # Add the new client to the list of clients
            self.clients.append(client)
            # Start a new thread to handle messages from this client
            thread = threading.Thread(target=self.handle_client, args=(client,))
            thread.start()

    def start(self):
        # Start the server to accept connections
        print('Server is running and listening for connections...')
        self.receive()

if __name__ == '__main__':
    # Create and start the chat server
    server = ChatServer()
    server.start()
