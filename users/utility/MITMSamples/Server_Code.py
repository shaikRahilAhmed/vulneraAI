import socket
from cryptography.fernet import Fernet

# Generate a key for symmetric encryption
key = Fernet.generate_key()  # Key to be shared with the client
cipher_suite = Fernet(key)

print(f"Server encryption key (share this with the client): {key.decode()}")

def secure_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(('localhost', 65432))  # Bind to localhost on port 65432
        server_socket.listen()  # Start listening for incoming connections
        print("Secure server listening on port 65432...")
        
        conn, addr = server_socket.accept()  # Accept a connection
        with conn:
            print(f"Connected by {addr}")
            while True:
                encrypted_data = conn.recv(1024)  # Receive encrypted data
                if not encrypted_data:
                    break  # Exit if no data is received
                try:
                    decrypted_data = cipher_suite.decrypt(encrypted_data)  # Decrypt the data
                    print(f"Received: {decrypted_data.decode()}")  # Print the decrypted message
                except Exception as e:
                    print(f"Decryption failed: {e}")

if __name__ == "__main__":
    secure_server()
