import socket
#from cryptography.fernet import Fernet
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
        count = 0
        while True:

            conn, addr = server_socket.accept()  # Accept a connection
            with conn:
                print(f"Connected by {addr}")

                encrypted_data = conn.recv(1024)  # Receive encrypted data
                # if not encrypted_data:
                #     print("Connection closed.")
                #     break  # Exit if no data is received
                try:
                    decrypted_data = cipher_suite.decrypt(encrypted_data)  # Decrypt the data
                    print(f"Received: {decrypted_data.decode()}")  # Print the decrypted message
                    count = count + 1
                    # Send a response back to the client
                    response_message = f"ACK {count} Acknowledged"  # input("Enter your response: ")
                    encrypted_response = cipher_suite.encrypt(response_message.encode())
                    conn.sendall(encrypted_response)  # Send encrypted response
                except Exception as e:
                    print(f"Decryption failed: {e}")


if __name__ == "__main__":
    secure_server()
