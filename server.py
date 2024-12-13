import socket
import random
from Crypto.Cipher import AES
import hashlib

# Diffie-Hellman parameters (small for simplicity in demonstration)
P = 23  # Prime number
G = 5   # Generator

# Function to derive AES key from shared key
def derive_aes_key(shared_key):
    return hashlib.sha256(str(shared_key).encode('utf-8')).digest()

# AES encryption
def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return cipher.nonce, ciphertext, tag

# Start the server
def start_server():
    HOST = '127.0.0.1'  # Localhost
    PORT = 65432        # Arbitrary port

    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()

    print("Server is listening...")
    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    # Handle communication
    handle_client(conn)

    conn.close()

# Handle client connection
def handle_client(conn):
    # Server generates private key and public key
    server_private = random.randint(1, P - 1)
    server_public = pow(G, server_private, P)

    # Send public key to client
    print(f"Sending server's public key: {server_public}")
    conn.send(str(server_public).encode('utf-8'))

    # Receive public key from client
    client_public = int(conn.recv(1024).decode('utf-8'))
    print(f"Received client's public key: {client_public}")

    # Compute shared key
    shared_key = pow(client_public, server_private, P)
    print(f"Computed shared key: {shared_key}")

    # Send handshake confirmation
    handshake_message = "Handshake successful!"
    print(f"Sending handshake confirmation: {handshake_message}")
    conn.send(handshake_message.encode('utf-8'))

    # Derive AES key from shared key
    aes_key = derive_aes_key(shared_key)

    # Encrypt and send a message to the client
    nonce, ciphertext, tag = encrypt_message(aes_key, "Encrypted data packet")
    print(f"Sending encrypted packet to client: {ciphertext.hex()} (nonce: {nonce.hex()}, tag: {tag.hex()})")
    conn.send(nonce + ciphertext + tag)

if __name__ == "__main__":
    start_server()
