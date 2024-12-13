import socket
import random
from Crypto.Cipher import AES
import hashlib

# Diffie-Hellman parameters (must match server)
P = 23  # Prime number
G = 5   # Generator

# Function to derive AES key from shared key
def derive_aes_key(shared_key):
    return hashlib.sha256(str(shared_key).encode('utf-8')).digest()

# AES decryption
def decrypt_message(key, nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

# Start the client
def start_client():
    HOST = '127.0.0.1'  # Server address
    PORT = 65432        # Same port as server

    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))

    # Client generates private key and public key
    client_private = random.randint(1, P - 1)
    client_public = pow(G, client_private, P)

    # Receive server's public key
    server_public = int(client_socket.recv(1024).decode('utf-8'))
    print(f"Received server's public key: {server_public}")

    # Send public key to server
    print(f"Sending client's public key: {client_public}")
    client_socket.send(str(client_public).encode('utf-8'))

    # Compute shared key
    shared_key = pow(server_public, client_private, P)
    print(f"Computed shared key: {shared_key}")

    # Receive handshake confirmation
    handshake_confirmation = client_socket.recv(1024).decode('utf-8')
    print(f"Received handshake confirmation: {handshake_confirmation}")

    # Derive AES key from shared key
    aes_key = derive_aes_key(shared_key)

    # Receive encrypted packet from server
    received_data = client_socket.recv(1024)
    nonce, ciphertext, tag = received_data[:16], received_data[16:-16], received_data[-16:]
    print(f"Received encrypted packet (nonce: {nonce.hex()}, ciphertext: {ciphertext.hex()}, tag: {tag.hex()})")

    # Decrypt the message
    decrypted_message = decrypt_message(aes_key, nonce, ciphertext, tag)
    print(f"Decrypted message from server: {decrypted_message}")

    client_socket.close()

if __name__ == "__main__":
    start_client()
