import socket
import os
from crypto_utils import encrypt_file
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

SERVER_HOST = '127.0.0.1'
PORT = 5001
CHUNK_SIZE = 4096

# Load server public key
try:
    with open("public_key.pem", "rb") as f:
        server_public_key = serialization.load_pem_public_key(f.read())
except Exception as e:
    print(f"❌ Failed to load server public key: {e}")
    exit(1)

filename = "secret.txt"
try:
    file_size = os.path.getsize(filename)
    file = open(filename, "rb")
except FileNotFoundError:
    print(f"❌ File '{filename}' not found.")
    exit(1)

aes_key = os.urandom(32)
iv = os.urandom(16)

# Encrypt the file in chunks
encrypted_chunks = []
while True:
    chunk = file.read(CHUNK_SIZE)
    if not chunk:
        break
    encrypted_chunk = encrypt_file(chunk, aes_key, iv)
    encrypted_chunks.append(encrypted_chunk)

file.close()
encrypted_data = b"".join(encrypted_chunks)

# Encrypt AES key
try:
    encrypted_key = server_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
except Exception as e:
    print(f"❌ AES key encryption failed: {e}")
    exit(1)

# Send data to server
try:
    client_socket = socket.socket()
    client_socket.connect((SERVER_HOST, PORT))

    client_socket.sendall(len(encrypted_key).to_bytes(4, 'big'))
    client_socket.sendall(encrypted_key)
    client_socket.sendall(iv)
    client_socket.sendall(len(filename.encode()).to_bytes(4, 'big'))
    client_socket.sendall(filename.encode())
    client_socket.sendall(len(encrypted_data).to_bytes(8, 'big'))
    client_socket.sendall(encrypted_data)

    client_socket.close()
    print("✅ File sent securely.")
except Exception as e:
    print(f"❌ Error during transmission: {e}")
