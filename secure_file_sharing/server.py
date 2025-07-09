import socket
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from datetime import datetime

def decrypt_file(encrypted_data, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

# Server setup
SERVER_HOST = '0.0.0.0'
PORT = 5001

server_socket = socket.socket()
server_socket.bind((SERVER_HOST, PORT))
server_socket.listen(5)

print(f"📡 Server listening on port {PORT}...")

try:
    while True:
        client_socket, addr = server_socket.accept()
        print(f"🔗 Connection received from {addr}")

        try:
            # Receive encrypted AES key
            enc_key_len = int.from_bytes(client_socket.recv(4), 'big')
            encrypted_key = client_socket.recv(enc_key_len)

            # Receive IV
            iv = client_socket.recv(16)

            # Receive filename
            filename_len = int.from_bytes(client_socket.recv(4), 'big')
            filename = client_socket.recv(filename_len).decode()

            # Receive encrypted file data
            encrypted_data_len = int.from_bytes(client_socket.recv(8), 'big')
            encrypted_data = b''
            while len(encrypted_data) < encrypted_data_len:
                encrypted_data += client_socket.recv(min(4096, encrypted_data_len - len(encrypted_data)))

            # Load private RSA key
            with open("private_key.pem", "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)

            # Decrypt AES key using private RSA key
            aes_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Decrypt the file
            file_data = decrypt_file(encrypted_data, aes_key, iv)
            print("📦 Decryption completed.")

            # Save the received file
            with open("received_" + filename, "wb") as f:
                f.write(file_data)

            print(f"✅ File received and saved as: received_{filename}")

            # 🔐 Log the file transfer
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log_entry = f"[{timestamp}] Received '{filename}' from {addr[0]}\n"
            with open("transfer_log.txt", "a") as log_file:
                log_file.write(log_entry)

        except Exception as e:
            print(f"❌ Error while receiving or processing file: {e}")
        finally:
            client_socket.close()

except KeyboardInterrupt:
    print("\n🛑 Server shutting down...")
finally:
    server_socket.close()
