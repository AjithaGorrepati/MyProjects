from crypto_utils import encrypt_file, decrypt_file
import os

# Message to encrypt
data = b"This is a secret message."

# Generate AES key and IV
key = os.urandom(32)  # 256-bit key
iv = os.urandom(16)   # 128-bit IV

# Encrypt and decrypt
encrypted = encrypt_file(data, key, iv)
decrypted = decrypt_file(encrypted, key, iv)

# Output
print("🔐 Encrypted:", encrypted)
print("🔓 Decrypted:", decrypted.decode())
