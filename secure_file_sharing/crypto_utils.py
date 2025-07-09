from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_file(file_data, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(file_data) + encryptor.finalize()

def decrypt_file(encrypted_data, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()
