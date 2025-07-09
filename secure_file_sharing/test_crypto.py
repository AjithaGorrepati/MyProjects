from cryptography.fernet import Fernet

print("🟢 Start of Script")

key = Fernet.generate_key()
print("🔐 Encryption Key:", key.decode())

print("✅ End of Script")
