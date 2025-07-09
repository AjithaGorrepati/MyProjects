import os
import socket
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from tkinterdnd2 import DND_FILES, TkinterDnD
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from crypto_utils import encrypt_file
import pandas as pd
from fpdf import FPDF
from datetime import datetime

# GUI App
class SecureFileSenderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure File Sender")
        self.root.geometry("650x540")

        # Server IP + Port
        tk.Label(root, text="Server IP:").grid(row=0, column=0)
        self.ip_entry = tk.Entry(root)
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.grid(row=0, column=1)

        tk.Label(root, text="Port:").grid(row=1, column=0)
        self.port_entry = tk.Entry(root)
        self.port_entry.insert(0, "5001")
        self.port_entry.grid(row=1, column=1)

        # File Selection
        tk.Label(root, text="File to send:").grid(row=2, column=0)
        self.file_entry = tk.Entry(root, width=45)
        self.file_entry.grid(row=2, column=1)
        self.file_entry.drop_target_register(DND_FILES)
        self.file_entry.dnd_bind('<<Drop>>', lambda e: self.file_entry.delete(0, tk.END) or self.file_entry.insert(0, e.data))

        tk.Button(root, text="📂 Browse", command=self.browse_file).grid(row=2, column=2)

        # Buttons
        tk.Button(root, text="📤 Send File", bg="green", fg="white", command=self.send_file).grid(row=3, column=1, pady=10)
        tk.Button(root, text="📄 View Log", command=self.view_log).grid(row=4, column=0)
        tk.Button(root, text="⬇️ Export CSV", command=lambda: self.export_log("csv")).grid(row=4, column=1)
        tk.Button(root, text="⬇️ Export PDF", command=lambda: self.export_log("pdf")).grid(row=4, column=2)

        # Log box
        self.log_text = scrolledtext.ScrolledText(root, height=12, width=80)
        self.log_text.grid(row=5, column=0, columnspan=3, padx=10, pady=10)

        # Received content box
        tk.Label(root, text="📬 Last Received File Content:").grid(row=6, column=0, columnspan=3)
        self.received_box = scrolledtext.ScrolledText(root, height=10, width=80)
        self.received_box.grid(row=7, column=0, columnspan=3, padx=10, pady=5)

        # Load last received file if exists
        self.load_received_file()

    def browse_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, filepath)

    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)

    def view_log(self):
        try:
            with open("transfer_log.txt", "r") as f:
                content = f.read()
            self.log_text.delete(1.0, tk.END)
            self.log_text.insert(tk.END, content)
        except FileNotFoundError:
            self.log("⚠️ No log file found.")

    def export_log(self, format="csv"):
        try:
            with open("transfer_log.txt", "r") as f:
                lines = f.readlines()

            df = pd.DataFrame(lines, columns=["Log"])
            if format == "csv":
                df.to_csv("transfer_log_export.csv", index=False)
                messagebox.showinfo("Exported", "✅ Log exported to CSV.")
            elif format == "pdf":
                pdf = FPDF()
                pdf.add_page()
                pdf.set_font("Arial", size=12)
                for line in lines:
                    pdf.cell(200, 10, txt=line.strip(), ln=True)
                pdf.output("transfer_log_export.pdf")
                messagebox.showinfo("Exported", "✅ Log exported to PDF.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def load_received_file(self):
        try:
            with open("received_secret.txt", "r") as f:
                content = f.read()
            self.received_box.delete(1.0, tk.END)
            self.received_box.insert(tk.END, content)
        except FileNotFoundError:
            self.received_box.insert(tk.END, "⚠️ No received file found.")

    def send_file(self):
        ip = self.ip_entry.get()
        port = int(self.port_entry.get())
        filepath = self.file_entry.get()

        if not os.path.exists(filepath):
            messagebox.showerror("File Error", "Selected file does not exist.")
            return

        try:
            with open("public_key.pem", "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())

            with open(filepath, "rb") as f:
                file_data = f.read()

            aes_key = os.urandom(32)
            iv = os.urandom(16)
            encrypted_data = encrypt_file(file_data, aes_key, iv)

            encrypted_key = public_key.encrypt(
                aes_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )

            client_socket = socket.socket()
            client_socket.connect((ip, port))
            filename = os.path.basename(filepath)

            # Send encrypted key
            client_socket.sendall(len(encrypted_key).to_bytes(4, 'big') + encrypted_key)
            client_socket.sendall(iv)
            client_socket.sendall(len(filename.encode()).to_bytes(4, 'big') + filename.encode())
            client_socket.sendall(len(encrypted_data).to_bytes(8, 'big') + encrypted_data)

            client_socket.close()

            # Auto-log
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_line = f"[{timestamp}] Sent: {filename} to {ip}:{port}\n"
            with open("transfer_log.txt", "a") as log_file:
                log_file.write(log_line)

            self.log("✅ File sent securely.")
            self.log(log_line.strip())

        except Exception as e:
            self.log(f"❌ Error: {e}")
            messagebox.showerror("Sending Error", str(e))


# Run GUI
if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = SecureFileSenderGUI(root)
    root.mainloop()
