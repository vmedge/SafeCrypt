# safecrypt_gui.py

import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64
import secrets

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(filepath: str, password: str):
    with open(filepath, 'rb') as f:
        data = f.read()

    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)

    with open(filepath + '.enc', 'wb') as f:
        f.write(salt + encrypted)

    messagebox.showinfo("Success", "File encrypted successfully!")

def decrypt_file(filepath: str, password: str):
    with open(filepath, 'rb') as f:
        data = f.read()

    salt = data[:16]
    encrypted = data[16:]
    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        decrypted = fernet.decrypt(encrypted)
        output_path = filepath.replace('.enc', '.dec')
        with open(output_path, 'wb') as f:
            f.write(decrypted)
        messagebox.showinfo("Success", f"File decrypted successfully! Saved as {output_path}")
    except Exception as e:
        messagebox.showerror("Error", "Invalid password or corrupted file!")

# GUI Setup
app = tk.Tk()
app.title("SafeCrypt - AES256 File Encryption Tool")
app.geometry("400x250")

file_path = tk.StringVar()
password = tk.StringVar()

def browse_file():
    path = filedialog.askopenfilename()
    if path:
        file_path.set(path)

def encrypt():
    if file_path.get() and password.get():
        encrypt_file(file_path.get(), password.get())
    else:
        messagebox.showerror("Error", "Select file and enter password.")

def decrypt():
    if file_path.get() and password.get():
        decrypt_file(file_path.get(), password.get())
    else:
        messagebox.showerror("Error", "Select file and enter password.")

tk.Label(app, text="SafeCrypt", font=("Helvetica", 18, "bold")).pack(pady=10)

tk.Button(app, text="Browse File", command=browse_file).pack()
tk.Entry(app, textvariable=file_path, width=40).pack(pady=5)

tk.Label(app, text="Password").pack()
tk.Entry(app, textvariable=password, show='*', width=30).pack(pady=5)

tk.Button(app, text="Encrypt", command=encrypt, width=15, bg="#4CAF50", fg="white").pack(pady=5)
tk.Button(app, text="Decrypt", command=decrypt, width=15, bg="#f44336", fg="white").pack(pady=5)

app.mainloop()
