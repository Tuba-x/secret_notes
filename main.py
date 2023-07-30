from tkinter import *
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


window = Tk()
window.title("Secret Notes")
window.config(padx=30, pady=30)

photo_image = PhotoImage(file="top-secret.png").subsample(8, 8)

image_label = Label(image=photo_image)
image_label.pack(pady=5)

title_label = Label(text="Enter your title")
title_label.pack()

title_entry = Entry()
title_entry.pack()

secret_label = Label(text="Enter your secret")
secret_label.pack()

secret_text = Text(width=30, height=10)
secret_text.pack()

password_label = Label(text="Enter your password")
password_label.pack()

password_entry = Entry()
password_entry.pack()

password_label2 = Label()
password_label2.pack()


def make_key(password):
    global f
    input_bytes = password.encode('utf-8')
    salt = b'secret'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = kdf.derive(input_bytes)

    key = base64.urlsafe_b64encode(key)

    f = Fernet(key)


def encrypt_clicked():
    make_key(password_entry.get())
    if len(password_entry.get()) < 8:
        password_label2.config(text="Your password must be 8 characters long")
    else:
        password_label2.config(text="")
        ciphertext = f.encrypt(bytes(secret_text.get("1.0", END)+password_entry.get(), 'UTF-8'))
        decoded = ciphertext.decode('utf8')
        txt_file = open("my_secret.txt", "a")
        txt_file.write(title_entry.get() + "\n" + str(decoded) + "\n")
        title_entry.delete(0, END)
        secret_text.delete("1.0", END)
        password_entry.delete(0, END)


encrypt_button = Button(text="Save & Encrypt", command=encrypt_clicked)
encrypt_button.pack()


def decrypt_clicked():
    try:
        make_key(password_entry.get())
        d = f.decrypt(secret_text.get("1.0", END))
        d = str(d)
        secret_text.delete("1.0", END)
        secret_text.insert("1.0", d[2:-11])
        password_entry.delete(0, END)
        password_label2.config(text="")
    except:
        password_label2.config(text="Your password is wrong")


decrypt_button = Button(text="Decrypt", command=decrypt_clicked)
decrypt_button.pack()


window.mainloop()
