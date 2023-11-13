from tkinter import *
from PIL import ImageTk, Image
from cryptography.fernet import Fernet

FONT = ("Arial", 13, "italic")

window = Tk()
window.minsize(350,500)
window.title("Very Important Secret Notes")
window.config(padx=40, pady=40)


image = Image.open("python.png")
resize_image = image.resize((80, 80))
img = ImageTk.PhotoImage(resize_image)
label = Label(image=img)
label.pack()


title_label = Label(text="Enter Your Title", font=FONT, fg="pink", pady=10)
title_label.pack()
title_entry = Entry(width=25)
title_entry.pack()

secret_label = Label(text="Enter Your Secret", font=FONT, fg="pink", pady=10)
secret_label.pack()
secret_text = Text(width=30, height=25, padx=25, pady=20)
secret_text.pack()

masterkey_label = Label(text="Enter Your Master Key", font=FONT, fg="pink", pady=10)
masterkey_label.pack()
masterkey_entry = Entry(width=25)
masterkey_entry.pack()



def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("secret.key", "rb").read()

def encrypt_message(message, key):
    cipher = Fernet(key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, key):
    cipher = Fernet(key)
    decrypted_message = cipher.decrypt(encrypted_message).decode()
    return decrypted_message

def save_and_encrypt():
    title = title_entry.get()
    secret = secret_text.get("1.0", END)
    master_key = masterkey_entry.get()

    if title and secret and master_key:
        key = load_key()
        encrypted_secret = encrypt_message(secret, key)

        with open(f"{title}.txt", "wb") as file:
            file.write(encrypted_secret)


        title_entry.delete(0, END)
        secret_text.delete("1.0", END)
        masterkey_entry.delete(0, END)


def decrypt():
    title = title_entry.get()
    master_key = masterkey_entry.get()

    if title and master_key:
        key = load_key()

        try:
            with open(f"{title}.txt", "rb") as file:
                encrypted_secret = file.read()
                decrypted_secret = decrypt_message(encrypted_secret, key)
                secret_text.delete("1.0", END)
                secret_text.insert("1.0", decrypted_secret)
        except FileNotFoundError:
            secret_text.delete("1.0", END)
            secret_text.insert("1.0", "File not found.")

generate_key()


save_button = Button(text="Save & Encrypt", command=save_and_encrypt)
save_button.pack()

decrypt_button = Button(text="Decrypt", command=decrypt)
decrypt_button.pack()



window.mainloop()
