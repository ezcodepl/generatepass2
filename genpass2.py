import customtkinter as ctk
import random
import string
import pyperclip
from tkinter import filedialog

def generate_password():
    length = int(length_var.get())
    characters = ""
    if uppercase_var.get():
        characters += string.ascii_uppercase
    if lowercase_var.get():
        characters += string.ascii_lowercase
    if digits_var.get():
        characters += string.digits
    if special_var.get():
        characters += string.punctuation
    if not characters:
        return None
    password = "".join(random.choice(characters) for _ in range(length))
    return password

def copy_password():
    pyperclip.copy(password_var.get())

def generate_password_list():
    password_list_box.delete("1.0", "end")
    password_list.clear()
    num_passwords = int(num_passwords_var.get())
    for _ in range(num_passwords):
        password = generate_password()
        if password:
            password_list.append(password)
            password_list_box.insert("end", password + "\n")

def save_to_txt():
    if not password_list:
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, 'w') as f:
            f.write("\n".join(password_list))

def save_to_csv():
    if not password_list:
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if file_path:
        with open(file_path, 'w') as f:
            for password in password_list:
                f.write(password + "\n")

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

root = ctk.CTk()
root.title("Generator Haseł ver. 2.0 autor Ernest Zając")
root.geometry("760x500")

password_var = ctk.StringVar()
length_var = ctk.IntVar(value=20)
uppercase_var = ctk.BooleanVar(value=True)
lowercase_var = ctk.BooleanVar(value=True)
digits_var = ctk.BooleanVar(value=True)
special_var = ctk.BooleanVar(value=False)
num_passwords_var = ctk.IntVar(value=5)
password_list = []

ctk.CTkEntry(root, textvariable=password_var, width=400, font=("Arial", 16)).grid(row=0, column=0, columnspan=3, padx=10, pady=10)
ctk.CTkButton(root, text="SKOPIUJ", command=copy_password).grid(row=0, column=3, padx=10)
ctk.CTkButton(root, text="Odśwież", command=lambda: password_var.set(generate_password())).grid(row=0, column=4, padx=10)

ctk.CTkLabel(root, text="Długość hasła").grid(row=1, column=0, padx=10, pady=10)
ctk.CTkEntry(root, textvariable=length_var, width=50).grid(row=1, column=1)
ctk.CTkSlider(root, from_=8, to=32, variable=length_var, orientation="horizontal").grid(row=1, column=2, columnspan=3, padx=10)

ctk.CTkCheckBox(root, text="Wielkie litery", variable=uppercase_var).grid(row=2, column=0, pady=10)
ctk.CTkCheckBox(root, text="Małe litery", variable=lowercase_var).grid(row=2, column=1, pady=10)
ctk.CTkCheckBox(root, text="Cyfry", variable=digits_var).grid(row=2, column=2, pady=10)
ctk.CTkCheckBox(root, text="Znaki specjalne", variable=special_var).grid(row=2, column=3, pady=10)

ctk.CTkLabel(root, text="Ile haseł wygenerować?").grid(row=3, column=0, padx=10, pady=10)
ctk.CTkEntry(root, textvariable=num_passwords_var, width=50).grid(row=3, column=1)
ctk.CTkSlider(root, from_=1, to=50, variable=num_passwords_var, orientation="horizontal").grid(row=3, column=2, columnspan=3, padx=10)

ctk.CTkButton(root, text="Generuj listę haseł", command=generate_password_list).grid(row=4, column=0, columnspan=5, padx=10, pady=10)

password_list_box = ctk.CTkTextbox(root, width=500, height=200, font=("Courier", 14), fg_color="black", text_color="lime")
password_list_box.grid(row=5, column=0, columnspan=5, padx=10, pady=10)

ctk.CTkButton(root, text="Zapisz do TXT", command=save_to_txt).grid(row=6, column=0, columnspan=2, padx=10, pady=10)
ctk.CTkButton(root, text="Zapisz do CSV", command=save_to_csv).grid(row=6, column=3, columnspan=2, padx=10, pady=10)

root.mainloop()

