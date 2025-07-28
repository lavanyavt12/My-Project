import tkinter as tk
from tkinter import filedialog, messagebox
from client_logic import upload_file, register_user

def login():
    global username, password
    username = username_entry.get()
    password = password_entry.get()
    messagebox.showinfo("Login", f"Logged in as {username}")

def register():
    user = username_entry.get()
    pwd = password_entry.get()
    if register_user(user, pwd):
        messagebox.showinfo("Success", "Registration successful")
    else:
        messagebox.showerror("Error", "Registration failed")

def upload():
    filepath = filedialog.askopenfilename()
    if filepath:
        success = upload_file(username, password, filepath)
        if success:
            messagebox.showinfo("Success", "File uploaded successfully")
        else:
            messagebox.showerror("Error", "File upload failed")

# GUI Setup
root = tk.Tk()
root.title("Encrypted File Transfer")

tk.Label(root, text="Username").pack()
username_entry = tk.Entry(root)
username_entry.pack()

tk.Label(root, text="Password").pack()
password_entry = tk.Entry(root, show='*')
password_entry.pack()

tk.Button(root, text="Register", command=register).pack(pady=5)
tk.Button(root, text="Login", command=login).pack(pady=5)
tk.Button(root, text="Upload File", command=upload).pack(pady=5)

root.mainloop()
