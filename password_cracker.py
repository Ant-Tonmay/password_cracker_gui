import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox

def hash_password(password, algorithm='md5'):
    """
    Hashes a given password using the specified hashing algorithm.
    """
    hash_func = hashlib.new(algorithm)
    hash_func.update(password.encode('utf-8'))
    return hash_func.hexdigest()

def crack_password(hashed_password, dictionary_file, algorithm='md5'):
    """
    Attempts to crack the hashed password using a dictionary attack.
    """
    try:
        with open(dictionary_file, 'r') as file:
            for line in file:
                password = line.strip()
                if hash_password(password, algorithm) == hashed_password:
                    return password
    except FileNotFoundError:
        messagebox.showerror("Error", "Dictionary file not found.")
    return None

def browse_file():
    """
    Open a file dialog to select the dictionary file.
    """
    filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if filename:
        dictionary_entry.delete(0, tk.END)
        dictionary_entry.insert(0, filename)

def start_cracking():
    """
    Start the password cracking process.
    """
    hashed_password = hashed_entry.get()
    dictionary_file = dictionary_entry.get()
    algorithm = algorithm_var.get()
    if not hashed_password or not dictionary_file:
        messagebox.showwarning("Warning", "Please provide both hashed password and dictionary file.")
        return

    result = crack_password(hashed_password, dictionary_file, algorithm)
    if result:
        messagebox.showinfo("Result", f"Password found: {result}")
    else:
        messagebox.showinfo("Result", "Password not found.")

# Create the main window
root = tk.Tk()
root.title("Password Cracker")

# Create and place the widgets
tk.Label(root, text="Hashed Password:").grid(row=0, column=0, padx=10, pady=10)
hashed_entry = tk.Entry(root, width=50)
hashed_entry.grid(row=0, column=1, padx=10, pady=10)

tk.Label(root, text="Dictionary File:").grid(row=1, column=0, padx=10, pady=10)
dictionary_entry = tk.Entry(root, width=50)
dictionary_entry.grid(row=1, column=1, padx=10, pady=10)
tk.Button(root, text="Browse", command=browse_file).grid(row=1, column=2, padx=10, pady=10)

tk.Label(root, text="Hash Algorithm:").grid(row=2, column=0, padx=10, pady=10)
algorithm_var = tk.StringVar(value='md5')
algorithm_menu = tk.OptionMenu(root, algorithm_var, 'md5', 'sha1', 'sha256')
algorithm_menu.grid(row=2, column=1, padx=10, pady=10)

tk.Button(root, text="Start Cracking", command=start_cracking).grid(row=3, column=1, padx=10, pady=20)

# Run the GUI event loop
root.mainloop()
