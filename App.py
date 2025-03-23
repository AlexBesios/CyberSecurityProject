import tkinter as tk
from tkinter import ttk
from ttkthemes import ThemedTk
import Ciphers as cp

def perform_action():
    cipher = cipher_var.get()
    action = action_var.get()
    message = message_entry.get()
    key = key_entry.get()

    try:
        if cipher == "Caesar":
            key = int(key)
            result = cp.caesar_encrypt(message, key) if action == "Encrypt" else cp.caesar_decrypt(message, key)
        elif cipher == "Vigenère":
            result = cp.vigenere_encrypt(message, key) if action == "Encrypt" else cp.vigenere_decrypt(message, key)
        elif cipher == "Affine":
            a, b = map(int, key.split(","))
            result = cp.affine_encrypt(message, a, b) if action == "Encrypt" else cp.affine_decrypt(message, a, b)
        elif cipher == "Substitution":
            key_dict = eval(key)
            result = cp.substitution_encrypt(message, key_dict) if action == "Encrypt" else cp.substitution_decrypt(message, key_dict)
        elif cipher == "OTP":
            result = cp.otp_encrypt(message, key) if action == "Encrypt" else cp.otp_decrypt(message, key)
        elif cipher == "Hill":
            import numpy as np
            key_matrix = np.array(eval(key))
            if action == "Encrypt":
                result = cp.hill_encrypt(message, key_matrix)
            else:
                result = cp.hill_decrypt(message, key_matrix)
        else:
            result = "Invalid cipher selected."
    except Exception as e:
        result = f"Error: {e}"

    result_label.config(text=f"Result: {result}")

root = ThemedTk(theme="arc")
root.title("Message Encryptor/Decryptor")
root.geometry("500x400")
root.resizable(False, False)
root.configure(bg="#f0f0f0")

style = ttk.Style()
style.configure("TLabel", font=("Arial", 12), background="#f0f0f0")
style.configure("TButton", font=("Arial", 12), padding=5)
style.configure("TEntry", font=("Arial", 12))
style.configure("TOptionMenu", font=("Arial", 12))

main_frame = ttk.Frame(root, padding="15", style="TFrame")
main_frame.grid(row=0, column=0, sticky="nsew")

def update_cipher(*args):
    cipher_var.set(cipher_var.get())

cipher_frame = ttk.Frame(main_frame, padding="10", style="TFrame")
cipher_frame.grid(row=0, column=0, columnspan=2, sticky="ew")
ttk.Label(cipher_frame, text="Select Cipher:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
cipher_var = tk.StringVar(value="Caesar")
cipher_var.trace_add("write", update_cipher)
cipher_menu = ttk.OptionMenu(cipher_frame, cipher_var, "Caesar", "Caesar", "Vigenère", "Affine", "Substitution", "OTP", "Hill")
cipher_menu.grid(row=0, column=1, padx=10, pady=5, sticky="e")

def update_action(*args):
    action_var.set(action_var.get())

action_frame = ttk.Frame(main_frame, padding="10", style="TFrame")
action_frame.grid(row=1, column=0, columnspan=2, sticky="ew")
ttk.Label(action_frame, text="Select Action:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
action_var = tk.StringVar(value="Encrypt")
action_var.trace_add("write", update_action)
action_menu = ttk.OptionMenu(action_frame, action_var, "Encrypt", "Encrypt", "Decrypt")
action_menu.grid(row=0, column=1, padx=10, pady=5, sticky="e")

message_frame = ttk.Frame(main_frame, padding="10", style="TFrame")
message_frame.grid(row=2, column=0, columnspan=2, sticky="ew")
ttk.Label(message_frame, text="Message:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
message_entry = ttk.Entry(message_frame, width=40)
message_entry.grid(row=0, column=1, padx=10, pady=5, sticky="e")

key_frame = ttk.Frame(main_frame, padding="10", style="TFrame")
key_frame.grid(row=3, column=0, columnspan=2, sticky="ew")
ttk.Label(key_frame, text="Key:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
key_entry = ttk.Entry(key_frame, width=40)
key_entry.grid(row=0, column=1, padx=10, pady=5, sticky="e")

button_frame = ttk.Frame(main_frame, padding="10", style="TFrame")
button_frame.grid(row=4, column=0, columnspan=2, sticky="ew")
action_button = ttk.Button(button_frame, text="Perform", command=perform_action)
action_button.grid(row=0, column=0, pady=10)

result_frame = ttk.Frame(main_frame, padding="10", style="TFrame")
result_frame.grid(row=5, column=0, columnspan=2, sticky="ew")
result_label = ttk.Label(result_frame, text="Result: ", wraplength=400, justify="left")
result_label.grid(row=0, column=0, padx=10, pady=5)

root.mainloop()
