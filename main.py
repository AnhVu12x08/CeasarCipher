import tkinter as tk
from tkinter import messagebox
import string


class CaesarCipher:
    def __init__(self):
        self.lowercase_alphabet = list(string.ascii_lowercase)
        self.uppercase_alphabet = list(string.ascii_uppercase)

    def encrypt(self, plaintext, k):
        ciphertext = ''
        k = k % 26
        for letter in plaintext:
            if letter in self.lowercase_alphabet:
                index = (self.lowercase_alphabet.index(letter) + k) % 26
                ciphertext += self.lowercase_alphabet[index]
            elif letter in self.uppercase_alphabet:
                index = (self.uppercase_alphabet.index(letter) + k) % 26
                ciphertext += self.uppercase_alphabet[index]
            else:
                ciphertext += letter
        return ciphertext

    def decrypt(self, ciphertext, k):
        plaintext = ''
        k = k % 26
        for letter in ciphertext:
            if letter in self.lowercase_alphabet:
                index = (self.lowercase_alphabet.index(letter) - k) % 26
                plaintext += self.lowercase_alphabet[index]
            elif letter in self.uppercase_alphabet:
                index = (self.uppercase_alphabet.index(letter) - k) % 26
                plaintext += self.uppercase_alphabet[index]
            else:
                plaintext += letter
        return plaintext

    def brute_force(self, ciphertext):
        results = []
        for k in range(26):
            decrypted_text = self.decrypt(ciphertext, k)
            results.append(f'Key {k}: {decrypted_text}')
        return "\n".join(results)


class GUI:
    def __init__(self, root):
        self.cipher = CaesarCipher()

        root.title("Caesar Cipher")

        self.message_label = tk.Label(root, text="Enter your message:")
        self.message_label.pack()

        self.message_entry = tk.Entry(root, width=50)
        self.message_entry.pack()

        self.mode_label = tk.Label(root, text="Select mode:")
        self.mode_label.pack()

        self.mode_var = tk.StringVar(value="encrypt")
        self.mode_menu = tk.OptionMenu(root, self.mode_var, "encrypt", "decrypt", "brute-force")
        self.mode_menu.pack()

        self.key_label = tk.Label(root, text="Enter key (for encrypt/decrypt):")
        self.key_label.pack()

        self.key_entry = tk.Entry(root, width=10)
        self.key_entry.pack()

        self.output_label = tk.Label(root, text="Output:")
        self.output_label.pack()

        self.output_text = tk.Text(root, height=20, width=80, state=tk.DISABLED)
        self.output_text.pack()

        self.process_button = tk.Button(root, text="Process", command=self.process, fg="red")
        self.process_button.pack()

    def process(self):
        message = self.message_entry.get()
        mode = self.mode_var.get()

        if mode in ['encrypt', 'decrypt']:
            try:
                key = int(self.key_entry.get())
            except ValueError:
                messagebox.showerror("Invalid Input", "Please enter a valid integer for the key.")
                return

            if mode == 'encrypt':
                result = self.cipher.encrypt(message, key)
            else:
                result = self.cipher.decrypt(message, key)
        elif mode == 'brute-force':
            result = self.cipher.brute_force(message)
        else:
            result = "Invalid mode selected."

        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, result)
        self.output_text.config(state=tk.DISABLED)


if __name__ == "__main__":
    root = tk.Tk()
    app = GUI(root)
    root.mainloop()
