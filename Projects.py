import tkinter as tk
from tkinter import ttk
import numpy as np

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption App")

        self.selected_cipher = tk.StringVar()

        # Cipher options
        self.cipher_options = ["Caesar Cipher", "Hill Cipher", "Rail Fence Cipher", "Vigenere Cipher"]

        # Create UI elements
        self.create_widgets()

    def create_widgets(self):
        # Label and Entry for plaintext
        self.plain_text_label = ttk.Label(self.root, text="Enter Plain Text:")
        self.plain_text_label.grid(row=0, column=0, padx=5, pady=5)
        self.plain_text_entry = ttk.Entry(self.root, width=50)
        self.plain_text_entry.grid(row=0, column=1, columnspan=2, padx=5, pady=5)

        # Label and Entry for key
        self.key_label = ttk.Label(self.root, text="Enter Key:")
        self.key_label.grid(row=1, column=0, padx=5, pady=5)
        self.key_entry = ttk.Entry(self.root, width=50)
        self.key_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=5)

        # Drop-down menu for selecting cipher
        self.cipher_label = ttk.Label(self.root, text="Select Cipher:")
        self.cipher_label.grid(row=2, column=0, padx=5, pady=5)
        self.cipher_combobox = ttk.Combobox(self.root, textvariable=self.selected_cipher, values=self.cipher_options, width=20)
        self.cipher_combobox.grid(row=2, column=1, padx=5, pady=5)
        self.cipher_combobox.current(0)

        # Encrypt Button
        self.encrypt_button = ttk.Button(self.root, text="Encrypt", command=self.encrypt)
        self.encrypt_button.grid(row=3, column=0, columnspan=3, padx=5, pady=5)

        # Label and Entry for encrypted text
        self.encrypted_text_label = ttk.Label(self.root, text="Encrypted Text:")
        self.encrypted_text_label.grid(row=4, column=0, padx=5, pady=5)
        self.encrypted_text_entry = ttk.Entry(self.root, width=50, state='readonly')
        self.encrypted_text_entry.grid(row=4, column=1, columnspan=2, padx=5, pady=5)

    def encrypt(self):
        plain_text = self.plain_text_entry.get()
        key = self.key_entry.get()
        cipher_type = self.selected_cipher.get()

        if cipher_type == "Caesar Cipher":
            encrypted_text = self.caesar_cipher_encrypt(plain_text, int(key))
        elif cipher_type == "Hill Cipher":
            encrypted_text = self.hill_cipher_encrypt(plain_text, key)
        elif cipher_type == "Rail Fence Cipher":
            encrypted_text = self.rail_fence_cipher_encrypt(plain_text, int(key))
        elif cipher_type == "Vigenere Cipher":
            encrypted_text = self.vigenere_cipher_encrypt(plain_text, key)

        self.encrypted_text_entry.config(state='normal')
        self.encrypted_text_entry.delete(0, tk.END)
        self.encrypted_text_entry.insert(0, encrypted_text)
        self.encrypted_text_entry.config(state='readonly')

    def caesar_cipher_encrypt(self, plain_text, shift):
        encrypted_text = ""
        for char in plain_text:
            if char.isalpha():
                if char.isupper():
                    encrypted_text += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
                else:
                    encrypted_text += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            else:
                encrypted_text += char
        return encrypted_text

    def hill_cipher_encrypt(self, plain_text, key):
        # Convert the plain text to uppercase and remove spaces
        plain_text = plain_text.upper().replace(" ", "")
        
        # Generate the key matrix
        key_matrix = np.array([[ord(char) - ord('A') for char in key[i]] for i in range(len(key))])
        
        # Pad the plaintext with 'X' if its length is not a multiple of the key matrix size
        while len(plain_text) % key_matrix.shape[0] != 0:
            plain_text += 'X'

        # Reshape the plain text into blocks based on the key matrix size
        plain_text_blocks = [plain_text[i:i + key_matrix.shape[0]] for i in range(0, len(plain_text), key_matrix.shape[0])]

        encrypted_text = ""
        
        for block in plain_text_blocks:
            # Convert the block into a column vector
            block_vector = np.array([[ord(char) - ord('A')] for char in block])
            
            # Perform matrix multiplication
            result_vector = np.dot(key_matrix, block_vector) % 26
            
            # Convert the resulting vector back to characters
            encrypted_text += ''.join([chr(result_vector[i][0] + ord('A')) for i in range(len(result_vector))])

        return encrypted_text

    def rail_fence_cipher_encrypt(self, plain_text, key):
        encrypted_text = ""
        rail_fence = [[] for _ in range(int(key))]
        direction = 1
        row = 0

        for char in plain_text:
            rail_fence[row].append(char)
            row += direction

            if row == int(key) - 1 or row == 0:
                direction *= -1

        for rail in rail_fence:
            encrypted_text += ''.join(rail)

        return encrypted_text

    def vigenere_cipher_encrypt(self, plain_text, key):
        key = key.upper()
        encrypted_text = ""
        key_index = 0

        for char in plain_text:
            if char.isalpha():
                shift = ord(key[key_index % len(key)]) - ord('A')
                if char.isupper():
                    encrypted_text += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
                else:
                    encrypted_text += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
                key_index += 1
            else:
                encrypted_text += char

        return encrypted_text

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
