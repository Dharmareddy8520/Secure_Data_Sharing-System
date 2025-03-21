import tkinter as tk
from tkinter import messagebox, ttk
from abe_crypto import ABECrypto
import sys

class SecureDataApp:
    def __init__(self, root):
        self.abe = ABECrypto()
        self.root = root
        self.root.title("Secure Data Sharing System")
        self.root.geometry("600x550")
        self.root.configure(bg="#f0f0f0")

        style = ttk.Style()
        style.configure("TButton", font=("Helvetica", 10), padding=5)
        style.configure("TLabel", font=("Helvetica", 10), background="#f0f0f0")
        style.configure("TEntry", font=("Helvetica", 10))

        self.frame = ttk.Frame(root, padding="10")
        self.frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        ttk.Label(self.frame, text="User ID:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        self.user_id_entry = ttk.Entry(self.frame)
        self.user_id_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(self.frame, text="Attributes (comma-separated):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)
        self.attributes_entry = ttk.Entry(self.frame)
        self.attributes_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(self.frame, text="Message:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.NE)
        self.message_text = tk.Text(self.frame, height=5, width=40, font=("Helvetica", 10), wrap=tk.WORD)
        self.message_text.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(self.frame, text="Policy:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.E)
        self.policy_entry = ttk.Entry(self.frame)
        self.policy_entry.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(self.frame, text="Data ID:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.E)
        self.data_id_entry = ttk.Entry(self.frame)
        self.data_id_entry.grid(row=4, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Button(self.frame, text="Issue AC", command=self.issue_ac).grid(row=5, column=0, padx=5, pady=5)
        ttk.Button(self.frame, text="Encrypt Data", command=self.encrypt_data).grid(row=5, column=1, padx=5, pady=5)
        ttk.Button(self.frame, text="Decrypt Data", command=self.decrypt_data).grid(row=6, column=0, padx=5, pady=5)
        ttk.Button(self.frame, text="Revoke Attribute", command=self.revoke_attribute).grid(row=6, column=1, padx=5, pady=5)
        ttk.Button(self.frame, text="Clear Log", command=self.clear_log).grid(row=7, column=0, columnspan=2, pady=10)

        self.output = tk.Text(self.frame, height=10, width=60, font=("Helvetica", 10), bg="#ffffff", fg="#333333")
        self.output.grid(row=8, column=0, columnspan=2, padx=5, pady=5)

    def log(self, message):
        self.output.insert(tk.END, message + "\n")
        self.output.see(tk.END)
        print(f"[LOG] {message}")

    def clear_log(self):
        self.output.delete(1.0, tk.END)
        print("[LOG] Cleared output log")

    def issue_ac(self):
        try:
            user_id = self.user_id_entry.get().strip()
            attributes = [attr.strip() for attr in self.attributes_entry.get().split(',') if attr.strip()]
            if not user_id:
                messagebox.showerror("Input Error", "User ID is required.")
                self.log("User ID is required.")
                return
            if not attributes:
                messagebox.showerror("Input Error", "At least one attribute is required.")
                self.log("At least one attribute is required.")
                return
            ac = self.abe.issue_ac(user_id, attributes)
            self.log(f"AC Issued: {ac}")
        except Exception as e:
            self.log(f"Error: {e}")
            messagebox.showerror("Error", str(e))

    def encrypt_data(self):
        try:
            # Get message from Text widget and remove trailing newlines/whitespace
            message = self.message_text.get("1.0", tk.END).strip()
            policy = self.policy_entry.get().strip()

            # Check for empty or whitespace-only message
            if not message or message.isspace():
                messagebox.showerror("Input Error", "Message is required.")
                self.log("Message is required.")
                return
            # Check for empty or whitespace-only policy
            if not policy or policy.isspace():
                messagebox.showerror("Input Error", "Policy is required.")
                self.log("Policy is required.")
                return

            data_id = self.abe.encrypt(message, policy)
            self.log(f"Data encrypted with ID: {data_id}")
            self.data_id_entry.delete(0, tk.END)
            self.data_id_entry.insert(0, data_id)
        except Exception as e:
            self.log(f"Error: {e}")
            messagebox.showerror("Error", str(e))

    def decrypt_data(self):
        try:
            user_id = self.user_id_entry.get().strip()
            data_id = self.data_id_entry.get().strip()
            if not user_id:
                messagebox.showerror("Input Error", "User ID is required.")
                self.log("User ID is required.")
                return
            if not data_id:
                messagebox.showerror("Input Error", "Data ID is required.")
                self.log("Data ID is required.")
                return
            message = self.abe.decrypt(user_id, data_id)
            self.log(f"Decrypted Message: {message}")
            messagebox.showinfo("Success", f"Decrypted Message: {message}")
        except Exception as e:
            self.log(f"Error: {e}")
            messagebox.showerror("Error", str(e))

    def revoke_attribute(self):
        try:
            user_id = self.user_id_entry.get().strip()
            attribute = self.attributes_entry.get().split(',')[0].strip()
            if not user_id:
                messagebox.showerror("Input Error", "User ID is required.")
                self.log("User ID is required.")
                return
            if not attribute:
                messagebox.showerror("Input Error", "Attribute to revoke is required.")
                self.log("Attribute to revoke is required.")
                return
            new_ac = self.abe.revoke_attribute(user_id, attribute)
            self.log(f"Updated AC: {new_ac}")
            messagebox.showinfo("Success", f"Attribute revoked. Updated AC: {new_ac}")
        except Exception as e:
            self.log(f"Error: {e}")
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureDataApp(root)
    root.mainloop()