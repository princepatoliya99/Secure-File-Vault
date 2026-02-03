import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog, scrolledtext
import os
import json
import base64
import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

# --- Constants ---
VAULT_FILENAME = "vault.dat"
SALT_SIZE = 16
NONCE_SIZE = 12  # AES-GCM recommended nonce size
KEY_SIZE = 32    # AES 256
PBKDF2_ITERATIONS = 600000  # Increased for better security (OWASP recommendation)
MAX_LOGIN_ATTEMPTS = 3

class SecureVaultApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Vault")
        self.root.geometry("500x400")
        self.root.resizable(False, False)

        # App state
        self.master_key = None
        self.vault_salt = None
        self.vault_contents = {"files": {}, "logs": []}
        self.failed_attempts = 0

        # Style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TButton', padding=6, relief="flat", font=('Inter', 10, 'bold'))
        self.style.configure('TLabel', font=('Inter', 10))
        self.style.configure('TEntry', padding=5)
        self.style.configure('Header.TLabel', font=('Inter', 16, 'bold'))

        # Main frame
        self.main_frame = ttk.Frame(root, padding="20 20 20 20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.check_vault_exists()

    def check_vault_exists(self):
        """Checks if the vault file exists and shows the appropriate screen."""
        if os.path.exists(VAULT_FILENAME):
            self.show_login_screen()
        else:
            self.show_create_vault_screen()

    def clear_frame(self):
        """Destroys all widgets in the main frame."""
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    # --- Key Derivation and Crypto ---

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derives a 32-byte key from a password and salt using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS
        )
        return kdf.derive(password.encode('utf-8'))

    def save_vault(self):
        """Encrypts and saves the entire vault_contents to disk."""
        if not self.master_key or not self.vault_salt:
            messagebox.showerror("Error", "Vault is not properly initialized.")
            return

        try:
            # Serialize vault contents
            data_to_encrypt = json.dumps(self.vault_contents).encode('utf-8')

            # Encrypt the entire vault blob
            aesgcm = AESGCM(self.master_key)
            nonce = os.urandom(NONCE_SIZE)
            ciphertext_with_tag = aesgcm.encrypt(nonce, data_to_encrypt, None)

            # Write to file: salt + nonce + encrypted_data
            with open(VAULT_FILENAME, 'wb') as f:
                f.write(self.vault_salt)
                f.write(nonce)
                f.write(ciphertext_with_tag)
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save vault: {e}")

    def load_vault(self, password: str) -> bool:
        """Loads and decrypts the vault file using the provided password."""
        try:
            with open(VAULT_FILENAME, 'rb') as f:
                # Read components: salt(16) + nonce(12) + data
                self.vault_salt = f.read(SALT_SIZE)
                nonce = f.read(NONCE_SIZE)
                ciphertext_with_tag = f.read()

            # Derive key
            self.master_key = self.derive_key(password, self.vault_salt)
            
            # Decrypt
            aesgcm = AESGCM(self.master_key)
            decrypted_data = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
            
            # Load contents
            self.vault_contents = json.loads(decrypted_data.decode('utf-8'))
            return True
        except (FileNotFoundError, IOError):
            messagebox.showerror("Error", "Vault file not found.")
            return False
        except InvalidTag:
            # This is the expected error for a wrong password
            return False
        except Exception as e:
            messagebox.showerror("Load Error", f"Failed to load vault: {e}")
            return False

    def log_activity(self, message: str):
        """Adds a timestamped log entry to the vault."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.vault_contents["logs"].append(f"{now}: {message}")
        # Note: save_vault() must be called after this to persist the log.

    # --- GUI Screens ---

    def show_create_vault_screen(self):
        """Displays the UI for creating a new vault and password."""
        self.clear_frame()
        
        ttk.Label(self.main_frame, text="Create New Vault", style='Header.TLabel').pack(pady=20)
        
        ttk.Label(self.main_frame, text="Create a strong master password:").pack(pady=(10, 5))
        
        self.password_entry = ttk.Entry(self.main_frame, show="*")
        self.password_entry.pack(pady=5, padx=20, fill=tk.X)
        
        ttk.Label(self.main_frame, text="Confirm password:").pack(pady=(10, 5))
        
        self.confirm_password_entry = ttk.Entry(self.main_frame, show="*")
        self.confirm_password_entry.pack(pady=5, padx=20, fill=tk.X)

        self.create_button = ttk.Button(
            self.main_frame, 
            text="Create Vault", 
            command=self.handle_create_vault
        )
        self.create_button.pack(pady=30)
        
        self.root.bind('<Return>', lambda e: self.create_button.invoke())

    def show_login_screen(self):
        """Displays the UI for logging into an existing vault."""
        self.clear_frame()
        
        ttk.Label(self.main_frame, text="Secure Vault Login", style='Header.TLabel').pack(pady=20)
        
        ttk.Label(self.main_frame, text="Enter master password:").pack(pady=(10, 5))
        
        self.password_entry = ttk.Entry(self.main_frame, show="*")
        self.password_entry.pack(pady=5, padx=20, fill=tk.X)
        self.password_entry.focus()

        self.login_button = ttk.Button(
            self.main_frame, 
            text="Login", 
            command=self.handle_login
        )
        self.login_button.pack(pady=30)
        
        self.root.bind('<Return>', lambda e: self.login_button.invoke())

    def show_main_vault_screen(self):
        """Displays the main vault interface for file management."""
        self.clear_frame()
        self.root.geometry("600x500") # Resize for main view
        
        # --- Top Frame for Buttons ---
        top_frame = ttk.Frame(self.main_frame)
        top_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(top_frame, text="Add File", command=self.handle_add_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="Export File", command=self.handle_export_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="Delete File", command=self.handle_delete_file).pack(side=tk.LEFT, padx=5)
        
        # --- Right-aligned buttons ---
        ttk.Button(top_frame, text="Lock Vault", command=self.handle_lock_vault).pack(side=tk.RIGHT, padx=5)
        ttk.Button(top_frame, text="View Logs", command=self.handle_view_logs).pack(side=tk.RIGHT, padx=5)
        
        # --- File List ---
        list_frame = ttk.Frame(self.main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL)
        self.file_listbox = tk.Listbox(
            list_frame, 
            yscrollcommand=scrollbar.set, 
            font=('Inter', 11),
            height=15
        )
        scrollbar.config(command=self.file_listbox.yview)
        
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.update_file_list()

    def update_file_list(self):
        """Refreshes the file listbox with files from vault_contents."""
        self.file_listbox.delete(0, tk.END)
        files = sorted(self.vault_contents.get("files", {}).keys())
        if not files:
            self.file_listbox.insert(tk.END, "Vault is empty. Click 'Add File' to start.")
        for filename in files:
            self.file_listbox.insert(tk.END, filename)

    # --- Button Handlers ---

    def handle_create_vault(self):
        """Validates and creates a new vault file."""
        password = self.password_entry.get()
        confirm = self.confirm_password_entry.get()
        
        if not password or not confirm:
            messagebox.showwarning("Input Error", "Password fields cannot be empty.")
            return
            
        if password != confirm:
            messagebox.showwarning("Input Error", "Passwords do not match.")
            return

        # Create vault
        self.vault_salt = os.urandom(SALT_SIZE)
        self.master_key = self.derive_key(password, self.vault_salt)
        self.vault_contents = {"files": {}, "logs": []}
        self.log_activity("Vault created.")
        self.save_vault()
        
        messagebox.showinfo("Success", "Vault created successfully.")
        self.show_main_vault_screen()

    def handle_login(self):
        """Validates login credentials and handles lockout."""
        password = self.password_entry.get()
        
        if self.load_vault(password):
            self.failed_attempts = 0
            messagebox.showinfo("Login Success", "Welcome back.")
            self.log_activity("User logged in.")
            self.save_vault() # Save the new log entry
            self.show_main_vault_screen()
        else:
            self.failed_attempts += 1
            remaining = MAX_LOGIN_ATTEMPTS - self.failed_attempts
            if remaining > 0:
                messagebox.showwarning("Login Failed", f"Invalid password. {remaining} attempts remaining.")
            else:
                messagebox.showerror("Vault Locked", "Too many failed login attempts. The application will now close.")
                self.root.destroy()

    def handle_add_file(self):
        """Opens file dialog to add a file, encrypts, and saves it to the vault."""
        filepath = filedialog.askopenfilename()
        if not filepath:
            return
            
        filename = os.path.basename(filepath)
        if filename in self.vault_contents["files"]:
            if not messagebox.askyesno("Overwrite", f"'{filename}' already exists. Overwrite?"):
                return

        try:
            with open(filepath, 'rb') as f:
                file_content = f.read()

            # Encrypt file content
            aesgcm = AESGCM(self.master_key)
            nonce = os.urandom(NONCE_SIZE)
            encrypted_content = aesgcm.encrypt(nonce, file_content, None)
            
            # Store as base64: nonce + encrypted_data
            stored_data = base64.b64encode(nonce + encrypted_content).decode('utf-8')
            self.vault_contents["files"][filename] = stored_data
            
            self.log_activity(f"Added file: {filename}")
            self.save_vault()
            self.update_file_list()
            messagebox.showinfo("Success", f"'{filename}' added to vault.")
            
        except Exception as e:
            messagebox.showerror("Add File Error", f"Failed to add file: {e}")

    def handle_export_file(self):
        """Decrypts a selected file and saves it to disk."""
        try:
            selected_index = self.file_listbox.curselection()
            if not selected_index:
                messagebox.showwarning("No Selection", "Please select a file to export.")
                return
            
            filename = self.file_listbox.get(selected_index)
        except tk.TclError:
             messagebox.showwarning("No Selection", "Please select a file to export.")
             return
        
        save_path = filedialog.asksaveasfilename(initialfile=filename)
        if not save_path:
            return

        try:
            # Retrieve and decode
            b64_data = self.vault_contents["files"][filename]
            full_data = base64.b64decode(b64_data)
            
            # Split nonce and ciphertext
            nonce = full_data[:NONCE_SIZE]
            encrypted_content = full_data[NONCE_SIZE:]
            
            # Decrypt
            aesgcm = AESGCM(self.master_key)
            decrypted_content = aesgcm.decrypt(nonce, encrypted_content, None)
            
            # Write to disk
            with open(save_path, 'wb') as f:
                f.write(decrypted_content)
                
            self.log_activity(f"Exported file: {filename}")
            self.save_vault() # Save log
            messagebox.showinfo("Success", f"'{filename}' exported successfully.")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export file: {e}")

    def handle_delete_file(self):
        """Removes a selected file from the vault."""
        try:
            selected_index = self.file_listbox.curselection()
            if not selected_index:
                messagebox.showwarning("No Selection", "Please select a file to delete.")
                return
            
            filename = self.file_listbox.get(selected_index)
        except tk.TclError:
             messagebox.showwarning("No Selection", "Please select a file to delete.")
             return

        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to permanently delete '{filename}'?"):
            try:
                del self.vault_contents["files"][filename]
                self.log_activity(f"Deleted file: {filename}")
                self.save_vault()
                self.update_file_list()
                messagebox.showinfo("Deleted", f"'{filename}' has been deleted.")
            except Exception as e:
                messagebox.showerror("Delete Error", f"Failed to delete file: {e}")

    def handle_view_logs(self):
        """Displays the access and activity logs in a new window."""
        log_window = tk.Toplevel(self.root)
        log_window.title("Activity Logs")
        log_window.geometry("600x400")
        
        log_text = scrolledtext.ScrolledText(log_window, wrap=tk.WORD, font=('Monaco', 10))
        log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        log_text.insert(tk.END, "--- Secure Vault Activity Log ---\n\n")
        
        if self.vault_contents["logs"]:
            for entry in reversed(self.vault_contents["logs"]):
                log_text.insert(tk.END, f"{entry}\n")
        else:
            log_text.insert(tk.END, "No activity to display.")
            
        log_text.config(state=tk.DISABLED) # Make read-only
        
        # Log this action
        self.log_activity("Viewed activity logs.")
        self.save_vault()

    def handle_lock_vault(self):
        """Locks the vault, clears memory, and returns to login screen."""
        # Clear sensitive data from memory
        self.master_key = None
        self.vault_contents = {"files": {}, "logs": []}
        self.vault_salt = None
        
        # Reset UI
        self.root.geometry("500x400") # Resize back
        self.show_login_screen()


# --- Main execution ---
if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = SecureVaultApp(root)
        root.mainloop()
    except Exception as e:
        # Fallback for unexpected errors
        print(f"A critical error occurred: {e}")
        # Try to show a simple tkinter error box if root is still available
        try:
            messagebox.showerror("Critical Error", f"A critical error occurred: {e}\n\nThe application will close.")
        except:
            pass
