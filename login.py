import tkinter as tk
from tkinter import messagebox
import sqlite3
import bcrypt
from main import VulnerabilityScannerApp


# Database setup
conn = sqlite3.connect('login_system.db')
c = conn.cursor()
c.execute('''
CREATE TABLE IF NOT EXISTS users (
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL
)
''')
conn.commit()

# Helper functions
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)

# Registration
def register(username, password, role="user"):
    hashed_password = hash_password(password)
    try:
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, role))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

# Login
def login(username, password):
    c.execute("SELECT password, role FROM users WHERE username=?", (username,))
    user = c.fetchone()
    if user and check_password(user[0], password):
        return user[1]  # Returns the role
    return False

def on_enter(e, btn):
    btn['background'] = '#003366'  # Lighter shade when hovering

def on_leave(e, btn):
    btn['background'] = 'grey'  # Original shade when not hovering

class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Login System")
        self.root.geometry("600x400")  # Set the window size

        # Set theme colors
        self.bg_color = "#003366"
        self.fg_color = "white"

        # Configure root window background color
        self.root.configure(bg=self.bg_color)

        # Frames
        self.login_frame = tk.Frame(self.root, bg=self.bg_color)
        self.register_frame = tk.Frame(self.root, bg=self.bg_color)
        self.show_frame(self.login_frame)

        # Login Widgets with updated colors
        tk.Label(self.login_frame, text="Username:", bg=self.bg_color, fg=self.fg_color).pack()
        self.login_username = tk.Entry(self.login_frame)
        self.login_username.pack()

        tk.Label(self.login_frame, text="Password:", bg=self.bg_color, fg=self.fg_color).pack()
        self.login_password = tk.Entry(self.login_frame, show="*")
        self.login_password.pack()

        # Buttons with uniform size and hover effect
        # Assuming these are your button definitions in the login frame
        login_btn = tk.Button(self.login_frame, text="Login", command=self.handle_login, bg="grey", fg=self.fg_color, width=20)
        login_btn.pack(pady=(10, 5))  # Increase the padding below the login button

        register_btn = tk.Button(self.login_frame, text="Register", command=lambda: self.show_frame(self.register_frame), bg="grey", fg=self.fg_color, width=20)
        register_btn.pack(pady=(5, 10))  # Increase the padding above the register button

        login_btn.bind("<Enter>", lambda e, btn=login_btn: on_enter(e, btn))
        login_btn.bind("<Leave>", lambda e, btn=login_btn: on_leave(e, btn))
        register_btn.bind("<Enter>", lambda e, btn=register_btn: on_enter(e, btn))
        register_btn.bind("<Leave>", lambda e, btn=register_btn: on_leave(e, btn))

        # Register Widgets with updated colors
        tk.Label(self.register_frame, text="Username:", bg=self.bg_color, fg=self.fg_color).pack()
        self.register_username = tk.Entry(self.register_frame)
        self.register_username.pack()

        tk.Label(self.register_frame, text="Password:", bg=self.bg_color, fg=self.fg_color).pack()
        self.register_password = tk.Entry(self.register_frame, show="*")
        self.register_password.pack()

        register_btn_frame = tk.Button(self.register_frame, text="Register", command=self.handle_register, bg="grey", fg=self.fg_color, width=20)
        register_btn_frame.pack(pady=(10, 0))  # Add some vertical padding for spacing from the above widget
        back_btn = tk.Button(self.register_frame, text="Back to Login", command=lambda: self.show_frame(self.login_frame), bg="grey", fg=self.fg_color, width=20)
        back_btn.pack(pady=(5, 10))  # Add some vertical padding for spacing from the register button and bottom margin

        # Applying hover effects
        register_btn_frame.bind("<Enter>", lambda e, btn=register_btn_frame: on_enter(e, btn))
        register_btn_frame.bind("<Leave>", lambda e, btn=register_btn_frame: on_leave(e, btn))
        back_btn.bind("<Enter>", lambda e, btn=back_btn: on_enter(e, btn))
        back_btn.bind("<Leave>", lambda e, btn=back_btn: on_leave(e, btn))
        

    def show_frame(self, frame):
        self.login_frame.pack_forget()
        self.register_frame.pack_forget()
        frame.pack()

    def handle_register(self):
        username = self.register_username.get()
        password = self.register_password.get()
        
    # Check for empty fields
        if not username or not password:
            messagebox.showerror("Error", "Fill in the username and password.", parent=self.root)
            return
        
        # Check for password length
        if len(password) < 5:
            messagebox.showerror("Error", "Password must be at least 5 characters long.", parent=self.root)
            return
        
        if register(username, password):  # Assuming the register function handles unique username validation
            messagebox.showinfo("Success", "Registration successful!", parent=self.root)
            self.show_frame(self.login_frame)
        else:
            messagebox.showerror("Error", "Registration failed. User might already exist.", parent=self.root)

    
    def handle_login(self):
        username = self.login_username.get()
        password = self.login_password.get()
        role = login(username, password)
        if role:
            messagebox.showinfo("Success", f"Login successful! Role: {role}", parent=self.root)
            self.root.destroy()  # Close the login window
            app = VulnerabilityScannerApp()  # Initialize the main application
            app.mainloop()  # Start the main application loop
        else:
            messagebox.showerror("Error", "Login failed. Check your username and password.", parent=self.root)

if __name__ == "__main__":
    root = tk.Tk()
    app = LoginApp(root)
    root.mainloop()
