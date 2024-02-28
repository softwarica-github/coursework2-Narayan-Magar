import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
# Assuming your actual test functions and load_payloads are defined in these modules
# from vulnerability_tests import *
from payload_loader import load_payloads
from bs4 import BeautifulSoup
import socket
import sqlite3
from datetime import datetime
import requests

class VulnerabilityScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Vulnerability Scanner")
        self.geometry("800x600")
        self.configure(bg='#003366')  # Set the background of the root window

        # Apply dark theme to ttk styles
        self.style = ttk.Style()
        self.style.theme_use('default')

        # Configure the TFrame style
        self.style.configure('TFrame', background='#003366')

        # Configure the TLabel style
        self.style.configure('TLabel', background='#003366', foreground='white')

        # Configure the TButton style for start button to have a green background
        self.style.configure('Start.TButton', background='green', foreground='white')
        self.style.map('Start.TButton', background=[('active', 'dark green')])

        
        # Load payloads
        self.payloads = {
            "xss": load_payloads('D:\cw3rsem\Vulnerability_Scanner-main111\Vulnerability_Scanner-main\Payloads\PayloadXSS.txt'),
            "sql": load_payloads('D:\cw3rsem\Vulnerability_Scanner-main111\Vulnerability_Scanner-main\Payloads\PayloadSQL.txt'),
            "rce": load_payloads('D:\cw3rsem\Vulnerability_Scanner-main111\Vulnerability_Scanner-main\Payloads\PayloadRCE.txt'),
            "ssti": load_payloads('D:\cw3rsem\Vulnerability_Scanner-main111\Vulnerability_Scanner-main\Payloads\PayloadSSTI.txt'),
            "open_redirect": load_payloads('D:\cw3rsem\Vulnerability_Scanner-main111\Vulnerability_Scanner-main\Payloads\PayloadOpenRed.txt'),
        }
        self.create_navbar()
        self.database_setup()
        
    
    def database_setup(self):
        self.conn = sqlite3.connect('vulnerability_scanner.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
        # Create a specific table for subdomain scan results
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS subdomain_scan_results
                            (id INTEGER PRIMARY KEY, subdomain TEXT, main_domain TEXT, 
                            timestamp TEXT)''')
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS csrf_scan_results
                         (id INTEGER PRIMARY KEY, scanned_url TEXT, 
                         csrf_vulnerable TEXT, timestamp TEXT)''')
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS sql_injection_scan_results
                            (id INTEGER PRIMARY KEY, scanned_url TEXT, 
                            vulnerable TEXT, timestamp TEXT)''')
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS open_redirection_scan_results
                         (id INTEGER PRIMARY KEY, scanned_url TEXT, 
                         vulnerable TEXT, timestamp TEXT)''')
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS clickjacking_scan_results
                         (id INTEGER PRIMARY KEY, scanned_url TEXT, 
                         protected TEXT, timestamp TEXT)''')
        self.conn.commit()
        
    def insert_subdomain_scan_result(self, subdomain, main_domain):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            # Create a new connection for the thread
            conn = sqlite3.connect('vulnerability_scanner.db')
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO subdomain_scan_results (subdomain, main_domain, timestamp)
                            VALUES (?, ?, ?)''', (subdomain, main_domain, timestamp))
            conn.commit()
            conn.close()  # Close the connection created within the thread
        except sqlite3.Error as e:
            print(f"Database error: {e}")
        except Exception as e:
            print(f"Exception in insert_subdomain_scan_result: {e}")
            
    def insert_sql_injection_scan_result(self, scanned_url, vulnerable):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            self.cursor.execute('''INSERT INTO sql_injection_scan_results (scanned_url, vulnerable, timestamp)
                                VALUES (?, ?, ?)''', (scanned_url, vulnerable, timestamp))
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Database error: {e}")
        except Exception as e:
            print(f"Exception in insert_sql_injection_scan_result: {e}")


    def insert_csrf_scan_result(self, scanned_url, csrf_vulnerable):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            conn = sqlite3.connect('vulnerability_scanner.db')
            cursor = conn.cursor()
            self.cursor.execute('''INSERT INTO csrf_scan_results (scanned_url, csrf_vulnerable, timestamp)
                                VALUES (?, ?, ?)''', (scanned_url, csrf_vulnerable, timestamp))
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Database error: {e}")
        except Exception as e:
            print(f"Exception in insert_csrf_scan_result: {e}")
            
    def insert_clickjacking_scan_result(self, scanned_url, protected):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            self.cursor.execute('''INSERT INTO clickjacking_scan_results (scanned_url, protected, timestamp)
                                VALUES (?, ?, ?)''', (scanned_url, protected, timestamp))
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Database error: {e}")
        except Exception as e:
            print(f"Exception in insert_clickjacking_scan_result: {e}")


    def insert_open_redirection_scan_result(self, scanned_url, vulnerable):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            self.cursor.execute('''INSERT INTO open_redirection_scan_results (scanned_url, vulnerable, timestamp)
                                VALUES (?, ?, ?)''', (scanned_url, vulnerable, timestamp))
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Database error: {e}")
        except Exception as e:
            print(f"Exception in insert_open_redirection_scan_result: {e}")

    
    def insert_scan_result(self, scan_type, target_url, vulnerable):
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.cursor.execute('''INSERT INTO scan_results (scan_type, target_url, vulnerable, timestamp)
                                VALUES (?, ?, ?, ?)''', (scan_type, target_url, vulnerable, timestamp))
            self.conn.commit()
            print(f"Inserted result for {scan_type} scan of {target_url}: {vulnerable}")  # Debugging print
        except sqlite3.Error as e:
            print(f"Database error: {e}")  # Debugging print
        except Exception as e:
            print(f"Exception in insert_scan_result: {e}")  # Debugging print

        
    def on_closing(self):
        self.conn.close()
        self.destroy()
        
    def create_navbar(self):
        self.tab_control = ttk.Notebook(self)
        
        # Dashboard Tab
        self.dashboard_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.dashboard_tab, text='Dashboard')
        self.setup_dashboard_tab()
        
        # Scan-specific Tabs
        self.setup_subdomain_tab()
        self.setup_xss_tab()
        self.setup_sql_injection_tab() 
        self.setup_csrf_tab()
        self.setup_open_redirection_tab()
        self.setup_clickjacking_tab()

        self.tab_control.pack(expand=1, fill="both")

    def setup_dashboard_tab(self):
        ttk.Label(self.dashboard_tab, text="Welcome to Vulnerability Scanner Dashboard").pack(pady=20)

    def setup_subdomain_tab(self):
        tab = ttk.Frame(self.tab_control)
        self.tab_control.add(tab, text="Subdomain Scanner")

        ttk.Label(tab, text="Enter Domain:").pack(pady=5)
        domain_entry = ttk.Entry(tab, width=60)
        domain_entry.pack(pady=5)

        output = scrolledtext.ScrolledText(tab, height=15)
        output.pack(pady=10, fill=tk.BOTH, expand=True)

        start_button = ttk.Button(tab, text="Start Scan", command=lambda: self.start_subdomain_scan(domain_entry.get(), output))
        start_button.pack(pady=20)

    def start_subdomain_scan(self, domain, output):
        if not domain:
            messagebox.showerror("Error", "Domain is required")
            return

        output.delete('1.0', tk.END)  # Clear previous output
        wordlist_path = 'D:\cw3rsem\Vulnerability_Scanner-main111\Vulnerability_Scanner-main\Payloads\Subdomain.txt'  # Assuming you have a wordlist at this path
        threading.Thread(target=self.scan_subdomains, args=(domain, wordlist_path, output), daemon=True).start()

    def scan_subdomains(self, domain, wordlist_path, output):
        output.insert(tk.END, "Starting Subdomain Scan...\n")
        try:
            with open(wordlist_path, 'r') as file:
                for line in file:
                    subdomain = line.strip() + '.' + domain
                    try:
                        resolved = socket.gethostbyname(subdomain)
                        output.insert(tk.END, f"Found: {subdomain} - {resolved}\n")
                        # Insert each found subdomain into the database
                        self.insert_subdomain_scan_result(subdomain, domain)
                    except socket.gaierror:
                        pass
        except Exception as e:
            messagebox.showerror("Error", str(e))
        output.insert(tk.END, "Subdomain Scan Completed.\n")


            
    def setup_xss_tab(self):
        tab = ttk.Frame(self.tab_control)
        self.tab_control.add(tab, text="XSS Scanner")

        ttk.Label(tab, text="Enter URL:").pack(pady=5)
        url_entry = ttk.Entry(tab, width=60)
        url_entry.pack(pady=5)

        output = scrolledtext.ScrolledText(tab, height=15)
        output.pack(pady=10, fill=tk.BOTH, expand=True)

        start_button = ttk.Button(tab, text="Start XSS Scan", command=lambda: self.start_xss_scan(url_entry.get(), output))
        start_button.pack(pady=20)

    def start_xss_scan(self, url, output):
        if not url:
            messagebox.showerror("Error", "URL is required")
            return

        output.delete('1.0', tk.END)  # Clear previous output
        threading.Thread(target=self.scan_xss, args=(url, self.payloads["xss"], output), daemon=True).start()

    def scan_xss(self, url, payloads, output):
        output.insert(tk.END, "Starting XSS Scan...\n")
        vulnerable = "No"  # Assume not vulnerable by default
        for payload in payloads:
            full_url = f"{url}?param={payload}"
            try:
                response = requests.get(full_url)  # Sending the payload
                if payload in response.text:  # Naive check for payload reflection
                    output.insert(tk.END, f"Potential XSS found with payload: {payload}\n")
                    vulnerable = "Yes"  # Update vulnerable status
                    break  # Exit after finding the first vulnerability
            except Exception as e:
                output.insert(tk.END, f"Error sending payload {payload}: {str(e)}\n")
        
        output.insert(tk.END, "XSS Scan Completed.\n")
        self.insert_scan_result('XSS', url, vulnerable)  # Insert scan result into database


    
    def setup_sql_injection_tab(self):
        tab = ttk.Frame(self.tab_control)
        self.tab_control.add(tab, text="SQL Injection Scanner")

        ttk.Label(tab, text="Enter URL:").pack(pady=5)
        url_entry = ttk.Entry(tab, width=60)
        url_entry.pack(pady=5)

        output = scrolledtext.ScrolledText(tab, height=15)
        output.pack(pady=10, fill=tk.BOTH, expand=True)

        start_button = ttk.Button(tab, text="Start SQL Injection Scan", command=lambda: self.start_sql_injection_scan(url_entry.get(), output))
        start_button.pack(pady=20)

    def start_sql_injection_scan(self, url, output):
        if not url:
            messagebox.showerror("Error", "URL is required")
            return

        output.delete('1.0', tk.END)  # Clear previous output
        threading.Thread(target=self.scan_sql_injection, args=(url, self.payloads["sql"], output), daemon=True).start()

    def scan_sql_injection(self, url, payloads, output):
        output.insert(tk.END, "Starting SQL Injection Scan...\n")
        vulnerable = "No"  # Assume not vulnerable by default
        for payload in payloads:
            full_url = f"{url}?param={payload}"
            try:
                response = requests.get(full_url)  # Sending the payload
                if "error" in response.text or "SQL" in response.text:
                    output.insert(tk.END, f"Potential SQL Injection found with payload: {payload}\n")
                    vulnerable = "Yes"  # Update vulnerable status if any indication of SQL injection is found
                    break  # Stop scanning after finding the first indication of vulnerability
            except Exception as e:
                output.insert(tk.END, f"Error sending payload {payload}: {str(e)}\n")
        output.insert(tk.END, "SQL Injection Scan Completed.\n")
        self.insert_sql_injection_scan_result(url, vulnerable)

            
    
    def setup_csrf_tab(self):
        tab = ttk.Frame(self.tab_control)
        self.tab_control.add(tab, text="CSRF Scanner")

        ttk.Label(tab, text="Enter URL:").pack(pady=5)
        url_entry = ttk.Entry(tab, width=60)
        url_entry.pack(pady=5)

        output = scrolledtext.ScrolledText(tab, height=15)
        output.pack(pady=10, fill=tk.BOTH, expand=True)

        start_button = ttk.Button(tab, text="Start CSRF Scan", command=lambda: self.start_csrf_scan(url_entry.get(), output))
        start_button.pack(pady=20)

    def start_csrf_scan(self, url, output):
        if not url:
            messagebox.showerror("Error", "URL is required")
            return

        output.delete('1.0', tk.END)  # Clear previous output
        threading.Thread(target=self.scan_csrf, args=(url, output), daemon=True).start()

    def scan_csrf(self, url, output):
        output.insert(tk.END, "Starting CSRF Scan...\n")
        csrf_vulnerable = "No"  # Assume not vulnerable by default
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            if forms:
                for form in forms:
                    if not form.find('input', {'name': 'csrf_token'}):
                        output.insert(tk.END, "Potential CSRF vulnerability detected: Form without CSRF token found.\n")
                        csrf_vulnerable = "Yes"  # Update CSRF vulnerability status
                        break  # Consider vulnerable if at least one form without CSRF token is found
            else:
                output.insert(tk.END, "No forms found on the page.\n")
        except Exception as e:
            output.insert(tk.END, f"Error during scan: {str(e)}\n")
        output.insert(tk.END, "CSRF Scan Completed.\n")
        # Insert CSRF scan result into database
        self.insert_csrf_scan_result(url, csrf_vulnerable)

        
    def setup_open_redirection_tab(self):
        tab = ttk.Frame(self.tab_control)
        self.tab_control.add(tab, text="Open Redirection Scanner")

        ttk.Label(tab, text="Enter URL:").pack(pady=5)
        url_entry = ttk.Entry(tab, width=60)
        url_entry.pack(pady=5)

        output = scrolledtext.ScrolledText(tab, height=15)
        output.pack(pady=10, fill=tk.BOTH, expand=True)

        start_button = ttk.Button(tab, text="Start Open Redirection Scan", command=lambda: self.start_open_redirection_scan(url_entry.get(), output))
        start_button.pack(pady=20)

    def start_open_redirection_scan(self, url, output):
        if not url:
            messagebox.showerror("Error", "URL is required")
            return

        output.delete('1.0', tk.END)  # Clear previous output
        threading.Thread(target=self.scan_open_redirection, args=(url, self.payloads["open_redirect"], output), daemon=True).start()

    def scan_open_redirection(self, url, payloads, output):
        output.insert(tk.END, "Starting Open Redirection Scan...\n")
        vulnerable = "No"  # Assume not vulnerable by default
        for payload in payloads:
            test_url = url + payload  # Adjust based on how your target application handles redirects
            try:
                response = requests.get(test_url, allow_redirects=False)
                if response.status_code in [301, 302, 303, 307, 308]:  # Checking for redirection response codes
                    location_header = response.headers.get('Location', '')
                    if "example.com" in location_header:  # Assume vulnerability if redirected to example.com
                        output.insert(tk.END, f"Potential Open Redirection found with payload: {payload}\n")
                        vulnerable = "Yes"
                        break  # Stop checking after the first indication of vulnerability
            except Exception as e:
                output.insert(tk.END, f"Error sending payload {payload}: {str(e)}\n")
        output.insert(tk.END, "Open Redirection Scan Completed.\n")
        self.insert_open_redirection_scan_result(url, vulnerable)

    
    def setup_clickjacking_tab(self):
        tab = ttk.Frame(self.tab_control)
        self.tab_control.add(tab, text="Clickjacking Scanner")

        ttk.Label(tab, text="Enter URL:").pack(pady=5)
        url_entry = ttk.Entry(tab, width=60)
        url_entry.pack(pady=5)

        output = scrolledtext.ScrolledText(tab, height=15)
        output.pack(pady=10, fill=tk.BOTH, expand=True)

        start_button = ttk.Button(tab, text="Start Clickjacking Scan", command=lambda: self.start_clickjacking_scan(url_entry.get(), output))
        start_button.pack(pady=20)

    def start_clickjacking_scan(self, url, output):
        if not url:
            messagebox.showerror("Error", "URL is required")
            return

        output.delete('1.0', tk.END)  # Clear previous output
        threading.Thread(target=self.scan_clickjacking, args=(url, output), daemon=True).start()

    def scan_clickjacking(self, url, output):
        output.insert(tk.END, "Starting Clickjacking Scan...\n")
        protected = "Yes"  # Assume the page is protected by default
        try:
            response = requests.get(url)
            x_frame_options = response.headers.get('X-Frame-Options', '').lower()
            content_security_policy = response.headers.get('Content-Security-Policy', '').lower()

            if 'deny' in x_frame_options or 'sameorigin' in x_frame_options or 'frame-ancestors' in content_security_policy:
                output.insert(tk.END, "Page is potentially protected against Clickjacking.\n")
            else:
                output.insert(tk.END, "Page is potentially vulnerable to Clickjacking.\n")
                protected = "No"
        except Exception as e:
            output.insert(tk.END, f"Error during scan: {str(e)}\n")
        output.insert(tk.END, "Clickjacking Scan Completed.\n")
        self.insert_clickjacking_scan_result(url, protected)



if __name__ == "__main__":
    app = VulnerabilityScannerApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
