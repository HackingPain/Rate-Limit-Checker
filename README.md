# Website Rate Limit Checker & Exploit Tool

**Disclaimer:**  
This tool is provided for educational and authorized security testing purposes only. Unauthorized or malicious use of this tool is illegal and unethical. Always obtain explicit permission before testing any systems.

---

## Overview

This Python tool simulates an email spoofing attack by sending form submissions to a target website's endpoint. It uses the 2Captcha service to automatically solve reCAPTCHA challenges, encodes target email addresses in Base64, and sends spoofed email requests. A graphical user interface (GUI) built with tkinter allows you to input parameters, control the process, and view real-time logs.

---

## Features

- **Automated CAPTCHA Solving:**  
  Uses 2Captcha API to solve reCAPTCHA challenges automatically.

- **Email Spoofing Simulation:**  
  Encodes target emails and sends spoofed form submissions to check for vulnerabilities.

- **Customizable Parameters:**  
  Easily configure target URL, API keys, spoofed and target email addresses, and number of attempts.

- **Real-Time Logging:**  
  Displays detailed logs in the GUI for monitoring the attack simulation process.

- **Multithreaded Execution:**  
  Runs the exploit in a separate thread, keeping the GUI responsive.

---

## Requirements

- **Python 3.6+**  
- **Libraries:**  
  - `requests`  
  - `tkinter` (usually included with Python)  
  - `base64` (standard library)  
  - `time` (standard library)  
  - `threading` (standard library)  
  - `logging` (standard library)

- **2Captcha API Key:**  
  You must have a valid 2Captcha API key to use the automated CAPTCHA solving feature.

---

## Setup

1. **Clone or Download the Repository**

   Clone this repository or download the script file to your local machine.

2. **Install Dependencies**

   Use pip to install the necessary Python packages:
   ```
   pip install requests
   ```

3. **Configure 2Captcha API Key**

   Obtain your 2Captcha API key from [2Captcha](http://2captcha.com) and keep it ready for input in the GUI.

---

## Usage

1. **Run the Script**

   Execute the script in your terminal or command prompt:
   ```
   python websiteratelimit_checker_2captcha.py
   ```
   This will launch the GUI.

2. **Configure Parameters in the GUI**

   - **2Captcha API Key:** Enter your 2Captcha API key.
   - **Target Form URL:** Default is set to `https://des.ncsuvt.org/sndreq/send_message.php`. Modify if needed.
   - **Google reCAPTCHA Site Key:** Enter the site key used by the target page.
   - **Target Email:** The email address that will be encoded and used in the form’s hidden field.
   - **Spoofed Email:** The email address that will appear as the sender.
   - **Number of Spam Attempts:** Define how many times the spoofed email request should be sent.

3. **Start the Exploit Process**

   Click the **"Start Exploit"** button. The tool will:
   - Request a CAPTCHA solution via 2Captcha.
   - Encode the target email.
   - Send the spoofed form submissions based on the configured number of attempts.
   - Log detailed output in the text area for you to monitor progress and responses.

---

## Code Overview

- **solve_captcha:**  
  Sends a request to 2Captcha to solve the reCAPTCHA challenge. It polls for the solution and returns a valid CAPTCHA token if successful.

- **send_exploit_requests:**  
  After obtaining the CAPTCHA solution, this function encodes the target email, constructs the payload with spoofed data, and sends multiple POST requests to the target form URL. It logs each attempt and response.

- **ExploitGUI Class:**  
  Implements the tkinter-based GUI. It collects user inputs, validates them, and starts the exploit process in a separate thread to keep the interface responsive. It also integrates a custom logging handler to display log messages in the GUI.

---

## Troubleshooting

- **CAPTCHA Solving Failure:**  
  Ensure your 2Captcha API key is valid and that the Google reCAPTCHA site key matches the target page.

- **Network Issues:**  
  Check your internet connection if the tool cannot reach the target URL or 2Captcha service.

- **Input Errors:**  
  Verify that all fields in the GUI are correctly filled. The number of spam attempts must be an integer.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## References

2Captcha. (n.d.). *2Captcha API Documentation*. Retrieved from https://2captcha.com  
  
*Note: This tool is intended solely for authorized security testing and educational purposes.*