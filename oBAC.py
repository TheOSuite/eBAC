import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import asyncio
import imaplib
import email
from email.header import decode_header
import requests
from twilio.rest import Client
import pyotp
import logging
import re
import os
import json
import time
from aiohttp import ClientSession, ClientTimeout, BasicAuth
import jsonpath_ng

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TextHandler(logging.Handler):
    """Custom logging handler to write to a Tkinter Text widget."""
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record)
        try:
            self.text_widget.configure(state='normal')
            self.text_widget.insert('end', msg + '\n')
            self.text_widget.see('end')
            self.text_widget.configure(state='disabled')
        except Exception:
            pass

class MFAHandler:
    # ... (MFAHandler class remains the same) ...
    def __init__(self, mfa_type, email_config=None, sms_config=None, totp_secret=None):
        self.mfa_type = mfa_type
        self.email_config = email_config
        self.sms_config = sms_config
        self.totp_secret = totp_secret

    async def get_otp(self):
        """Asynchronously retrieve OTP based on type."""
        if self.mfa_type == "Email":
            return await self.get_otp_from_email()
        elif self.mfa_type == "SMS":
            return await self.get_otp_from_sms()
        elif self.mfa_type == "TOTP":
            return self.get_otp_from_totp()
        else:
            logger.error(f"Unsupported MFA type: {self.mfa_type}")
            return None

    async def get_otp_from_email(self, wait_time=10, interval=1):
        """Retrieve OTP from the latest email, waiting for new messages."""
        logger.info(f"Attempting to retrieve OTP from email for up to {wait_time} seconds...")
        if not self.email_config or not all(self.email_config.values()):
            logger.error("Email configuration is incomplete.")
            return None

        loop = asyncio.get_event_loop()
        start_time = time.time()

        while time.time() - start_time < wait_time:
            try:
                otp = await loop.run_in_executor(None, self._get_latest_otp_from_email_sync)
                if otp:
                    logger.info(f"OTP retrieved from email: {otp}")
                    return otp
            except Exception as e:
                logger.error(f"Error during email OTP retrieval: {e}")

            await asyncio.sleep(interval)

        logger.warning(f"Timed out after {wait_time} seconds waiting for email OTP.")
        return None

    def _get_latest_otp_from_email_sync(self):
        """Synchronous function to connect to IMAP and get the latest OTP."""
        try:
            mail = imaplib.IMAP4_SSL(self.email_config['imap_server'])
            mail.login(self.email_config['email'], self.email_config['password'])
            mail.select('inbox')

            status, messages = mail.search(None, '(SINCE "{}")'.format(time.strftime("%d-%b-%Y")))
            messages = messages[0].split()

            if not messages:
                logger.debug("No new emails found since yesterday.")
                return None

            latest_email_id = messages[-1]
            status, msg_data = mail.fetch(latest_email_id, '(RFC822)')

            if status != 'OK':
                logger.error(f"Failed to fetch latest email: {status}")
                return None

            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    subject, encoding = decode_header(msg["Subject"])[0]
                    if isinstance(subject, bytes):
                        subject = subject.decode(encoding if encoding else 'utf-8', errors='ignore')

                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            ctype = part.get_content_type()
                            cdisp = part.get('Content-Disposition')
                            if ctype == 'text/plain' and cdisp is None:
                                try:
                                    body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore')
                                    break
                                except:
                                    pass
                    else:
                        try:
                             body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='ignore')
                        except:
                             pass

                    otp = self.extract_otp_from_text(subject + " " + body)
                    if otp:
                        return otp

        except Exception as e:
            logger.error(f"Error connecting to IMAP or processing email: {e}")
            return None
        finally:
             try:
                 mail.logout()
             except:
                 pass

        return None

    async def get_otp_from_sms(self, wait_time=10, interval=1):
        """Retrieve OTP from an SMS message using Twilio, waiting for new messages."""
        logger.info(f"Attempting to retrieve OTP from SMS for up to {wait_time} seconds...")
        if not self.sms_config or not all(self.sms_config.values()):
            logger.error("SMS configuration is incomplete.")
            return None

        loop = asyncio.get_event_loop()
        start_time = time.time()

        while time.time() - start_time < wait_time:
            try:
                otp = await loop.run_in_executor(None, self._get_latest_otp_from_sms_sync)
                if otp:
                    logger.info(f"OTP retrieved from SMS: {otp}")
                    return otp
            except Exception as e:
                logger.error(f"Error during SMS OTP retrieval: {e}")

            await asyncio.sleep(interval)

        logger.warning(f"Timed out after {wait_time} seconds waiting for SMS OTP.")
        return None

    def _get_latest_otp_from_sms_sync(self):
        """Synchronous function to get the latest OTP from Twilio messages."""
        try:
            client = Client(self.sms_config['account_sid'], self.sms_config['auth_token'])
            messages = client.messages.list(to=self.sms_config['to_phone_number'], limit=5)

            for message in messages:
                message_time = message.date_sent.timestamp()
                if time.time() - message_time < 300:
                     otp = self.extract_otp_from_text(message.body)
                     if otp:
                         return otp
                else:
                    break

        except Exception as e:
            logger.error(f"Error connecting to Twilio or processing SMS: {e}")
            return None

        return None

    def get_otp_from_totp(self):
        """Generate OTP using TOTP (synchronous)."""
        logger.info("Generating OTP from TOTP secret...")
        if not self.totp_secret:
            logger.error("TOTP secret is required for TOTP MFA.")
            return None
        try:
            totp = pyotp.TOTP(self.totp_secret)
            otp = totp.now()
            logger.info(f"Generated TOTP: {otp}")
            return otp
        except Exception as e:
            logger.error(f"Failed to generate TOTP: {e}")
            return None

    def extract_otp_from_text(self, text):
        """Extract the OTP from the text (using regex)."""
        match = re.search(r'\b(\d{4}|\d{6}|\d{8})\b', text)
        if match:
            return match.group(1)
        return None

class TestCase:
    def __init__(self, name, url, method, headers, params, body, role, expected_status, expected_content=None):
        self.name = name
        self.url = url
        self.method = method.upper()
        self.headers = headers or {}
        self.params = params or {}
        self.body = body
        self.role = role
        self.expected_status = expected_status
        self.expected_content = expected_content

    def __str__(self):
        return f"[{self.name}] {self.method} {self.url} (Role: {self.role})"

class APITestRunner:
    def __init__(self, session, mfa_handler=None, auth_method=None, auth_credentials=None):
        self.session = session
        self.mfa_handler = mfa_handler
        self.auth_method = auth_method
        self.auth_credentials = auth_credentials
        self.results = [] # Store results of each test case

    async def run_test_case(self, test_case):
        logger.info(f"Running test case: {test_case}")
        result = {
            "name": test_case.name,
            "url": test_case.url,
            "method": test_case.method,
            "role": test_case.role,
            "expected_status": test_case.expected_status,
            "actual_status": None,
            "passed": False,
            "validation_message": "",
            "error": None,
            "potential_vulnerability": False # Flag for potential issues
        }

        try:
            current_headers = test_case.headers.copy()
            auth = None

            if self.auth_method == "Bearer Token" and self.auth_credentials.get("token"):
                current_headers['Authorization'] = f'Bearer {self.auth_credentials["token"]}'
            elif self.auth_method == "Basic Auth" and self.auth_credentials.get("username") and self.auth_credentials.get("password"):
                auth = BasicAuth(self.auth_credentials["username"], self.auth_credentials["password"])
            elif self.auth_method == "Session Cookies" and self.auth_credentials.get("cookie"):
                 current_headers['Cookie'] = self.auth_credentials["cookie"]

            if self.mfa_handler:
                 logger.info(f"Attempting to get OTP for MFA for test case: {test_case.name}")
                 otp = await self.mfa_handler.get_otp()
                 if otp is None:
                     logger.warning(f"OTP retrieval failed for test case {test_case.name}. Skipping MFA step.")
                 else:
                     current_headers['X-OTP'] = otp # Example header, adjust as needed
                     logger.info(f"Using OTP: {otp} for test case: {test_case.name}")


            async with self.session.request(
                test_case.method,
                test_case.url,
                headers=current_headers,
                params=test_case.params,
                json=test_case.body if test_case.method in ["POST", "PUT"] else None,
                auth=auth,
                timeout=ClientTimeout(total=15),
                ssl=False
            ) as response:
                actual_status = response.status
                result["actual_status"] = actual_status
                response_text = await response.text()
                content_type = response.headers.get('Content-Type', '').lower()

                passed = True
                validation_message = ""

                if actual_status != test_case.expected_status:
                    passed = False
                    validation_message += f"Expected status {test_case.expected_status}, Got {actual_status}. "

                if test_case.expected_content is not None:
                    if isinstance(test_case.expected_content, (dict, list)):
                        if 'application/json' in content_type:
                            try:
                                actual_json = await response.json()
                                if not self._validate_json_content(actual_json, test_case.expected_content):
                                    passed = False
                                    validation_message += "JSON content validation failed. "
                            except json.JSONDecodeError:
                                passed = False
                                validation_message += "Response is not valid JSON. "
                            except Exception as e:
                                passed = False
                                validation_message += f"Error during JSON validation: {e}. "
                        else:
                            passed = False
                            validation_message += f"Expected JSON content, but response Content-Type was '{content_type}'. "
                    elif isinstance(test_case.expected_content, str):
                         if test_case.expected_content.startswith("regex:"):
                              pattern_str = test_case.expected_content[len("regex:"):].strip()
                              try:
                                   pattern = re.compile(pattern_str)
                                   if not pattern.search(response_text):
                                        passed = False
                                        validation_message += f"Expected content pattern '{pattern_str}' not found in response. "
                              except re.error as e:
                                   passed = False
                                   validation_message += f"Invalid regex pattern '{pattern_str}': {e}. "
                         else:
                             if test_case.expected_content not in response_text:
                                passed = False
                                validation_message += f"Expected content '{test_case.expected_content}' not found in response. "

                result["passed"] = passed
                result["validation_message"] = validation_message

                # Basic Potential Vulnerability Detection
                # If expected a denial (401/403) but got success (200-level)
                if test_case.expected_status in [401, 403] and 200 <= actual_status < 300:
                    result["potential_vulnerability"] = True
                    logger.warning(f"POTENTIAL VULNERABILITY: Test case failed {test_case.name} - Expected denial ({test_case.expected_status}), but got success ({actual_status}).")
                # You can add other vulnerability checks here (e.g., unexpected sensitive data in response)

                # Report Result
                if passed:
                    logger.info(f"Test case passed: {test_case.name} (Status: {actual_status})")
                else:
                    logger.warning(f"Test case failed: {test_case.name} (Status: {actual_status}) - {validation_message}")
                    logger.debug(f"Response content for failed test:\n{response_text[:500]}...")

        except asyncio.TimeoutError:
             result["error"] = "Timeout"
             logger.error(f"Test case failed (Timeout): {test_case.name} timed out.")
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"Error running test case {test_case.name}: {e}")

        self.results.append(result) # Add result to the list

    def _validate_json_content(self, actual_json, expected_json):
        """Recursively validates if expected_json is a subset of actual_json."""
        if isinstance(expected_json, dict):
            if not isinstance(actual_json, dict):
                return False
            for key, expected_value in expected_json.items():
                if key not in actual_json:
                    return False
                actual_value = actual_json[key]
                if not self._validate_json_content(actual_value, expected_value):
                    return False
            return True
        elif isinstance(expected_json, list):
            if not isinstance(actual_json, list):
                return False
            for expected_item in expected_json:
                found = False
                for actual_item in actual_json:
                    if self._validate_json_content(actual_item, expected_item):
                         found = True
                         break
                if not found:
                    return False
            return True
        else:
            return actual_json == expected_json

    # Optional: _validate_json_with_jsonpath method would go here if used

class APITesterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Access Control Scanner with MFA Support")
        self.root.geometry("900x750") # Increased height for summary

        self.base_url = tk.StringVar()
        self.auth_method = tk.StringVar(value="No Auth")
        self.bearer_token = tk.StringVar()
        self.basic_auth_username = tk.StringVar()
        self.basic_auth_password = tk.StringVar()
        self.cookie_value = tk.StringVar()
        self.mfa_type = tk.StringVar(value="None")
        self.email_imap_server = tk.StringVar()
        self.email_address = tk.StringVar()
        self.email_password = tk.StringVar()
        self.sms_account_sid = tk.StringVar()
        self.sms_auth_token = tk.StringVar()
        self.sms_to_phone = tk.StringVar()
        self.totp_secret = tk.StringVar()
        self.response_log_file = tk.StringVar(value="response_log.txt")
        self.error_log_file = tk.StringVar(value="error_log.txt")

        self.create_widgets()
        self.configure_logging()

    def create_widgets(self):
        main_pane = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        input_frame = ttk.LabelFrame(main_pane, text="Configuration")
        main_pane.add(input_frame)

        auth_frame = ttk.LabelFrame(input_frame, text="Authentication")
        auth_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

        ttk.Label(auth_frame, text="Method:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        auth_methods = ["No Auth", "Bearer Token", "Basic Auth", "Session Cookies"]
        ttk.OptionMenu(auth_frame, self.auth_method, self.auth_method.get(), *auth_methods, command=self.toggle_auth_fields).grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.bearer_token_label = ttk.Label(auth_frame, text="Bearer Token:")
        self.bearer_token_entry = ttk.Entry(auth_frame, textvariable=self.bearer_token, width=40)
        self.basic_auth_username_label = ttk.Label(auth_frame, text="Username:")
        self.basic_auth_username_entry = ttk.Entry(auth_frame, textvariable=self.basic_auth_username, width=40)
        self.basic_auth_password_label = ttk.Label(auth_frame, text="Password:")
        self.basic_auth_password_entry = ttk.Entry(auth_frame, textvariable=self.basic_auth_password, show="*", width=40)
        self.cookie_value_label = ttk.Label(auth_frame, text="Cookie Value:")
        self.cookie_value_entry = ttk.Entry(auth_frame, textvariable=self.cookie_value, width=40)

        self.toggle_auth_fields()


        mfa_frame = ttk.LabelFrame(input_frame, text="MFA Configuration")
        mfa_frame.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")

        ttk.Label(mfa_frame, text="MFA Type:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        mfa_types = ["None", "Email", "SMS", "TOTP"]
        ttk.OptionMenu(mfa_frame, self.mfa_type, self.mfa_type.get(), *mfa_types, command=self.toggle_mfa_fields).grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.email_imap_server_label = ttk.Label(mfa_frame, text="IMAP Server:")
        self.email_imap_server_entry = ttk.Entry(mfa_frame, textvariable=self.email_imap_server, width=30)
        self.email_address_label = ttk.Label(mfa_frame, text="Email Address:")
        self.email_address_entry = ttk.Entry(mfa_frame, textvariable=self.email_address, width=30)
        self.email_password_label = ttk.Label(mfa_frame, text="Email Password/App Password:")
        self.email_password_entry = ttk.Entry(mfa_frame, textvariable=self.email_password, show="*", width=30)

        self.sms_account_sid_label = ttk.Label(mfa_frame, text="Twilio Account SID:")
        self.sms_account_sid_entry = ttk.Entry(mfa_frame, textvariable=self.sms_account_sid, width=30)
        self.sms_auth_token_label = ttk.Label(mfa_frame, text="Twilio Auth Token:")
        self.sms_auth_token_entry = ttk.Entry(mfa_frame, textvariable=self.sms_auth_token, show="*", width=30)
        self.sms_to_phone_label = ttk.Label(mfa_frame, text="Twilio To Phone:")
        self.sms_to_phone_entry = ttk.Entry(mfa_frame, textvariable=self.sms_to_phone, width=30)

        self.totp_secret_label = ttk.Label(mfa_frame, text="TOTP Secret:")
        self.totp_secret_entry = ttk.Entry(mfa_frame, textvariable=self.totp_secret, width=30)

        self.toggle_mfa_fields()


        test_cases_frame = ttk.LabelFrame(input_frame, text="Test Cases (JSON format)")
        test_cases_frame.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")

        self.test_cases_text = scrolledtext.ScrolledText(test_cases_frame, height=10, wrap='word')
        self.test_cases_text.pack(fill=tk.BOTH, expand=True)

        test_case_buttons_frame = ttk.Frame(test_cases_frame)
        test_case_buttons_frame.pack(fill=tk.X, pady=5)
        ttk.Button(test_case_buttons_frame, text="Load Test Cases", command=self.load_test_cases).pack(side=tk.LEFT, padx=5)
        ttk.Button(test_case_buttons_frame, text="Save Test Cases", command=self.save_test_cases).pack(side=tk.LEFT, padx=5)
        ttk.Button(test_case_buttons_frame, text="Example Test Cases", command=self.load_example_test_cases).pack(side=tk.LEFT, padx=5)


        self.run_button = ttk.Button(input_frame, text="Run Tests", command=self.run_tests)
        self.run_button.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

        # Summary Frame
        summary_frame = ttk.LabelFrame(main_pane, text="Summary")
        main_pane.add(summary_frame)
        self.summary_text = scrolledtext.ScrolledText(summary_frame, height=4, wrap='word', state='disabled')
        self.summary_text.pack(fill=tk.BOTH, expand=True)


        # Log Output Frame
        log_frame = ttk.LabelFrame(main_pane, text="Log Output")
        main_pane.add(log_frame)

        self.log_output = scrolledtext.ScrolledText(log_frame, wrap='word', state='disabled')
        self.log_output.pack(fill=tk.BOTH, expand=True)


        input_frame.columnconfigure(0, weight=1)
        input_frame.columnconfigure(1, weight=1)
        input_frame.rowconfigure(1, weight=1)

        auth_frame.columnconfigure(1, weight=1)
        mfa_frame.columnconfigure(1, weight=1)
        test_cases_frame.columnconfigure(0, weight=1)
        test_cases_frame.rowconfigure(0, weight=1)

        summary_frame.columnconfigure(0, weight=1)
        summary_frame.rowconfigure(0, weight=1)

        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)


    def configure_logging(self):
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)

        gui_handler = TextHandler(self.log_output)
        gui_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        gui_handler.setFormatter(formatter)
        logger.addHandler(gui_handler)

        file_handler = logging.FileHandler("access_control_scan.log")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)


    def toggle_auth_fields(self, *args):
        self.bearer_token_label.grid_forget()
        self.bearer_token_entry.grid_forget()
        self.basic_auth_username_label.grid_forget()
        self.basic_auth_username_entry.grid_forget()
        self.basic_auth_password_label.grid_forget()
        self.basic_auth_password_entry.grid_forget()
        self.cookie_value_label.grid_forget()
        self.cookie_value_entry.grid_forget()

        selected_method = self.auth_method.get()
        if selected_method == "Bearer Token":
            self.bearer_token_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
            self.bearer_token_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        elif selected_method == "Basic Auth":
            self.basic_auth_username_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
            self.basic_auth_username_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
            self.basic_auth_password_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")
            self.basic_auth_password_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        elif selected_method == "Session Cookies":
            self.cookie_value_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
            self.cookie_value_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")


    def toggle_mfa_fields(self, *args):
        self.email_imap_server_label.grid_forget()
        self.email_imap_server_entry.grid_forget()
        self.email_address_label.grid_forget()
        self.email_address_entry.grid_forget()
        self.email_password_label.grid_forget()
        self.email_password_entry.grid_forget()

        self.sms_account_sid_label.grid_forget()
        self.sms_account_sid_entry.grid_forget()
        self.sms_auth_token_label.grid_forget()
        self.sms_auth_token_entry.grid_forget()
        self.sms_to_phone_label.grid_forget()
        self.sms_to_phone_entry.grid_forget()

        self.totp_secret_label.grid_forget()
        self.totp_secret_entry.grid_forget()

        selected_type = self.mfa_type.get()
        if selected_type == "Email":
            self.email_imap_server_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
            self.email_imap_server_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
            self.email_address_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")
            self.email_address_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
            self.email_password_label.grid(row=3, column=0, padx=5, pady=5, sticky="w")
            self.email_password_entry.grid(row=3, column=1, padx=5, pady=5, sticky="ew")
        elif selected_type == "SMS":
            self.sms_account_sid_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
            self.sms_account_sid_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
            self.sms_auth_token_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")
            self.sms_auth_token_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
            self.sms_to_phone_label.grid(row=3, column=0, padx=5, pady=5, sticky="w")
            self.sms_to_phone_entry.grid(row=3, column=1, padx=5, pady=5, sticky="ew")
        elif selected_type == "TOTP":
            self.totp_secret_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
            self.totp_secret_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")


    def load_test_cases(self):
        filepath = filedialog.askopenfilename(
            initialdir="./",
            title="Select Test Cases File",
            filetypes=(("JSON Files", "*.json"), ("All Files", "*.*"))
        )
        if filepath:
            try:
                with open(filepath, 'r') as f:
                    test_cases_data = json.load(f)
                    if isinstance(test_cases_data, list) and all(isinstance(tc, dict) for tc in test_cases_data):
                        self.test_cases_text.delete(1.0, tk.END)
                        self.test_cases_text.insert(tk.END, json.dumps(test_cases_data, indent=4))
                        logger.info(f"Successfully loaded test cases from {filepath}")
                    else:
                        messagebox.showerror("Load Error", "Invalid JSON format. Expected a list of objects.")
                        logger.error(f"Invalid JSON format in {filepath}")
            except FileNotFoundError:
                messagebox.showerror("Load Error", "File not found.")
                logger.error(f"Test cases file not found: {filepath}")
            except json.JSONDecodeError:
                messagebox.showerror("Load Error", "Invalid JSON format.")
                logger.error(f"JSON decoding error in {filepath}")
            except Exception as e:
                messagebox.showerror("Load Error", f"An error occurred: {e}")
                logger.error(f"Error loading test cases: {e}")

    def save_test_cases(self):
        filepath = filedialog.asksaveasfilename(
            initialdir="./",
            title="Save Test Cases File",
            filetypes=(("JSON Files", "*.json"), ("All Files", "*.*")),
            defaultextension=".json"
        )
        if filepath:
            try:
                test_cases_json = self.test_cases_text.get(1.0, tk.END).strip()
                test_cases_data = json.loads(test_cases_json)
                with open(filepath, 'w') as f:
                    json.dump(test_cases_data, f, indent=4)
                logger.info(f"Successfully saved test cases to {filepath}")
            except json.JSONDecodeError:
                messagebox.showerror("Save Error", "Invalid JSON format in the text area.")
                logger.error("Invalid JSON format in test cases text area.")
            except Exception as e:
                messagebox.showerror("Save Error", f"An error occurred: {e}")
                logger.error(f"Error saving test cases: {e}")

    def load_example_test_cases(self):
        example_cases = [
            {
                "name": "User access own profile",
                "url": "http://example.com/api/v1/users/1",
                "method": "GET",
                "headers": {},
                "params": {},
                "body": None,
                "role": "user",
                "expected_status": 200,
                "expected_content": {
                    "id": 1,
                    "username": "user1"
                }
            },
            {
                "name": "User access other user profile (IDOR)",
                "url": "http://example.com/api/v1/users/2",
                "method": "GET",
                "headers": {},
                "params": {},
                "body": None,
                "role": "user",
                "expected_status": 403,
                "expected_content": {"error": "Access Denied"}
            },
             {
                "name": "Admin access user list",
                "url": "http://example.com/api/v1/users",
                "method": "GET",
                "headers": {},
                "params": {},
                "body": None,
                "role": "admin",
                "expected_status": 200,
                "expected_content": [
                    {"id": 1},
                    {"id": 2}
                ]
            },
            {
                "name": "Unauthenticated access admin dashboard",
                "url": "http://example.com/api/v1/admin/dashboard",
                "method": "GET",
                "headers": {},
                "params": {},
                "body": None,
                "role": "unauthenticated",
                "expected_status": 401,
                "expected_content": "regex:Unauthorized|Authentication Required"
            },
             {
                "name": "User attempt admin endpoint (Vertical AC)",
                "url": "http://example.com/api/v1/admin/settings",
                "method": "GET",
                "headers": {},
                "params": {},
                "body": None,
                "role": "user",
                "expected_status": 403 # Expect Forbidden
            }
        ]
        self.test_cases_text.delete(1.0, tk.END)
        self.test_cases_text.insert(tk.END, json.dumps(example_cases, indent=4))
        logger.info("Loaded example test cases.")


    async def run_tests_async(self):
        logger.info("Starting access control tests...")
        self.run_button.config(state="disabled", text="Running...")
        self.summary_text.configure(state='normal')
        self.summary_text.delete(1.0, tk.END)
        self.summary_text.configure(state='disabled')


        auth_method = self.auth_method.get()
        auth_credentials = {}
        if auth_method == "Bearer Token":
            auth_credentials["token"] = self.bearer_token.get().strip()
        elif auth_method == "Basic Auth":
            auth_credentials["username"] = self.basic_auth_username.get().strip()
            auth_credentials["password"] = self.basic_auth_password.get().strip()
        elif auth_method == "Session Cookies":
            auth_credentials["cookie"] = self.cookie_value.get().strip()

        mfa_type = self.mfa_type.get()
        mfa_handler = None
        if mfa_type != "None":
            email_config = None
            sms_config = None
            totp_secret = None
            if mfa_type == "Email":
                 email_config = {
                     'imap_server': self.email_imap_server.get().strip(),
                     'email': self.email_address.get().strip(),
                     'password': self.email_password.get().strip()
                 }
                 if not all(email_config.values()):
                     messagebox.showwarning("MFA Warning", "Email configuration is incomplete. Skipping Email MFA.")
                 else:
                    mfa_handler = MFAHandler(mfa_type=mfa_type, email_config=email_config)

            elif mfa_type == "SMS":
                 sms_config = {
                     'account_sid': self.sms_account_sid.get().strip(),
                     'auth_token': self.sms_auth_token.get().strip(),
                     'to_phone_number': self.sms_to_phone.get().strip()
                 }
                 if not all(sms_config.values()):
                      messagebox.showwarning("MFA Warning", "SMS configuration is incomplete. Skipping SMS MFA.")
                 else:
                      mfa_handler = MFAHandler(mfa_type=mfa_type, sms_config=sms_config)

            elif mfa_type == "TOTP":
                 totp_secret = self.totp_secret.get().strip()
                 if not totp_secret:
                      messagebox.showwarning("MFA Warning", "TOTP secret is required. Skipping TOTP MFA.")
                 else:
                     mfa_handler = MFAHandler(mfa_type=mfa_type, totp_secret=totp_secret)


        test_cases_json = self.test_cases_text.get(1.0, tk.END).strip()
        try:
            test_cases_data = json.loads(test_cases_json)
            test_cases = []
            for tc_data in test_cases_data:
                 required_fields = ["name", "url", "method", "role", "expected_status"]
                 if not all(field in tc_data for field in required_fields):
                      logger.error(f"Skipping invalid test case (missing required fields): {tc_data}")
                      messagebox.showwarning("Test Case Warning", f"Skipping invalid test case (missing required fields): {tc_data.get('name', 'Unnamed')}")
                      continue

                 test_cases.append(TestCase(**tc_data))

            logger.info(f"Loaded {len(test_cases)} valid test cases.")
        except json.JSONDecodeError:
            messagebox.showerror("Test Case Error", "Invalid JSON format in test cases.")
            logger.error("Invalid JSON format in test cases text area.")
            self.run_button.config(state="normal", text="Run Tests")
            return
        except Exception as e:
             messagebox.showerror("Test Case Error", f"An unexpected error occurred parsing test cases: {e}")
             logger.error(f"Unexpected error parsing test cases: {e}")
             self.run_button.config(state="normal", text="Run Tests")
             return

        if not test_cases:
             messagebox.showwarning("No Test Cases", "No valid test cases were loaded. Please define test cases in the JSON area.")
             self.run_button.config(state="normal", text="Run Tests")
             return


        async with ClientSession() as session:
            test_runner = APITestRunner(session, mfa_handler, auth_method, auth_credentials)
            tasks = [test_runner.run_test_case(tc) for tc in test_cases]
            await asyncio.gather(*tasks)

            # Generate and display summary
            self.display_summary(test_runner.results)

        logger.info("Access control tests finished.")
        self.run_button.config(state="normal", text="Run Tests")

    def display_summary(self, results):
        """Generates and displays the test summary."""
        total_tests = len(results)
        passed_tests = sum(1 for r in results if r["passed"] and r["error"] is None)
        failed_tests = sum(1 for r in results if not r["passed"] and r["error"] is None)
        errored_tests = sum(1 for r in results if r["error"] is not None)
        potential_vulnerabilities = [r for r in results if r["potential_vulnerability"]]

        summary = f"--- Test Summary ---\n"
        summary += f"Total Test Cases: {total_tests}\n"
        summary += f"Passed: {passed_tests}\n"
        summary += f"Failed (Validation Mismatch): {failed_tests}\n"
        summary += f"Errored (Request Failed): {errored_tests}\n"
        summary += f"Potential Vulnerabilities Detected: {len(potential_vulnerabilities)}\n"

        if potential_vulnerabilities:
            summary += "\nPotential Vulnerabilities:\n"
            for vuln in potential_vulnerabilities:
                summary += f"  - [{vuln['name']}] {vuln['method']} {vuln['url']} (Role: {vuln['role']}) - Expected denial ({vuln['expected_status']}), got success ({vuln['actual_status']}).\n"
                if vuln["validation_message"]:
                     summary += f"    Validation Note: {vuln['validation_message']}\n"
                if vuln["error"]:
                     summary += f"    Error Note: {vuln['error']}\n"


        self.summary_text.configure(state='normal')
        self.summary_text.delete(1.0, tk.END)
        self.summary_text.insert(tk.END, summary)
        self.summary_text.configure(state='disabled')

        logger.info(summary) # Also log the summary to the file


    def run_tests(self):
        """Starts the asynchronous test execution in a separate thread."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        def start_async_loop():
            loop.run_until_complete(self.run_tests_async())

        import threading
        thread = threading.Thread(target=start_async_loop)
        thread.start()


if __name__ == "__main__":
    try:
        import aiohttp
        import pyotp
        import twilio
        import imaplib
        import jsonpath_ng
    except ImportError:
        print("Installing required libraries...")
        try:
            import subprocess
            subprocess.check_call([sys.executable, "-m", "pip", "install", "aiohttp pyotp requests twilio jsonpath-ng"])
            print("Successfully installed libraries. Please run the script again.")
            sys.exit(0)
        except subprocess.CalledProcessError as e:
            print(f"Failed to install libraries: {e}")
            print("Please install them manually using: pip install aiohttp pyotp requests twilio jsonpath-ng")
            sys.exit(1)

    root = tk.Tk()
    app = APITesterApp(root)
    root.mainloop()
