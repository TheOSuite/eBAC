# Advanced Access Control Scanner with MFA Support

This tool provides an automated framework for testing API access control vulnerabilities, including scenarios involving Multi-Factor Authentication (MFA). Leveraging asynchronous HTTP requests and customizable test cases, it enables security professionals and developers to efficiently identify authorization bypasses, Insecure Direct Object References (IDORs), and privilege escalation flaws.

## Features

*   **Asynchronous HTTP Client:** Built with `asyncio` and `aiohttp` for high-performance concurrent testing.
*   **Flexible Authentication:** Supports common API authentication schemes:
    *   Bearer Tokens
    *   Basic Authentication
    *   Session Cookies
*   **MFA Integration:** Automates retrieval of One-Time Passwords (OTPs) for APIs protected by:
    *   Email-based OTPs (via IMAP)
    *   SMS-based OTPs (via Twilio API)
    *   Time-based One-Time Passwords (TOTP)
*   **Structured Test Cases:** Define test scenarios using a JSON format, specifying:
    *   Target URLs and HTTP Methods (GET, POST, PUT, DELETE)
    *   Request Headers, Parameters, and Body
    *   User/Role context for the test
    *   Expected HTTP Status Code
    *   Advanced Expected Content Validation:
        *   Substring or Regular Expression matching in response body.
        *   Structured validation of JSON responses (checking for required keys/values, including nested structures).
*   **Automated Vulnerability Detection:** Flags potential broken access control issues where actual response status codes deviate from expected denial codes (e.g., expecting 401/403 but receiving 2xx).
*   **Detailed Logging:** Provides comprehensive logging of request/response details and test outcomes.
*   **Result Summary:** Generates a concise summary of test execution, including pass/fail counts and identified potential vulnerabilities.
*   **GUI Interface:** A Tkinter-based graphical interface for easy configuration, test case management, and results visualization.

## Use Cases

*   Automated testing of API endpoints for authorization bypasses.
*   Verifying correct access control for different user roles and permission levels.
*   Testing APIs that enforce MFA to ensure the OTP validation is correctly implemented per request.
*   Identifying IDOR vulnerabilities by testing access to resources with different identifiers using lower-privileged credentials.
*   Regression testing of access control mechanisms during development cycles.

## Requirements

*   Python 3.7+
*   The following Python libraries (automatically checked and installed on first run if missing):
    *   `aiohttp`
    *   `pyotp`
    *   `requests` (Used for dependency check, `aiohttp` is used for main requests)
    *   `twilio` (Required for SMS MFA testing)
    *   `jsonpath-ng` (Required for advanced JSON validation)
*   **For Email MFA:** IMAP access enabled for the target email account, and potentially an application-specific password if 2FA is enabled.
*   **For SMS MFA:** A configured Twilio account and a Twilio phone number capable of receiving SMS.
*   **For TOTP MFA:** The shared secret key associated with the target account's TOTP setup.

## Installation

1.  **Clone or Download:** Get the source code.
2.  **Run the Script:** Open your terminal or command prompt, navigate to the directory where you saved the script, and run:
    ```bash
    python your_script_name.py
    ```
3.  **Dependency Installation:** On the first run, the script will check for required libraries and attempt to install them using `pip`. If automatic installation fails, manually install them:
    ```bash
    pip install aiohttp pyotp requests twilio jsonpath-ng
    ```

## Usage

1.  **Launch the GUI:** Run `python your_script_name.py`.
2.  **Configure Authentication:** In the "Authentication" section, select the method used by the target API (Bearer Token, Basic Auth, or Session Cookies) and provide the necessary credentials.
3.  **Configure MFA (if applicable):** In the "MFA Configuration" section, select the MFA type (Email, SMS, or TOTP) and provide the required connection details or secret key.
4.  **Define Test Cases:** Use the "Test Cases (JSON format)" area to define your test scenarios.
    *   Click "Example Test Cases" to load a template demonstrating different validation types.
    *   Define an array of test case objects, each with the following keys:
        *   `name` (string): A descriptive name for the test.
        *   `url` (string): The full URL of the API endpoint.
        *   `method` (string): HTTP method (GET, POST, PUT, DELETE).
        *   `headers` (object, optional): Custom request headers.
        *   `params` (object, optional): URL query parameters.
        *   `body` (any, optional): Request body for POST/PUT requests (JSON is recommended).
        *   `role` (string): A descriptive label for the role/context being tested (e.g., "admin", "user", "unauthenticated"). This is for reporting purposes.
        *   `expected_status` (integer): The expected HTTP status code (e.g., 200, 401, 403).
        *   `expected_content` (any, optional): Criteria for validating the response body.
            *   String: Checks for substring presence.
            *   String starting with `"regex:"`: Treats the rest as a regular expression pattern.
            *   Object (`{}`) or Array (`[]`): Validates that the actual JSON response contains the specified structure and values as a subset.
    *   Use "Load Test Cases" and "Save Test Cases" to manage your JSON test definitions.
5.  **Run Tests:** Click the "Run Tests" button. The GUI will update its status, and progress will be shown in the "Log Output".
6.  **Review Results:**
    *   The "Log Output" provides real-time details of each request and validation outcome.
    *   The "Summary" section displays a concise overview of the test run, including total tests, pass/fail/error counts, and a list of potential vulnerabilities detected.

## Potential Vulnerability Identification

The tool flags a "Potential Vulnerability" when a test case is configured to expect a denial status code (401 or 403) but the actual HTTP response code falls within the success range (200-299). This indicates a potential authorization bypass or broken access control issue.

Further analysis of the detailed logs and response content for flagged tests is recommended to confirm the vulnerability.

## Security Considerations

*   **Test Environment:** **Only use this tool against systems you own or have explicit, written permission to test.** Unauthorized security testing is illegal and unethical.
*   **Credential Management:** The GUI prompts for credentials. For production use or repeated automated scans, consider more secure methods for storing and accessing sensitive information (e.g., environment variables, secrets management tools).
*   **MFA Configuration:** Ensure the email account or Twilio number used for MFA retrieval is dedicated for testing purposes and its security is managed appropriately.
*   **OTP Extraction:** The default regex for OTP extraction (`\b(\d{4}|\d{6}|\d{8})\b`) covers common formats. **Customize this regex in the `MFAHandler` class if the target application uses a different OTP format.**

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

