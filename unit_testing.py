import unittest
from main import VulnerabilityScannerApp
from unittest.mock import patch, MagicMock, mock_open
import sqlite3
import tkinter as tk
from payload_loader import load_payloads
import utils
import logging

class TestVulnerabilityScannerApp(unittest.TestCase):
    def setUp(self):
        """Set up a temporary database for testing."""
        self.app = VulnerabilityScannerApp()
        self.app.conn = sqlite3.connect(':memory:')  # Use an in-memory database for testing
        self.app.database_setup()
        self.app.output = MagicMock()

    def setUp(self):
        """Set up a fresh database for each test."""
        self.app = VulnerabilityScannerApp()
        self.app.conn = sqlite3.connect(':memory:')  # Use an in-memory database
        self.app.database_setup()
        # Clear the table if needed
        self.app.cursor.execute("DELETE FROM subdomain_scan_results")
        self.app.conn.commit()
        
    def tearDown(self):
        """Close the database connection after each test."""
        self.app.conn.close()

    def test_database_setup(self):
        """Test the database setup function."""
        # Test if the tables exist
        tables = ["scan_results", "subdomain_scan_results", "csrf_scan_results", "clickjacking_scan_results"]
        self.app.cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        existing_tables = [row[0] for row in self.app.cursor.fetchall()]
        for table in tables:
            self.assertIn(table, existing_tables)

    def test_insert_subdomain_scan_result(self):
        """Test inserting a subdomain scan result."""
        test_subdomain = "test.example.com"
        test_domain = "example.com"
        self.app.insert_subdomain_scan_result(test_subdomain, test_domain)
        self.app.cursor.execute("SELECT * FROM subdomain_scan_results;")
        results = self.app.cursor.fetchall()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][1], test_subdomain)
        self.assertEqual(results[0][2], test_domain)




class TestXSSScan(unittest.TestCase):
    def setUp(self):
        """Set up the test environment before each test."""
        self.app = VulnerabilityScannerApp()
        # Mock the database connection and cursor
        self.app.conn = MagicMock()
        self.app.cursor = MagicMock()
        # Mock the output widget to prevent GUI calls during the test
        self.app.output = MagicMock()

    @patch('requests.get')
    def test_scan_xss_vulnerable(self, mock_get):
        """Test scanning a URL that is vulnerable to XSS."""
        # Mocking the requests.get response to simulate a vulnerable page
        mock_response = MagicMock()
        mock_response.text = '<script>alert("xss")</script>'
        mock_get.return_value = mock_response

        # Define a payload that should trigger the vulnerability detection
        test_payload = '<script>alert("xss")</script>'
        self.app.payloads = {"xss": [test_payload]}

        # Call the scan_xss method with a test URL and the mocked output
        test_url = "http://example.com"
        self.app.scan_xss(test_url, self.app.payloads["xss"], self.app.output)

        self.app.cursor.execute.assert_called()

    @patch('requests.get')
    def test_scan_xss_not_vulnerable(self, mock_get):
        """Test scanning a URL that is not vulnerable to XSS."""

        mock_response = MagicMock()
        mock_response.text = 'Safe Page Content'
        mock_get.return_value = mock_response

     
        test_payload = '<script>alert("xss")</script>'
        self.app.payloads = {"xss": [test_payload]}

        # Call the scan_xss method with a test URL and the mocked output
        test_url = "http://safe-example.com"
        self.app.scan_xss(test_url, self.app.payloads["xss"], self.app.output)

class TestSQLInjectionScan(unittest.TestCase):
    def setUp(self):
        """Set up the test environment before each test."""
        self.app = VulnerabilityScannerApp()
 
        self.app.conn = MagicMock()
        self.app.cursor = MagicMock()
    
        self.app.output = MagicMock()

    @patch('requests.get')
    def test_scan_sql_injection_vulnerable(self, mock_get):
        """Test scanning a URL that is vulnerable to SQL Injection."""

        mock_response = MagicMock()
        mock_response.text = 'SQL syntax error'
        mock_get.return_value = mock_response

        test_payload = "' OR '1'='1"
        self.app.payloads = {"sql": [test_payload]}

 
        test_url = "http://example.com/vulnerable"
        self.app.scan_sql_injection(test_url, self.app.payloads["sql"], self.app.output)

        self.app.cursor.execute.assert_called()

    @patch('requests.get')
    def test_scan_sql_injection_not_vulnerable(self, mock_get):
        """Test scanning a URL that is not vulnerable to SQL Injection."""

        mock_response = MagicMock()
        mock_response.text = 'No errors found'
        mock_get.return_value = mock_response

        test_payload = "' OR '1'='1"
        self.app.payloads = {"sql": [test_payload]}

        test_url = "http://example.com/safe"
        self.app.scan_sql_injection(test_url, self.app.payloads["sql"], self.app.output)


class TestOpenRedirectionScan(unittest.TestCase):
    def setUp(self):
        """Setup a fresh environment for each test."""
        self.app = VulnerabilityScannerApp()


        self.app.conn = MagicMock()
        self.app.cursor = MagicMock()
    
        self.app.output = MagicMock()

    @patch('requests.get')
    def test_scan_open_redirection_vulnerable(self, mock_get):
        """Test scanning a URL that is vulnerable to Open Redirection."""
    
        mock_response = MagicMock()
        mock_response.status_code = 302
        mock_response.headers = {'Location': 'http://example.com'}
        mock_get.return_value = mock_response

    
        test_payload = "/redirect?url=http://example.com"
        self.app.payloads = {"open_redirect": [test_payload]}

      
        test_url = "http://vulnerable-site.com"
        self.app.scan_open_redirection(test_url, self.app.payloads["open_redirect"], self.app.output)
        self.app.cursor.execute.assert_called()

    @patch('requests.get')
    def test_scan_open_redirection_not_vulnerable(self, mock_get):
        """Test scanning a URL that is not vulnerable to Open Redirection."""
   
        mock_response = MagicMock()
        mock_response.status_code = 200 
        mock_response.headers = {}
        mock_get.return_value = mock_response

        test_payload = "/redirect?url=http://safe-site.com"
        self.app.payloads = {"open_redirect": [test_payload]}


        test_url = "http://safe-site.com"
        self.app.scan_open_redirection(test_url, self.app.payloads["open_redirect"], self.app.output)

        self.app.output.insert.assert_called_with(tk.END, "Open Redirection Scan Completed.\n")
class TestClickjackingScan(unittest.TestCase):
    def setUp(self):
        """Prepare the environment for each test."""
        self.app = VulnerabilityScannerApp()
        # Mock the database interaction and the Tkinter output widget
        self.app.conn = MagicMock()
        self.app.cursor = MagicMock()
        self.app.output = MagicMock()

    @patch('requests.get')
    def test_scan_clickjacking_protected(self, mock_get):
        """Test scanning a URL that is protected against Clickjacking."""
        # Setup a mock response indicating the page is protected
        mock_response = MagicMock()
        mock_response.headers = {'X-Frame-Options': 'DENY'}
        mock_get.return_value = mock_response

        # Execute the scan
        test_url = "http://protected-example.com"
        self.app.scan_clickjacking(test_url, self.app.output)

    @patch('requests.get')
    def test_scan_clickjacking_vulnerable(self, mock_get):
        """Test scanning a URL that is vulnerable to Clickjacking."""
        # Setup a mock response indicating the page is vulnerable
        mock_response = MagicMock()
        mock_response.headers = {}  # No protection headers present
        mock_get.return_value = mock_response

        # Execute the scan
        test_url = "http://vulnerable-example.com"
        self.app.scan_clickjacking(test_url, self.app.output)


class TestLoadPayloads(unittest.TestCase):
    def test_load_payloads_success(self):
        """Test loading payloads successfully from a file."""
        mock_file_content = "payload1\npayload2\n\npayload3\n"
        expected_payloads = ['payload1', 'payload2', 'payload3']
        # Mock the open function and simulate reading from a file
        with patch("builtins.open", mock_open(read_data=mock_file_content)):
            payloads = load_payloads("fake_payloads.txt")
        # Check if the function returns the correct list of payloads
        self.assertEqual(payloads, expected_payloads)

    def test_load_payloads_file_not_found(self):
        """Test handling of a non-existent payload file."""
        # Simulate FileNotFoundError when trying to open a file
        with patch("builtins.open", side_effect=FileNotFoundError):
            with patch("builtins.print") as mocked_print:
                payloads = load_payloads("non_existent_file.txt")
                # Verify that the function returns an empty list
                self.assertEqual(payloads, [])
                # Verify that the correct error message was printed
                mocked_print.assert_called_with("Payload file not found: non_existent_file.txt")

class TestUtils(unittest.TestCase):
    @patch('logging.basicConfig')
    def test_setup_logging(self, mock_basicConfig):
        """Test that logging is set up with the correct parameters."""
        logfile = 'test.log'
        utils.setup_logging(logfile)
        mock_basicConfig.assert_called_with(filename=logfile, level=logging.INFO,
                                            format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    def test_format_gui_message(self):
        """Test formatting of GUI messages based on different levels."""
        self.assertEqual(utils.format_gui_message("Test message"), "[INFO] Test message")
        self.assertEqual(utils.format_gui_message("Warning message", "warning"), "[WARNING] Warning message")
        self.assertEqual(utils.format_gui_message("Error message", "error"), "[ERROR] Error message")
        self.assertEqual(utils.format_gui_message("Custom level message", "custom"), "[CUSTOM] Custom level message")

    @patch('tkinter.messagebox.showerror')
    def test_show_error_message(self, mock_showerror):
        """Test that the error message dialog is displayed with the correct title and message."""
        title = "Error Title"
        message = "Error Message"
        utils.show_error_message(title, message)
        mock_showerror.assert_called_with(title, message)

    def test_safe_str_lower(self):
        """Test safe conversion of strings to lower case, including non-string input handling."""
        self.assertEqual(utils.safe_str_lower("TEST"), "test")
        self.assertEqual(utils.safe_str_lower(123), None)
        self.assertIsNone(utils.safe_str_lower(None))
        self.assertEqual(utils.safe_str_lower("MixedCASE"), "mixedcase")

if __name__ == '__main__':
    unittest.main()