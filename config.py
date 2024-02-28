import os

# Base directory of the project
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Payload file paths
PAYLOAD_FILES = {
    'xss': os.path.join(BASE_DIR, 'Payloads', 'PayloadXSS.txt'),
    'sql': os.path.join(BASE_DIR, 'Payloads', 'PayloadSQL.txt'),
    'rce': os.path.join(BASE_DIR, 'Payloads', 'PayloadRCE.txt'),
    'ssti': os.path.join(BASE_DIR, 'Payloads', 'PayloadSSTI.txt'),
    'open_redirect': os.path.join(BASE_DIR, 'Payloads', 'PayloadOpenRed.txt'),
    # Add other payload types as needed
}

# WebDriver configurations
WEBDRIVER_CONFIG = {
    'chrome': {
        'path': os.path.join(BASE_DIR, 'WebDrivers', 'chromedriver'),  # Path to ChromeDriver
        'headless': True  # Run Chrome in headless mode
    },
    'firefox': {
        'path': os.path.join(BASE_DIR, 'WebDrivers', 'geckodriver'),  # Path to GeckoDriver
        'headless': True  # Run Firefox in headless mode
    },
    # Add other browsers as needed
}

# Logging configuration
LOG_FILE = os.path.join(BASE_DIR, 'Vulnerability_scanner.log')

# Example of extending the configuration for other needs
# Define the maximum depth for link crawling
MAX_CRAWL_DEPTH = 3

# Selenium WebDriver implicit wait time
WEBDRIVER_IMPLICIT_WAIT = 10  # seconds
