import logging
from tkinter import messagebox

# Configure logging
def setup_logging(logfile='Vulnerability_scanner.log'):
    """
    Sets up basic logging for the application.

    Args:
        logfile (str): Path to the log file.
    """
    logging.basicConfig(filename=logfile, level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# Utility function for GUI message formatting
def format_gui_message(message, level="info"):
    """
    Formats a message string with a prefix based on the level of the message.

    Args:
        message (str): The message to format.
        level (str): The level of the message ('info', 'warning', 'error').

    Returns:
        str: The formatted message.
    """
    if level.lower() == "info":
        return f"[INFO] {message}"
    elif level.lower() == "warning":
        return f"[WARNING] {message}"
    elif level.lower() == "error":
        return f"[ERROR] {message}"
    else:
        return f"[{level.upper()}] {message}"

# Example utility function to show error dialogs in the GUI
def show_error_message(title, message):
    """
    Displays an error message dialog.

    Args:
        title (str): The title of the dialog window.
        message (str): The error message to display.
    """
    messagebox.showerror(title, message)

# Example utility function for safely converting string to lower case
def safe_str_lower(text):
    """
    Safely converts a string to lower case, handling cases where input is not a string.

    Args:
        text: The text to convert to lower case.

    Returns:
        The lower case version of the text if it is a string, otherwise returns None.
    """
    if isinstance(text, str):
        return text.lower()
    return None
