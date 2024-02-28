def load_payloads(filepath):
    """
    Load payloads from a specified file.

    Args:
        filepath (str): The path to the payload file.

    Returns:
        list: A list of payloads read from the file, or an empty list if the file cannot be found.
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            payloads = [line.strip() for line in file if line.strip()]
        return payloads
    except FileNotFoundError:
        print(f"Payload file not found: {filepath}")
        return []

# Demonstration of loading payloads
if __name__ == "__main__":
    # Assuming the script is run from a directory where '/mnt/data/PayloadOpenRed.txt' is accessible
    filepath = '/mnt/data/PayloadOpenRed.txt'
    payloads = load_payloads(filepath)
    print(f"Loaded {len(payloads)} payloads from {filepath}")
    for payload in payloads[:10]:  # Print first 10 payloads as a sample
        print(payload)
