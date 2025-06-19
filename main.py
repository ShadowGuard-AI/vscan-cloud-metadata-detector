import argparse
import requests
import logging
import sys
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define cloud metadata endpoints
METADATA_ENDPOINTS = {
    "aws": {
        "url": "http://169.254.169.254/latest/meta-data/",
        "sensitive_keywords": ["access-key", "secret-key", "instance-id", "iam"]
    },
    "gcp": {
        "url": "http://metadata.google.internal/computeMetadata/v1/",
        "headers": {"Metadata-Flavor": "Google"},
        "sensitive_keywords": ["instance", "project", "zone", "id_token"]
    },
    "azure": {
        "url": "http://169.254.169.254/metadata/instance?api-version=2020-09-01",
        "headers": {"Metadata": "true"},
        "sensitive_keywords": ["vmId", "name", "location"]
    }
}


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Detects if cloud metadata endpoints are accessible and discloses sensitive information.")
    parser.add_argument("-u", "--url", help="Target URL to check for metadata exposure. If not provided, performs basic checks against known endpoints.", required=False)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output for debugging.", required=False)

    return parser.parse_args()


def check_metadata_endpoint(url, headers=None, sensitive_keywords=None):
    """
    Checks a given URL for metadata information and sensitive keywords.

    Args:
        url (str): The URL to check.
        headers (dict, optional): Headers to include in the request. Defaults to None.
        sensitive_keywords (list, optional): List of sensitive keywords to search for. Defaults to None.

    Returns:
        bool: True if sensitive information is found, False otherwise.
    """
    try:
        logging.info(f"Checking metadata endpoint: {url}")
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        content = response.text

        if sensitive_keywords:
            for keyword in sensitive_keywords:
                if keyword in content.lower():  # Case-insensitive search
                    logging.warning(f"Possible sensitive information found (keyword: {keyword}) in {url}")
                    return True

        if content:
             logging.info(f"Content retrieved from {url}:\n{content}")
             return True
        else:
            logging.info(f"No content retrieved from {url}")
            return False


    except requests.exceptions.RequestException as e:
        logging.error(f"Error accessing {url}: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False

def scan_target_url(target_url):
    """
    Scans the provided target URL for cloud metadata exposure.

    Args:
        target_url (str): The target URL to scan.

    Returns:
        None
    """
    logging.info(f"Starting scan on target URL: {target_url}")

    for cloud, config in METADATA_ENDPOINTS.items():
        metadata_url = target_url.rstrip('/') + config["url"]
        headers = config.get("headers")
        sensitive_keywords = config.get("sensitive_keywords")

        check_metadata_endpoint(metadata_url, headers, sensitive_keywords)



def main():
    """
    Main function to execute the cloud metadata detection tool.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.url:
        scan_target_url(args.url)
    else:
        # Basic Checks against known endpoints
        logging.info("Performing basic checks against known metadata endpoints...")
        for cloud, config in METADATA_ENDPOINTS.items():
            logging.info(f"Checking {cloud} metadata endpoint: {config['url']}")
            check_metadata_endpoint(config["url"], config.get("headers"), config.get("sensitive_keywords"))

    logging.info("Scan completed.")


if __name__ == "__main__":
    main()