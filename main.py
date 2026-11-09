import argparse
import requests
import logging
import sys
from urllib.parse import urlparse

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
        # Redirects are not followed: a redirect at a metadata path is
        # not a metadata response, and following it could match keywords
        # on an unrelated page (for example the site home page).
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=False)
        if 300 <= response.status_code < 400:
            logging.info(f"Redirect from {url} (status {response.status_code}) not followed, not a metadata response")
            return False
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        content = response.text

        # Report the status, the response length, and the names of any
        # matched keywords only. The response body itself is never logged.
        logging.info(f"Response from {url}: status {response.status_code}, length {len(content)}")

        matched = []
        if sensitive_keywords:
            for keyword in sensitive_keywords:
                # Substring matching cuts both ways: iam appears inside ordinary words, and instance appears in plenty of harmless text. A match says the word was present, nothing about whether a credential or a token was anywhere near it.
                if keyword.lower() in content.lower():  # Case-insensitive search
                    matched.append(keyword)

        if matched:
            logging.warning(f"Possible sensitive information found (keywords: {', '.join(matched)}) in {url}")
            return True

        # A response with no matched sensitive keyword is not reported
        # as exposure: any web page served with a 200 at this path would
        # otherwise count, including a custom error or login page.
        if content:
             logging.info(f"Content retrieved from {url} (status {response.status_code}, length {len(content)}, no sensitive keywords matched, not reported as exposure)")
             return False
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
        # Build the metadata path onto the operator's target. The known
        # endpoint contributes only its path (and query), never its full
        # URL, so the checked address stays a valid URL on the target.
        endpoint = urlparse(config["url"])
        metadata_path = endpoint.path
        if endpoint.query:
            metadata_path = metadata_path + "?" + endpoint.query
        # AWS and Azure share the same address here, so a target scan tries both path shapes against one host and applies each providers headers in turn. The answers are logged per provider, but a host that answers the shared address cannot tell me which cloud it belongs to.
        metadata_url = target_url.rstrip('/') + metadata_path
        headers = config.get("headers")
        sensitive_keywords = config.get("sensitive_keywords")

        # The return value is thrown away by both callers. Everything this tool concludes lives in the log lines, the process exits 0 either way, and a calling script has nothing to test except its own reading of the log.
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
        # Run with no target, this reaches out to the real link local addresses from the machine it runs on. On an actual cloud instance that is a live test of my own metadata service, not a simulation, and the answers describe this machine.
        logging.info("Performing basic checks against known metadata endpoints...")
        for cloud, config in METADATA_ENDPOINTS.items():
            logging.info(f"Checking {cloud} metadata endpoint: {config['url']}")
            check_metadata_endpoint(config["url"], config.get("headers"), config.get("sensitive_keywords"))

    logging.info("Scan completed.")


if __name__ == "__main__":
    main()
