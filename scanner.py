import re
import argparse
import requests


def extract_domain(url: str) -> str:
    """Extract the domain name form the provided URL.

    Args:
        url: URL as a string.

    Returns:
        The ddomain as strin if domain is found else nothing.
    """
    pattern = r'https?://(?:www\.)?([a-zA-Z0-9.-]+)'
    match = re.search(pattern, url)
    if match:
        return match.group(1)
    else:
        return ""
    

def check_website_accessible(url: str) -> bool:
    """Checks the website accessiblity.

    Args:
        url: URL of the website.

    Returns:
        A boolean value True if accessible, False if not.
    """
    try:
        response = requests.get(url)
        return True
    except requests.ConnectionError:
        return False
    except:
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scripts to Initiate the scans")
    parser.add_argument("secret_key", help="Authentication secret key")
    parser.add_argument("scan_result_api", help="API to send the scan output")
    parser.add_argument("add_vulnerability_api", help="API to send the discovered vulnerabilities")
    parser.add_argument("scan_status_api", help="API to update the scan status")
    parser.add_argument("audit_id", help="Audit id")
    parser.add_argument("url", help="Scope URL for scan")
    args = parser.parse_args()


    domain = extract_domain(args.url)

    if check_website_accessible(args.url):
        pass
    else:
        pass