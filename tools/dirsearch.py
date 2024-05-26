import json
import subprocess
import argparse
import requests
from urllib.parse import urlparse

def run_dirsearch(url):
    process = subprocess.Popen(
        ["dirsearch",
         "-u", url,
         "-e", "php,js,json,zip,css,gz,zip,html,aspx,java,svg,pdf",
         "-x", "300,301,400,401,402,403,404,405,429,500",
         "--format=json", "-o", "dirsearch.json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )
    output, errors = process.communicate()
    if errors:
        print(f"Error occurred: {errors}")
        return None
    try:
        with open('tool-output.json', "r") as file:
            return json.load(file)
    except FileNotFoundError:
        print('No endpoints discovered')
        return None


def extract_endpoints(data):
    endpoints = [result['url'] + (" --> " + result['redirect']) if result['redirect'] else result['url'] for result in data['results']]
    directory_urls = [result['url'] for result in data['results'] if result['url'].endswith('/')]
    all_urls = [result['url'] for result in data['results']] + [result['redirect'] for result in data['results'] if result['redirect']]
    return endpoints, directory_urls, all_urls


def check_directory_listing(urls, headers):
    indicators = [
        '<title>Index of',
        'Index of /',
        'Directory listing for',
        'Parent Directory',
        'Directory Listing'
    ]

    vulnerable_urls = []
    for url in urls:
        response = requests.get(url, headers=headers)
        if any(indicator in response.text for indicator in indicators):
            vulnerable_urls.append(url)
    return vulnerable_urls


def check_cross_domain_referer_and_CORS(urls, headers, base_url):
    cross_domain_vulnerable_urls = []
    cors_vulnerable_urls = []

    urls = list(set(urls + [base_url]))  # Ensure the base URL is included and remove duplicates

    for url in urls:
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                # Check for Cross-Domain Referer vulnerability
                referer_value = response.headers.get('Referer')
                if referer_value and urlparse(referer_value).netloc != urlparse('https://evil.com').netloc:
                    cross_domain_vulnerable_urls.append(url)
                
                # Check for CORS vulnerability
                allow_origin = response.headers.get('Access-Control-Allow-Origin')
                if allow_origin and (allow_origin == '*' or urlparse(allow_origin).netloc == urlparse('https://evil.com').netloc):
                    cors_vulnerable_urls.append(url)
        except requests.RequestException as e:
            print(f'Request error: {e}')
    
    return cross_domain_vulnerable_urls, cors_vulnerable_urls



def report_vulnerabilities(api, secret_key, audit_id, vulnerabilities):
    payload = {
        'secret_key': secret_key,
        'audit_id': audit_id,
        'vulnerabilities': vulnerabilities
    }
    response = requests.post(api, json=payload)
    return response.status_code


def main(secret_key, add_vulnerability_api, audit_id, url):
    data = run_dirsearch(url)
    if not data:
        return

    endpoints, directory_urls, all_urls = extract_endpoints(data)
    vulnerabilities={}
    if endpoints:
        vulnerabilities['Endpoints Discovered'] = endpoints

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'en-GB,en-US;q=0.9,en;q=0.8',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://evil.com',
        'Origin':'https://evil.com',
    }


    directory_listing_vulns = check_directory_listing(directory_urls, headers)
    if directory_listing_vulns:
        vulnerabilities['Directory Listing Enabled'] = directory_listing_vulns


    cross_domain_referer_vulns, cors_vulns = check_cross_domain_referer_and_CORS(all_urls, headers, args.url)
    if cross_domain_referer_vulns:
        vulnerabilities['Cross-Domain Referer Leakage'] = cross_domain_referer_vulns


    if cors_vulns:
        vulnerabilities['Insecure Cross-Origin Resource Sharing Configuration'] = cors_vulns


    if vulnerabilities:
        status_code = report_vulnerabilities(add_vulnerability_api, secret_key, audit_id, vulnerabilities)
        if status_code == 200:
            print("Vulnerabilities reported successfully.")
        else:
            print(f"Failed to report vulnerabilities, status code: {status_code}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Performs directory enumeration")
    parser.add_argument("secret_key", help="Authentication secret key")
    parser.add_argument("add_vulnerability_api", help="API to send the discovered vulnerabilities")
    parser.add_argument("audit_id", help="Audit ID")
    parser.add_argument("url", help="Scope URL for scan")
    args = parser.parse_args()

    main(args.secret_key, args.add_vulnerability_api, args.audit_id, args.url)
