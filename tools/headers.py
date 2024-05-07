import json
import subprocess
import argparse
import requests

def check_security_headers(secret_key, add_vulnerability_api, audit_id, url):
    headers_process = subprocess.Popen(
        ["python3",
         "./tools/shcheck.py", "-i", "-j", url],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )

    output, errors = headers_process.communicate()

    if not errors:
        security_headers = json.loads(output)
        vulnerabilities = {}
        headers_for = list(security_headers.keys())[0]
        missing_security_headers = {'secret_key': secret_key, 'audit_id': audit_id}

        if security_headers[headers_for]['missing']:
            vulnerabilities['Missing Security Headers'] = security_headers[headers_for]['missing']
        if security_headers['information_disclosure']:
            vulnerabilities['Banner Grabbing'] = [f"{header}: {value}" for header, value in security_headers['information_disclosure'].items()]

        if vulnerabilities:
            missing_security_headers['vulnerabilities'] = vulnerabilities
            response = requests.post(add_vulnerability_api, json=missing_security_headers)
    else:
        print(f"Error occurred: {errors}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Performs security header check")
    parser.add_argument("secret_key", help="Authentication secret key")
    parser.add_argument("add_vulnerability_api", help="API to send the discovered vulnerabilities")
    parser.add_argument("audit_id", help="Audit id")
    parser.add_argument("url", help="Scope domain for security header check")
    args = parser.parse_args()

    check_security_headers(args.secret_key, args.add_vulnerability_api, args.audit_id, args.url)
