import json
import subprocess
import argparse
import requests

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Performs directory enumeration")
    parser.add_argument("secret_key", help="Authentication secret key")
    parser.add_argument("scan_result_api", help="API to send the scan output")
    parser.add_argument("add_vulnerability_api", help="API to send the discovered vulnerabilities")
    parser.add_argument("audit_id", help="Audit id")
    parser.add_argument("url", help="Scope URL for scan")
    args = parser.parse_args()

    # Update Nuclei templates
    Nuclei_update = subprocess.Popen(
        ["nuclei", "-ut", "-up"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )
    output, errors = Nuclei_update.communicate()

    # Run Nuclei scan
    Nuclei = subprocess.Popen(
        ["nuclei", "-nc", "-u", args.url],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )
    output, errors = Nuclei.communicate()

    # Prepare and send scan result to the scan_result_api
    result = {'secret_key': args.secret_key, 'audit_id': args.audit_id, 'tool': 'nuclei', 'output': errors + output}
    response = requests.post(args.scan_result_api, json=result)
