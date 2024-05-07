import json
import subprocess
import argparse
import requests

def perform_directory_enumeration(secret_key, scan_result_api, add_vulnerability_api, audit_id, url):
    # Run dirsearch command with specified arguments
    dirsearch_process = subprocess.Popen(
        ["dirsearch",
         "-u", url,
         "-e", "php,js,json,zip,css,gz,zip,html,aspx,java,php,svg,pdf",
         "-x", "300,301,400,401,402,403,404,405,429,500",
         "--format=json", "-o", "dirsearch.json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )
    output, errors = dirsearch_process.communicate()

    if not errors:
        try:
            # Load JSON data from the output file
            with open('./dirsearch.json', "r") as file:
                data = json.load(file)
        except:
            print('No endpoints discovered')
            data = ''
            result_list = ''
        
        if data:
            # Extract discovered endpoints from JSON data
            discovered_endpoints = {'secret_key': secret_key, 'audit_id': audit_id}
            endpoints_list = [result['url'] + (" --> " + result['redirect']) if result['redirect'] else result['url'] for result in data['results']]
            result_list = {'Endpoints Discovered': endpoints_list}

            if result_list:
                discovered_endpoints['vulnerabilities'] = result_list
                # Send the discovered vulnerabilities to the API
                response = requests.post(add_vulnerability_api, json=discovered_endpoints)
    else:
        print(f"Error occurred: {errors}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Performs directory enumeration")
    parser.add_argument("secret_key", help="Authentication secret key")
    parser.add_argument("scan_result_api", help="API to send the scan output")
    parser.add_argument("add_vulnerability_api", help="API to send the discovered vulnerabilities")
    parser.add_argument("audit_id", help="Audit id")
    parser.add_argument("url", help="Scope URL for scan")
    args = parser.parse_args()

    # Call the directory enumeration function with parsed arguments
    perform_directory_enumeration(args.secret_key, args.scan_result_api, args.add_vulnerability_api, args.audit_id, args.url)
