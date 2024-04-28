import json
import subprocess
import argparse
import requests




if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Performs directory enumeration")
    parser.add_argument("secret_key", help="secret key to submit the request")
    parser.add_argument("scan_result_api", help="API where to send the scan output")
    parser.add_argument("add_vulnerability_api", help="Server API endpoint for sending request")
    parser.add_argument("audit_id", help="Audit id for which the scan is Initiated")
    parser.add_argument("url", help="URL for which the ciphers needs to be extracted")
    args = parser.parse_args()

    headers = subprocess.Popen(
						    ["python3",
						     "./tools/shcheck.py", "-i", "-j", args.url],
						    stdout=subprocess.PIPE,
						    stderr=subprocess.PIPE,
						    universal_newlines=True
                            )


    output, errors = headers.communicate()


    if errors == '':
        security_headers = json.loads(output)
        vulnerabilities = {}
        headers_for = list(security_headers.keys())[0]
        missing_security_headers = {'secret_key':args.secret_key, 'audit_id':args.audit_id}
        if security_headers[headers_for]['missing'] != []:
            vulnerabilities['Missing Security Headers'] = security_headers[headers_for]['missing']
        if security_headers['information_disclosure'] != {}:
            vulnerabilities['Banner Grabbing'] = ['{} : {}'.format(headers_, security_headers['information_disclosure'][headers_]) for headers_ in security_headers['information_disclosure']]
        if vulnerabilities != {}:
            missing_security_headers['vulnerabilities'] = vulnerabilities
            response = requests.post(args.add_vulnerability_api, json=missing_security_headers)
       