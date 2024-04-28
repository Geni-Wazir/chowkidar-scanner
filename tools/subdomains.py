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


    subdomians_scan = subprocess.Popen(
						    ["sublist3r",
						     "-d",args.url,
                             "-n",
                             "-o", "./subdomains.txt"],
						    stdout=subprocess.PIPE,
						    stderr=subprocess.PIPE,
						    universal_newlines=True
                            )
    
    output, errors = subdomians_scan.communicate()
    result = {'secret_key':args.secret_key, 'audit_id':args.audit_id, 'tool':'sublister', 'output': errors+output}
    response = requests.post(args.scan_result_api, json=result)

    
    
    if errors == '':
        discovered_subdomains = {'secret_key':args.secret_key, 'audit_id':args.audit_id}

        with open('./subdomains.txt', "r") as file:
            data = file.read()

        subdomains = {'Discovered Subdomains':data.splitlines()}
        discovered_subdomains['vulnerabilities']= subdomains

        response = requests.post(args.add_vulnerability_api, json=discovered_subdomains)

    print('Sublister Output')
    print(output)
    print()
    print('Sublister Errors')
    print(errors)


