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

    

    Dirsearch = subprocess.Popen(
						    ["dirsearch",
						     "-u", args.url,
						     "-e", "php,js,json,zip,css,gz,zip,html,aspx,java,php,svg,pdf",
						     "-x", "300,301,400,401,402,403,404,405,429,500", 
                             "--format=json", "-o", "dirsearch.json"],
						    stdout=subprocess.PIPE,
						    stderr=subprocess.PIPE,
						    universal_newlines=True
                            )
    
    output, errors = Dirsearch.communicate()


    if errors == '':
        try :
            with open('./dirsearch.json', "r") as file:
                data = json.load(file)
        except:
            print('No endpoints discovered')
            data = ''
            result_list = ''
        if data != '':
            discovered_endpoints = {'secret_key':args.secret_key, 'audit_id':args.audit_id}
            result_list = {'Endpoints Discovered':[result['url'] + (" --> " + result['redirect']) if result['redirect'] else result['url'] for result in data['results']]}
            if result_list != []:
                discovered_endpoints['vulnerabilities'] = result_list
                response = requests.post(args.add_vulnerability_api, json=discovered_endpoints)