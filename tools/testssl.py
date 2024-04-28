import json
import subprocess
import argparse
import requests


def check_ssl_tls(data):
    for result in data['scanResult']:
        ssl_tls = []
        for protocol in result['protocols']:
            if protocol['severity'] not in ['OK', 'INFO']:
                ssl_tls.append(protocol['id'])
                testssl_vulnerabilities['Non Compliant TLS Enabled'] = ssl_tls



def tls_vulnerabilies(data):
    for result in data['scanResult']:
        for vulnerability in result['vulnerabilities']:
            if vulnerability['severity'] not in ['OK', 'INFO', 'WARN']:
                if 'CRIME_TLS' in vulnerability['id']:
                    testssl_vulnerabilities['Potentially Vulnerable To CRIME'] = [vulnerability['cve']]
                elif 'POODLE_SSL' in vulnerability['id']:
                    testssl_vulnerabilities['Potentially Vulnerable To POODLE'] = [vulnerability['cve']]
                elif 'SWEET32' in vulnerability['id']:
                    testssl_vulnerabilities['Potentially Vulnerable To SWEET32'] = [vulnerability['cve']]
                elif 'FREAK' in vulnerability['id']:
                    testssl_vulnerabilities['Potentially Vulnerable To FREAK'] = [vulnerability['cve']]
                elif 'DROWN' in vulnerability['id']:
                    testssl_vulnerabilities['Potentially Vulnerable To DROWN'] = [vulnerability['cve']]
                elif 'LOGJAM' in vulnerability['id']:
                    testssl_vulnerabilities['Potentially Vulnerable To LOGJAM'] = [vulnerability['cve']]
                elif 'BEAST' in vulnerability['id']:
                    testssl_vulnerabilities['Potentially Vulnerable To BEAST'] = [vulnerability['cve']]
                elif 'RC4' in vulnerability['id']:
                    testssl_vulnerabilities['Potentially Vulnerable To RC4'] = [vulnerability['cve']]
                elif 'Winshock' in vulnerability['id']:
                    testssl_vulnerabilities['Potentially Vulnerable To WINSHOCK'] = [vulnerability['cve']]
        break




if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Performs directory enumeration")
    parser.add_argument("secret_key", help="secret key to submit the request")
    parser.add_argument("scan_result_api", help="API where to send the scan output")
    parser.add_argument("add_vulnerability_api", help="Server API endpoint for sending request")
    parser.add_argument("audit_id", help="Audit id for which the scan is Initiated")
    parser.add_argument("url", help="URL for which the ciphers needs to be extracted")
    args = parser.parse_args()

    testssl = subprocess.Popen(
						    ["testssl",
                             "--color",
                             "0",
						     "--jsonfile-pretty",
						     "./testssl.json",
						     args.url],
						    stdout=subprocess.PIPE,
						    stderr=subprocess.PIPE,
						    universal_newlines=True
                            )
    
    output, errors = testssl.communicate() 
    result = {'secret_key':args.secret_key, 'audit_id':args.audit_id, 'tool':'testssl', 'output': output+errors}
    response = requests.post(args.scan_result_api, json=result)

    if errors == '':
        with open('./testssl.json', "r") as file:
            data = json.load(file)

        testssl_vulnerabilities = {}

        check_ssl_tls(data)
        tls_vulnerabilies(data)
        if testssl_vulnerabilities != {}:
            testssl_result = {'secret_key':args.secret_key, 'audit_id':args.audit_id}
            testssl_result['vulnerabilities']= testssl_vulnerabilities
            response = requests.post(args.add_vulnerability_api, json=testssl_result)

