import re
import argparse
import requests
import subprocess


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
    parser.add_argument("nmap", help="nmap scan")
    parser.add_argument("headers", help="security headers scan")
    parser.add_argument("dirsearch", help="directory scan")
    parser.add_argument("testssl", help="ssl/tsl scan")
    args = parser.parse_args()


    domain = extract_domain(args.url)




    if check_website_accessible(args.url):
        if args.headers == 'True':
            Headers = subprocess.Popen(["python3", "./tools/headers.py", args.secret_key, args.scan_result_api, args.add_vulnerability_api, args.audit_id, args.url],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                universal_newlines=True
                                )
            
            output, errors = Headers.communicate()




        if args.nmap == 'True':
            Nmap = subprocess.Popen(["python3", "./tools/nmap.py", args.secret_key, args.scan_result_api, args.add_vulnerability_api, args.audit_id, domain],
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE,
                                            universal_newlines=True
                                            )

            output, errors = Nmap.communicate()



        if args.dirsearch == 'True':
            Dirsearch = subprocess.Popen(["python3", "./tools/dirsearch.py", args.secret_key, args.scan_result_api, args.add_vulnerability_api, args.audit_id, args.url],
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE,
                                            universal_newlines=True
                                            )

            output, errors = Dirsearch.communicate()



        if args.testssl == 'True':
            Lucky13 = subprocess.Popen(
                                    ["python3", "./tools/lucky13.py", args.secret_key, args.scan_result_api, args.add_vulnerability_api, args.audit_id, domain],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    universal_newlines=True)
            
            output, errors = Lucky13.communicate()

            Testssl = subprocess.Popen(["python3", "./tools/testssl.py", args.secret_key, args.scan_result_api, args.add_vulnerability_api, args.audit_id, args.url],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        universal_newlines=True
                        )
            
            output, errors = Testssl.communicate()



        if args.nuclei == 'True':
            Nuclei = subprocess.Popen(["python3", "./tools/nuclei.py", args.secret_key, args.scan_result_api, args.add_vulnerability_api, args.audit_id, args.url],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        universal_newlines=True
                        )
            
            output, errors = Nuclei.communicate()
        



        status_update = {'secret_key':args.secret_key, 
                      'audit_id':args.audit_id, 
                      'status':'finished',
                      }
        response = requests.post(args.scan_status_api, json=status_update)
    else:
        tools = []
        if args.nmap == 'True':
            tools.append('nmap')
            tools.append('vulnerabilities')
            tools.append('slowloris')
            tools.append('diffiehellman')
            tools.append('heartbleed')
            tools.append('poodle')
        if args.headers == 'True':
            tools.append('headers')
        if args.dirsearch == 'True':
            tools.append('dirsearch')
        if args.testssl == 'True':
            tools.append('testssl')
        if args.nuclei == 'True':
            tools.append('nuclei')

        status_update = {'secret_key':args.secret_key, 
                      'audit_id':args.audit_id, 
                      'status':'stopped',
                      'tools':tools
                      }
        response = requests.post(args.scan_status_api, json=status_update)