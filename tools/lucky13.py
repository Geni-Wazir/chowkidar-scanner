import requests
import argparse

def fetch_all_ciphers(domain):
    """Get all the ciphers used by serve from ssllabs.

    Args:
        domain: domain of the website.
    
    Returns:
        json data returned from ssllabs or None.
    """
    api_url = f"https://api.ssllabs.com/api/v3/analyze?host={domain}&all=done"
    response = requests.get(api_url)
    if response.status_code == 200:
        data = response.json()
        while data['status'] != 'READY':
            response = requests.get(api_url)
            data = response.json()
        return data
    else:
        None
        

def process_response(response):
    """Process and get the weak ciphers.

    Args:
        response: The response recieved form ssllabs.
    
    Returns:
        A dictionary where keys are the ip address of the server and values are list having weak ciphers.
    """
    endpoints = response['endpoints']
    endpoints_with_weak_ciphers = {}
    if endpoints:
        for endpoint in endpoints:
            weak_ciphers = []
            for cipher in endpoint['details']['suites'][0]['list']:
                if 'q' in cipher and cipher['q'] == 1:
                    weak_ciphers.append(cipher['name'])
            if weak_ciphers != []:
                endpoints_with_weak_ciphers[endpoint['ipAddress']] = weak_ciphers
        return endpoints_with_weak_ciphers
    else:
        return endpoints_with_weak_ciphers
    


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Performs directory enumeration")
    parser.add_argument("secret_key", help="Authentication secret key")
    parser.add_argument("scan_result_api", help="API to send the scan output")
    parser.add_argument("add_vulnerability_api", help="API to send the discovered vulnerabilities")
    parser.add_argument("audit_id", help="Audit id")
    parser.add_argument("url", help="Scope domin for scan")
    args = parser.parse_args()


    ciphers = process_response(fetch_all_ciphers(args.url))
    if ciphers != {}:
        discovered_weak_ciphers = {'secret_key':args.secret_key, 'audit_id':args.audit_id}
        discovered_weak_ciphers['vulnerabilities'] = {'Vulnerable to Lucky13':ciphers}
        response = requests.post(args.add_vulnerability_api, json=discovered_weak_ciphers)
