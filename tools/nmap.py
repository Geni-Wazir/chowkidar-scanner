import subprocess
import argparse
import requests

from nmap_parser import parse_nmap_xml, find_hosts_with_open_ports, find_vulnerable_service, diffiehellman_test, slowloris_test, heartbleed_test, poodle_test



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Perfom NMAP scan")
    parser.add_argument("secret_key", help="Authentication secret key")
    parser.add_argument("scan_result_api", help="API to send the scan output")
    parser.add_argument("add_vulnerability_api", help="API to send the discovered vulnerabilities")
    parser.add_argument("audit_id", help="Audit id")
    parser.add_argument("url", help="Scope domin for scan")
    args = parser.parse_args()


    nmap_vulnerability = {'secret_key':args.secret_key, 'audit_id':args.audit_id}

    

# Performs the ping with a service version detection scan for all 65535 ports.
    Nmap = subprocess.Popen(["nmap", "-sV", "-p-", "-Pn", "--min-rate=500", "-oX", "nmap.xml", args.url],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        universal_newlines=True
                                        )

    output, errors = Nmap.communicate()
    result = {'secret_key':args.secret_key, 'audit_id':args.audit_id, 'tool':'nmap', 'output': output+errors}
    response = requests.post(args.scan_result_api, json=result)
    open_ports = find_hosts_with_open_ports(parse_nmap_xml('./nmap.xml')) # process the result to find vulnerabilities
    vulnerabilities = {}
    if open_ports !={}:
        vulnerabilities['Review Open Ports'] = open_ports
    nmap_vulnerability['vulnerabilities'] = vulnerabilities
    response = requests.post(args.add_vulnerability_api, json=nmap_vulnerability) # send the discovered vulnerabilities to the server




# Performs the vulners script scan for all the known ports.
    Vulnerabilities = subprocess.Popen(["nmap", "-sV", "--script=vulners.nse", "-oX", "./vulnerabilities.xml", args.url],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        universal_newlines=True
                                        )
    
    output, errors = Vulnerabilities.communicate()
    result = {'secret_key':args.secret_key, 'audit_id':args.audit_id, 'tool':'vulnerabilities', 'output': output+errors}
    response = requests.post(args.scan_result_api, json=result)
    vulnerable_service = find_vulnerable_service(parse_nmap_xml('./vulnerabilities.xml')) # process the result to find vulnerabilities
    vulnerabilities = {}
    if vulnerable_service != {}:
        vulnerabilities['Ports Running Services With Known Vulnerabilities'] = vulnerable_service
    nmap_vulnerability['vulnerabilities'] = vulnerabilities
    response = requests.post(args.add_vulnerability_api, json=nmap_vulnerability) # send the discovered vulnerabilities to the server




# Performs the slowloris script scan for all the known ports.
    Slowloris = subprocess.Popen(["nmap", "-Pn", "--script=http-slowloris-check", "-oX", "./slowloris.xml", args.url],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                universal_newlines=True
                                )

    output, errors = Slowloris.communicate()
    result = {'secret_key':args.secret_key, 'audit_id':args.audit_id, 'tool':'slowloris', 'output': output+errors}
    response = requests.post(args.scan_result_api, json=result)
    slowloris = slowloris_test(parse_nmap_xml('./slowloris.xml')) # process the result to find vulnerabilities
    vulnerabilities = {}
    if slowloris != {}:
        vulnerabilities['Vulnerable To Slowloris DDoS Attack'] = slowloris
    nmap_vulnerability['vulnerabilities'] = vulnerabilities
    response = requests.post(args.add_vulnerability_api, json=nmap_vulnerability) # send the discovered vulnerabilities to the server




# Performs the diffiehellman script scan for all the known ports.
    DiffieHellman = subprocess.Popen(["nmap", "--script=ssl-dh-params", "-oX", "./diffiehellman.xml", args.url],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        universal_newlines=True
                                        )
    
    output, errors = DiffieHellman.communicate()
    result = {'secret_key':args.secret_key, 'audit_id':args.audit_id, 'tool':'diffiehellman', 'output': output+errors}
    response = requests.post(args.scan_result_api, json=result)
    diffiehellman = diffiehellman_test(parse_nmap_xml('./diffiehellman.xml')) # process the result to find vulnerabilities
    vulnerabilities = {}
    if diffiehellman != {}:
        vulnerabilities['Vulnerable To Diffie-Hellman Key Exchange Attack'] = diffiehellman

    nmap_vulnerability['vulnerabilities'] = vulnerabilities
    response = requests.post(args.add_vulnerability_api, json=nmap_vulnerability) # send the discovered vulnerabilities to the server




# Performs the heartbleed script scan for all the known ports.
    Heartbleed = subprocess.Popen(["nmap", "-sV", "--script=ssl-heartbleed", "-p443,80", "-oX", "./heartbleed.xml", args.url],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    universal_newlines=True
                                    )
    
    output, errors = Heartbleed.communicate()
    result = {'secret_key':args.secret_key, 'audit_id':args.audit_id, 'tool':'heartbleed', 'output': output+errors}
    response = requests.post(args.scan_result_api, json=result)
    heartbleed = heartbleed_test(parse_nmap_xml('./heartbleed.xml')) # process the result to find vulnerabilities
    vulnerabilities = {}
    if heartbleed != {}:
        vulnerabilities['Vulnerable To OpenSSL Heartbleed Attack'] = heartbleed
    response = requests.post(args.add_vulnerability_api, json=nmap_vulnerability) # send the discovered vulnerabilities to the server




# Performs the poodle script scan for all the known ports.
    Poodle = subprocess.Popen(["nmap", "-sV", "--version-light", "--script=ssl-poodle", "-oX", "./poodle.xml", args.url],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                universal_newlines=True
                                )

    output, errors = Poodle.communicate()
    result = {'secret_key':args.secret_key, 'audit_id':args.audit_id, 'tool':'poodle', 'output': output+errors}
    response = requests.post(args.scan_result_api, json=result)
    poodle = poodle_test(parse_nmap_xml('./poodle.xml')) # process the result to find vulnerabilities
    vulnerabilities = {}
    if poodle != {}:
        vulnerabilities['Vulnerable To Poodle SSLv3 Attack'] = poodle
    nmap_vulnerability['vulnerabilities'] = vulnerabilities
    response = requests.post(args.add_vulnerability_api, json=nmap_vulnerability) # send the discovered vulnerabilities to the server