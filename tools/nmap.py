import subprocess
import argparse
import requests

from nmap_parser import parse_nmap_xml, find_hosts_with_open_ports, find_vulnerable_service, diffiehellman_test, slowloris_test, heartbleed_test, poodle_test



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Performs directory enumeration")
    parser.add_argument("secret_key", help="secret key to submit the request")
    parser.add_argument("scan_result_api", help="API where to send the scan output")
    parser.add_argument("add_vulnerability_api", help="Server API endpoint for sending request")
    parser.add_argument("audit_id", help="Audit id for which the scan is Initiated")
    parser.add_argument("url", help="URL for which nmap scan need to be done")
    args = parser.parse_args()


    nmap_vulnerability = {'secret_key':args.secret_key, 'audit_id':args.audit_id}

    

    Nmap = subprocess.Popen(["nmap", "-sV", "-p-", "-Pn", "-T3", "-oX", "nmap.xml", args.url],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        universal_newlines=True
                                        )

    output, errors = Nmap.communicate()
    result = {'secret_key':args.secret_key, 'audit_id':args.audit_id, 'tool':'nmap', 'output': output+errors}
    response = requests.post(args.scan_result_api, json=result)
    open_ports = find_hosts_with_open_ports(parse_nmap_xml('./nmap.xml'))
    vulnerabilities = {}
    if open_ports !={}:
        vulnerabilities['Review Open Ports'] = open_ports
    nmap_vulnerability['vulnerabilities'] = vulnerabilities
    response = requests.post(args.add_vulnerability_api, json=nmap_vulnerability)




    Vulnerabilities = subprocess.Popen(["nmap", "-sV", "--script=vulners.nse", "-T3", "-oX", "./vulnerabilities.xml", args.url],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        universal_newlines=True
                                        )
    
    output, errors = Vulnerabilities.communicate()
    result = {'secret_key':args.secret_key, 'audit_id':args.audit_id, 'tool':'vulnerabilities', 'output': output+errors}
    response = requests.post(args.scan_result_api, json=result)
    vulnerable_service = find_vulnerable_service(parse_nmap_xml('./vulnerabilities.xml'))
    vulnerabilities = {}
    if vulnerable_service != {}:
        vulnerabilities['Ports Running Services With Known Vulnerabilities'] = vulnerable_service
    nmap_vulnerability['vulnerabilities'] = vulnerabilities
    response = requests.post(args.add_vulnerability_api, json=nmap_vulnerability)



    Slowloris = subprocess.Popen(["nmap", "-Pn", "--script=http-slowloris-check", "-T3", "-oX", "./slowloris.xml", args.url],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                universal_newlines=True
                                )

    output, errors = Slowloris.communicate()
    result = {'secret_key':args.secret_key, 'audit_id':args.audit_id, 'tool':'slowloris', 'output': output+errors}
    response = requests.post(args.scan_result_api, json=result)
    slowloris = slowloris_test(parse_nmap_xml('./slowloris.xml'))
    vulnerabilities = {}
    if slowloris != {}:
        vulnerabilities['Vulnerable To Slowloris DDoS Attack'] = slowloris
    nmap_vulnerability['vulnerabilities'] = vulnerabilities
    response = requests.post(args.add_vulnerability_api, json=nmap_vulnerability)




    DiffieHellman = subprocess.Popen(["nmap", "--script=ssl-dh-params", "-T3", "-oX", "./diffiehellman.xml", args.url],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        universal_newlines=True
                                        )
    
    output, errors = DiffieHellman.communicate()
    result = {'secret_key':args.secret_key, 'audit_id':args.audit_id, 'tool':'diffiehellman', 'output': output+errors}
    response = requests.post(args.scan_result_api, json=result)
    diffiehellman = diffiehellman_test(parse_nmap_xml('./diffiehellman.xml'))
    vulnerabilities = {}
    if diffiehellman != {}:
        vulnerabilities['Vulnerable To Diffie-Hellman Key Exchange Attack'] = diffiehellman

    nmap_vulnerability['vulnerabilities'] = vulnerabilities
    response = requests.post(args.add_vulnerability_api, json=nmap_vulnerability)



    Heartbleed = subprocess.Popen(["nmap", "-sV", "--script=ssl-heartbleed", "-T3", "-p443,80", "-oX", "./heartbleed.xml", args.url],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    universal_newlines=True
                                    )
    
    output, errors = Heartbleed.communicate()
    result = {'secret_key':args.secret_key, 'audit_id':args.audit_id, 'tool':'heartbleed', 'output': output+errors}
    response = requests.post(args.scan_result_api, json=result)
    heartbleed = heartbleed_test(parse_nmap_xml('./heartbleed.xml'))
    vulnerabilities = {}
    if heartbleed != {}:
        vulnerabilities['Vulnerable To OpenSSL Heartbleed Attack'] = heartbleed
    response = requests.post(args.add_vulnerability_api, json=nmap_vulnerability)




    Poodle = subprocess.Popen(["nmap", "-sV", "--version-light", "--script=ssl-poodle", "-T3", "-oX", "./poodle.xml", args.url],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                universal_newlines=True
                                )

    output, errors = Poodle.communicate()
    result = {'secret_key':args.secret_key, 'audit_id':args.audit_id, 'tool':'poodle', 'output': output+errors}
    response = requests.post(args.scan_result_api, json=result)
    poodle = poodle_test(parse_nmap_xml('./poodle.xml'))
    vulnerabilities = {}
    if poodle != {}:
        vulnerabilities['Vulnerable To Poodle SSLv3 Attack'] = poodle
    nmap_vulnerability['vulnerabilities'] = vulnerabilities
    response = requests.post(args.add_vulnerability_api, json=nmap_vulnerability)

