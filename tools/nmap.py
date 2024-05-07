import subprocess
import argparse
import requests

from nmap_parser import parse_nmap_xml, find_hosts_with_open_ports, find_vulnerable_service, diffiehellman_test, slowloris_test, heartbleed_test, poodle_test

def run_nmap_scan(tool, args, script_args=None):
    # Construct the command for Nmap scan
    nmap_command = ["nmap", "-T3", "-oX", f"./{tool}.xml", args.url]
    if script_args:
        nmap_command.extend(script_args)

    # Run the Nmap scan
    nmap_process = subprocess.Popen(nmap_command,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    universal_newlines=True)

    output, errors = nmap_process.communicate()

    # Prepare the result data
    result = {'secret_key': args.secret_key, 'audit_id': args.audit_id, 'tool': tool, 'output': output + errors}
    response = requests.post(args.scan_result_api, json=result)

    # Process the Nmap scan result for vulnerabilities
    parse_function = {
        'nmap': find_hosts_with_open_ports,
        'vulnerabilities': find_vulnerable_service,
        'slowloris': slowloris_test,
        'diffiehellman': diffiehellman_test,
        'heartbleed': heartbleed_test,
        'poodle': poodle_test
    }.get(tool)

    if parse_function:
        vulnerabilities = parse_function(parse_nmap_xml(f"./{tool}.xml"))
        if vulnerabilities:
            nmap_vulnerability = {'secret_key': args.secret_key, 'audit_id': args.audit_id, 'vulnerabilities': vulnerabilities}
            response = requests.post(args.add_vulnerability_api, json=nmap_vulnerability)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Perform NMAP scans and detect vulnerabilities")
    parser.add_argument("secret_key", help="Authentication secret key")
    parser.add_argument("scan_result_api", help="API to send the scan output")
    parser.add_argument("add_vulnerability_api", help="API to send the discovered vulnerabilities")
    parser.add_argument("audit_id", help="Audit id")
    parser.add_argument("url", help="Scope domain for scan")
    args = parser.parse_args()

    # Run Nmap scans for different tools
    run_nmap_scan('nmap', args, ["-sV", "-p-", "-Pn", "-T3"])
    run_nmap_scan('vulnerabilities', args, ["-sV", "-T3", "--script=vulners.nse"])
    run_nmap_scan('slowloris', args, ["-Pn", "-T3", "--script=http-slowloris-check"])
    run_nmap_scan('diffiehellman', args, ["--script=ssl-dh-params"])
    run_nmap_scan('heartbleed', args, ["-sV", "-T3", "--script=ssl-heartbleed", "-p443,80"])
    run_nmap_scan('poodle', args, ["-sV", "-T3", "--version-light", "--script=ssl-poodle"])
