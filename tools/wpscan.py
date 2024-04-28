import json
import subprocess
import argparse
import requests



def wordpress_interesting_findings(data):
    if 'interesting_findings' in data:
        for finding in data['interesting_findings']:
            name = finding['to_s'].replace(finding['url'], '').replace(':','')
            if 'xmlrpc' in finding['type']:
                wordpress_vulns[name.title()] = [finding['url'], finding['references']] # if xmlrpc enabled then add it to the vulnerablility list
            if 'debug_log' in finding['type']:
                wordpress_vulns[name.title()] = [finding['url']] # if debug_log found then add this to the vulnerablility list




def wordpress_version(data):
    worpress_vulnerability = []
    if data['version']['status'] in ['outdated', 'insecure']:
        wordpress_vulns['Outdated Wordpress Version Being Used'] = [data['version']['number']] # if wordpress version is outdated, add it to the vulnerablility list
    if data['version']['vulnerabilities'] != []:
        for vulnerability in data['version']['vulnerabilities']:
                worpress_vulnerability.append(vulnerability)
        wordpress_vulns['Wordpress Version With Known Vulnerabilities'] = worpress_vulnerability # if wordpress version is vulnerable, add it to the vulnerablility list




def wordpress_vulnerable_themes(data):
    outdated_themes = []
    vulnerable_theme = []
    if 'themes' in data:
        for theme in data['themes']:
            if data['themes'][theme]['outdated']:
                outdated_themes.append([data['themes'][theme]['slug'], data['themes'][theme]['latest_version']])
                wordpress_vulns['Outdated Wordpress Themes Being Used'] = outdated_themes # if themes are outdated, add them to the vulnerablility list
            if data['themes'][theme]['vulnerabilities'] != []:
                for vulnerability in data['themes'][theme]['vulnerabilities']:
                    vulnerable_theme.append(vulnerability)
                wordpress_vulns['Wordpress Theme With Known Vulnerabilities'] = vulnerable_theme  # if themes are vulnerable, add them to the vulnerablility list
    else:
        if data['main_theme']['outdated']:
            outdated_themes.append(f"{data['main_theme']['slug']} : {data['main_theme']['latest_version']}")
            wordpress_vulns['Outdated Wordpress Themes Being Used'] = outdated_themes # if main theme is outdated, add it to the vulnerablility list
            if data['main_theme']['vulnerabilities'] != []:
                for vulnerability in data['main_theme']['vulnerabilities']:
                    vulnerable_theme.append(vulnerability)
                wordpress_vulns['Wordpress Theme With Known Vulnerabilities'] = vulnerable_theme # if main theme is vulnerable, add it to the vulnerablility list




def wordpress_vulnerable_plugins(data):
    if 'plugins' in data:
        outdated_plugins = []
        for plugin in data['plugins']:
            vulnerable_plugin = []
            if data['plugins'][plugin]['outdated']:
                outdated_plugins.append(f"{data['plugins'][plugin]['slug']} : {data['plugins'][plugin]['latest_version']}")
                wordpress_vulns['Outdated Wordpress Plugins Being Used'] = outdated_plugins # if plugins are outdated, add them to the vulnerablility list
            if data['plugins'][plugin]['vulnerabilities'] != []:
                for vulnerability in data['plugins'][plugin]['vulnerabilities']:
                    vulnerable_plugin.append(vulnerability)
                wordpress_vulns['Wordpress Plugin With Known Vulnerabilities'] = vulnerable_plugin # if plugins are vulnerable, add them to the vulnerablility list




def wordpress_config_backups(data):
    if 'config_backups' in data:
        config_backups = list(data['config_backups'].keys())
        if config_backups != []:
            wordpress_vulns['Wordpress Config Backup File Discovered'] = config_backups # if configration and backup files are found, add them to the vulnerablility list




def wordpress_users(data):
    if 'users' in data:
        users = list(data['users'].keys())
        if users != []:
            wordpress_vulns['Wordpress Users Discovered'] = users # if users are found, add them to the vulnerablility list
        



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Performs directory enumeration")
    parser.add_argument("secret_key", help="Authentication secret key")
    parser.add_argument("scan_result_api", help="API to send the scan output")
    parser.add_argument("add_vulnerability_api", help="API to send the discovered vulnerabilities")
    parser.add_argument("audit_id", help="Audit id")
    parser.add_argument("url", help="Scope URL for scan")
    parser.add_argument("wpscan_api", help="wpscan API Key")
    args = parser.parse_args()

    wpscan_json = subprocess.Popen(
						    ["wpscan",
						     "--url", args.url,
						     "--api-token", args.wpscan_api,
						     "-e", "vp,vt,cb,dbe,u",
                             "-f", "json",
                             "-o", "wpscan.json"],
						    stdout=subprocess.PIPE,
						    stderr=subprocess.PIPE,
						    universal_newlines=True
                            )
    output, errors = wpscan_json.communicate()

    wpscan_orignal = subprocess.Popen(
						    ["wpscan",
						     "--url", args.url,
						     "--api-token", args.wpscan_api,
						     "-e", "vp,vt,cb,dbe,u",
                             "-f", "cli-no-colour",],
						    stdout=subprocess.PIPE,
						    stderr=subprocess.PIPE,
						    universal_newlines=True
                            )
    
    output_orignal, orignal_errors = wpscan_orignal.communicate()
    result = {'secret_key':args.secret_key, 'audit_id':args.audit_id, 'tool':'wpscan', 'output': output_orignal+orignal_errors}
    response = requests.post(args.scan_result_api, json=result)

    if errors == '':
        with open('wpscan.json', "r") as file:
            data = json.load(file)

        wordpress_vulns = {}

        wordpress_interesting_findings(data)
        wordpress_version(data)
        wordpress_vulnerable_themes(data)
        wordpress_vulnerable_plugins(data)
        wordpress_config_backups(data)
        wordpress_users(data)

        if wordpress_vulns != {}:
            discovered_vulnerability = {'secret_key':args.secret_key, 'audit_id':args.audit_id}
            discovered_vulnerability['vulnerabilities'] = wordpress_vulns
            response = requests.post(args.add_vulnerability_api, json=discovered_vulnerability)
            