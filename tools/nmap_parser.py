import xml.etree.ElementTree as ET

def parse_nmap_xml(filename: str) -> ET.ElementTree:
    """Parses an Nmap XML file.

    Args:
        filename: The path to the Nmap XML file.

    Returns:
        An ElementTree object representing the parsed XML.
    """
    return ET.parse(filename)




def find_hosts_with_open_ports(root: ET.Element) -> list[list[int, str, str]]:
    """Finds hosts with open ports and services.

    Args:
        root: The root element of the parsed Nmap XML.

    Returns:
        A nested list contains three elements: port number, service running, and version.
    """
    open_port_and_service = [['Ports', 'Services', 'Version'],]
    for host in root.findall('host'):
        if host.find('status').get('state') == 'up':
            for port_elem in host.find('ports').findall('port'):
                open_port_and_service.append([port_elem.get('portid'),
                                              port_elem.find('service').get('name') if port_elem.find('service') is not None else '',
                                              f"{port_elem.find('service').get('product') if port_elem.find('service').get('product') is not None else ''} {port_elem.find('service').get('version') if port_elem.find('service').get('version') is not None else ''}" if port_elem.find('service') is not None else ''
                                              ])

    return open_port_and_service




def find_vulnerable_service(root: ET.Element) -> dict[str, str]:
    """Finds ports running vulnerable services.

    Args:
        root: The root element of the parsed Nmap XML.

    Returns:
        A dictionary where keys are vulnerable ports with there versions and values are string containig all the CVEs.
    """
    ports_with_vulnerable_service = {}
    for host in root.findall('host'):
        if host.find('status').get('state') == 'up':
            for port_elem in host.find('ports').findall('port'):
                if port_elem.find('script'):
                    if port_elem.find('script').get('id')=="vulners":
                        ports_with_vulnerable_service[f"{port_elem.get('portid')} {port_elem.find('service').get('name') if port_elem.find('service') is not None else ''} {port_elem.find('service').get('version') if port_elem.find('service') is not None else ''}"] = port_elem.find('script').get('output')

    return ports_with_vulnerable_service




def diffiehellman_test(root: ET.Element) -> dict[str, str]:
    """Finds if the host is vulnerable to diffiehellman key exchange attack.

    Args:
        root: The root element of the parsed Nmap XML.

    Returns:
        A dictionary where keys are vulnerable ports with there versions and values are string containig all the CVEs.
    """
    ports_vulnerable_to_diffiehellman = {}
    for host in root.findall('host'):
        if host.find('status').get('state') == 'up':
            for port_elem in host.find('ports').findall('port'):
                if port_elem.find('script'):
                    if port_elem.find('script').get('id')=="ssl-dh-params":
                        ports_vulnerable_to_diffiehellman[f"{port_elem.get('portid')} {port_elem.find('service').get('name') if port_elem.find('service') is not None else ''}"] = port_elem.find('script').get('output')

    return ports_vulnerable_to_diffiehellman




def slowloris_test(root: ET.Element) -> dict[str, str]:
    """Finds if the host is vulnerable to Slowloris DDoS attack.

    Args:
        root: The root element of the parsed Nmap XML.

    Returns:
        A dictionary where keys are vulnerable ports with there versions and values are string containig all the CVEs.
    """
    ports_vulnerable_to_slowloris = {}
    for host in root.findall('host'):
        if host.find('status').get('state') == 'up':
            for port_elem in host.find('ports').findall('port'):
                if port_elem.find('script'):
                    if port_elem.find('script').get('id')=="http-slowloris-check":
                        ports_vulnerable_to_slowloris[f"{port_elem.get('portid')} {port_elem.find('service').get('name') if port_elem.find('service') is not None else ''}"] = port_elem.find('script').get('output')

    return ports_vulnerable_to_slowloris




def heartbleed_test(root: ET.Element) -> dict[str, str]:
    """Finds if the host is vulnerable to heartbleed attack.

    Args:
        root: The root element of the parsed Nmap XML.

    Returns:
        A dictionary where keys are vulnerable ports with there versions and values are string containig all the CVEs.
    """
    ports_vulnerable_to_heartbleed = {}
    for host in root.findall('host'):
        if host.find('status').get('state') == 'up':
            for port_elem in host.find('ports').findall('port'):
                if port_elem.find('script'):
                    if port_elem.find('script').get('id')=="ssl-heartbleed":
                        ports_vulnerable_to_heartbleed[f"{port_elem.get('portid')} {port_elem.find('service').get('name') if port_elem.find('service') is not None else ''}"] = port_elem.find('script').get('output')

    return ports_vulnerable_to_heartbleed




def poodle_test(root: ET.Element) -> dict[str, str]:
    """Finds if the host is vulnerable to Poodle attack.

    Args:
        root: The root element of the parsed Nmap XML.

    Returns:
        A dictionary where keys are vulnerable ports with there versions and values are string containig all the CVEs.
    """
    ports_vulnerable_to_poodle = {}
    for host in root.findall('host'):
        if host.find('status').get('state') == 'up':
            for port_elem in host.find('ports').findall('port'):
                if port_elem.find('script'):
                    if port_elem.find('script').get('id')=="ssl-poodle":
                        ports_vulnerable_to_poodle[f"{port_elem.get('portid')} {port_elem.find('service').get('name') if port_elem.find('service') is not None else ''}"] = port_elem.find('script').get('output')

    return ports_vulnerable_to_poodle