![logo](https://github.com/Geni-Wazir/chowkidar-scanner/assets/47722406/79d08dd0-6293-47f2-8ebd-3da120f58651)
<h1 align="center">Chowkidar Scanner</h1>

![home-report](https://github.com/Geni-Wazir/chowkidar-scanner/assets/47722406/96a6f206-40f5-4721-8513-eda49a47a9e3)


## Project Description:
Chowkidar Scanner is an integral part of the <a href="https://chowkidar.xyz/" target="_blank">Chowkidar platform</a>, enabling users to add new audits, perform automated scans, and generate detailed vulnerability reports. This scanner leverages various open-source tools and incorporates custom rules to detect and report vulnerabilities.

## Features
- **Automated Scanning:** Once a new audit is added via the Chowkidar platform, the scanner automatically performs a series of comprehensive scans to identify potential security issues.
  
- **Detailed Reporting:** The scanner generates detailed reports outlining the vulnerabilities detected, along with recommendations for remediation. These reports are accessible through the Chowkidar platform.
- **Diverse Toolset:** Chowkidar Scanner leverages a suite of open-source tools, each specialized in different aspects of security scanning, ensuring thorough coverage of potential vulnerabilities.
- **Custom Rules:** The scanner incorporates custom rules on top of the integrated tools, enhancing its ability to detect and report specific vulnerabilities relevant to the user's environment.
- **Integration with Chowkidar Platform:** Findings from the scans are reported directly to the Chowkidar platform, allowing users to manage and track their security posture effectively.

## Integrated Tools:
- **Nmap:** A powerful network scanning tool used for network discovery and security auditing.

- **Dirsearch:** A web path scanner that identifies directories and files in web servers.
- **Nuclei:** A fast, customizable vulnerability scanner based on YAML templates.
- **WPScan:** A security scanner specifically designed for WordPress sites.
- **Sublist3r:** A tool for subdomain enumeration, helping to map the attack surface.
- **testssl:** A tool for checking SSL/TLS vulnerabilities.
- **Security Headers:** An analyzer for HTTP response headers to detect security misconfigurations.

## Installation:
To install and set up the Chowkidar Scanner, follow these steps:

#### Prerequisites:
- Docker
- Chowkidar platform

1. Clone the repository:
```bash
git clone https://github.com/Geni-Wazir/chowkidar-scanner.git
```
2. Build the image (keep the image name scanner)
```bash
cd chowkidar-scanner
docker build . -t scanner
```

## Contributing:
Contributions to Sasori are welcome! If you encounter any bugs, have feature requests, or would like to contribute code improvements, please follow the following guidelines.

1. **Fork the Repository:** Begin by forking the Chowkidar Scanner repository to your GitHub account.
2. **Create a Branch:** Create a new branch for your work to keep your changes separate from the main codebase.
```bash
git checkout -b feature-name
```
3. **Commit Your Changes:** Make your changes and commit them with clear commit messages.
```bash
git commit -m "Your commit message"
```
4. **Push Your Changes:** Push your changes to your fork.
5. **Open a Pull Request:** After pushing your changes to your fork, proceed to open a pull request against the main chowkidar-scanner repository. Make sure to include a concise description of your modifications and explain why they are essential.

## License:
This project is licensed under the [MIT License](LICENSE.md).

## Acknowledgements:
I would like to thank the developers of the following tools for their contributions to the open-source community:
- **Nmap**
- **Dirsearch**
- **Nuclei**
- **WPScan**
- **Sublist3r**
- **testssl**



