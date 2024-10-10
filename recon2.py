import os
import json
import csv
import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import shutil
import sys
import requests
import xml.etree.ElementTree as ET
from ipwhois import IPWhois
import whois

# Configure logging
logging.basicConfig(
    filename='scan_logs.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# Check if required tools are installed
def check_tools():
    tools = ['nuclei', 'nikto', 'gobuster', 'nmap', 'wapiti']
    missing_tools = []
    for tool in tools:
        if shutil.which(tool) is None:
            missing_tools.append(tool)
    if missing_tools:
        logging.error(f"Missing tools: {', '.join(missing_tools)}. Please install them before running the script.")
        raise EnvironmentError(f"Missing tools: {', '.join(missing_tools)}. Please install them before running the script.")
    logging.info("All required tools are installed.")

# Load subdomains from a file
def load_subdomains(file_path):
    if not os.path.exists(file_path):
        logging.error(f"Subdomains file not found: {file_path}")
        raise FileNotFoundError(f"Subdomains file not found: {file_path}")
    with open(file_path, 'r') as file:
        subdomains = [line.strip() for line in file if line.strip()]
    logging.info(f"Loaded {len(subdomains)} subdomains from {file_path}")
    return subdomains

# Check if a subdomain is active
def is_subdomain_active(subdomain, timeout=5):
    protocols = ['https://', 'http://']
    for protocol in protocols:
        url = f"{protocol}{subdomain}"
        try:
            response = requests.head(url, timeout=timeout, allow_redirects=True)
            if 200 <= response.status_code < 400:
                logging.info(f"Subdomain active: {url} (Status Code: {response.status_code})")
                return True
        except requests.RequestException as e:
            logging.warning(f"Failed to reach {url}: {e}")
    logging.info(f"Subdomain inactive: {subdomain}")
    return False

# General scan function
def run_scan(command, output_file, parser=lambda x: x):
    try:
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if os.path.exists(output_file):
            with open(output_file, 'r') as file:
                return parser(file.read())
        else:
            logging.warning(f"Output file {output_file} does not exist.")
            return None
    except subprocess.CalledProcessError as e:
        logging.error(f"Command {' '.join(command)} failed: {e.stderr.decode().strip()}")
        return None
    except Exception as e:
        logging.error(f"Error running command {' '.join(command)}: {str(e)}")
        return None

# Nuclei scan function
def nuclei_scan(subdomain):
    output_file = f"outputs/{subdomain}_nuclei.json"
    command = ['nuclei', '-u', f"https://{subdomain}", '-json', '-o', output_file]
    result = run_scan(command, output_file, parser=lambda x: json.loads(x) if x else [])
    return {"nuclei_vulnerabilities": result} if result else {"nuclei_vulnerabilities": []}

# Nikto scan function
def nikto_scan(subdomain):
    output_file = f"outputs/{subdomain}_nikto.json"
    command = ['nikto', '-host', f"https://{subdomain}", '-Format', 'json', '-output', output_file]
    result = run_scan(command, output_file, parser=lambda x: json.loads(x) if x else {})
    return {"nikto_results": result} if result else {"nikto_results": {}}

# Gobuster scan function (replacing Dirsearch)
def gobuster_scan(subdomain):
    output_file = f"outputs/{subdomain}_gobuster.json"
    wordlist = '/usr/share/wordlists/dirbuster/common.txt'  # Update the path to your wordlist
    if not os.path.exists(wordlist):
        logging.error(f"Gobuster wordlist not found: {wordlist}")
        return {"gobuster_results": {}}
    command = [
        'gobuster', 'dir', 
        '-u', f"https://{subdomain}",
        '-w', wordlist,
        '-o', output_file,
        '-f',  # Force Gobuster to write in JSON format (requires Gobuster v3.1.0+)
        '--json'
    ]
    # Gobuster may not support JSON output in all versions; adjust accordingly
    result = run_scan(command, output_file, parser=lambda x: json.load(x) if x else {})
    return {"gobuster_results": result} if result else {"gobuster_results": {}}

# Wapiti scan function (replacing OWASP ZAP)
def wapiti_scan(subdomain):
    output_file = f"outputs/{subdomain}_wapiti.json"
    command = [
        'wapiti', 
        '-u', f"https://{subdomain}", 
        '-f', 'json', 
        '-o', output_file
    ]
    result = run_scan(command, output_file, parser=lambda x: json.loads(x) if x else {})
    return {"wapiti_results": result} if result else {"wapiti_results": {}}

# Nmap scan function with IP extraction
def nmap_scan(subdomain):
    output_file = f"outputs/{subdomain}_nmap.xml"
    command = ['nmap', '-sV', '-oX', output_file, subdomain]
    result = run_scan(command, output_file, parser=lambda x: x)  # Raw XML content

    if result:
        try:
            tree = ET.ElementTree(ET.fromstring(result))
            root = tree.getroot()
            # Nmap XML namespace handling if necessary
            # Extract the IP address
            address = root.find('host/address[@addrtype="ipv4"]')
            ip_address = address.get('addr') if address is not None else "N/A"
            logging.info(f"Extracted IP address for {subdomain}: {ip_address}")
            return {"nmap_results": result, "ip_address": ip_address}
        except ET.ParseError as e:
            logging.error(f"Error parsing Nmap XML for {subdomain}: {e}")
            return {"nmap_results": result, "ip_address": "Parsing Error"}
    else:
        return {"nmap_results": "", "ip_address": "No Data"}

# Function to perform WHOIS lookup for a given IP address
def whois_lookup(ip_address):
    if ip_address in ["N/A", "Parsing Error", "No Data"]:
        return {"asn": "N/A", "org": "N/A"}
    try:
        obj = IPWhois(ip_address)
        results = obj.lookup_rdap(asn_methods=["whois"])
        asn = results.get('asn', 'N/A')
        org = results.get('asn_description', 'N/A')
        logging.info(f"WHOIS lookup for IP {ip_address}: ASN {asn}, Org {org}")
        return {"asn": asn, "org": org}
    except Exception as e:
        logging.error(f"WHOIS lookup failed for IP {ip_address}: {e}")
        return {"asn": "Lookup Failed", "org": "Lookup Failed"}

# Function to perform WHOIS domain lookup
def domain_whois_lookup(subdomain):
    try:
        w = whois.whois(subdomain)
        registrant = w.registrant if hasattr(w, 'registrant') else 'N/A'
        # Handle cases where creation_date and expiration_date can be lists or single values
        if isinstance(w.creation_date, list):
            creation_date = w.creation_date[0].isoformat() if w.creation_date else 'N/A'
        elif hasattr(w.creation_date, 'isoformat'):
            creation_date = w.creation_date.isoformat()
        else:
            creation_date = 'N/A'

        if isinstance(w.expiration_date, list):
            expiration_date = w.expiration_date[0].isoformat() if w.expiration_date else 'N/A'
        elif hasattr(w.expiration_date, 'isoformat'):
            expiration_date = w.expiration_date.isoformat()
        else:
            expiration_date = 'N/A'

        logging.info(f"WHOIS lookup for domain {subdomain}: Registrant {registrant}, Creation Date {creation_date}, Expiration Date {expiration_date}")
        return {
            "domain_registrant": registrant,
            "domain_creation_date": creation_date,
            "domain_expiration_date": expiration_date
        }
    except Exception as e:
        logging.error(f"Domain WHOIS lookup failed for {subdomain}: {e}")
        return {
            "domain_registrant": "Lookup Failed",
            "domain_creation_date": "Lookup Failed",
            "domain_expiration_date": "Lookup Failed"
        }

# Function to run all scans on a single subdomain
def run_scans(subdomain):
    logging.info(f"Starting scans for {subdomain}")
    results = {"subdomain": subdomain, "errors": []}

    scan_functions = [
        nuclei_scan,
        nikto_scan,
        gobuster_scan,
        nmap_scan,
        wapiti_scan
    ]

    scan_results = {}
    for scan in scan_functions:
        try:
            scan_result = scan(subdomain)
            # Merge scan_result into scan_results
            for key, value in scan_result.items():
                # If the key already exists and is a list or dict, merge appropriately
                if key in scan_results:
                    if isinstance(value, list):
                        scan_results[key].extend(value)
                    elif isinstance(value, dict):
                        scan_results[key].update(value)
                    else:
                        scan_results[key] = value
                else:
                    scan_results[key] = value
        except Exception as e:
            error_message = f"{scan.__name__} failed: {str(e)}"
            logging.error(error_message)
            results["errors"].append(error_message)

    # Extract IP address from Nmap results
    ip_address = scan_results.get("ip_address", "N/A")
    results["ip_address"] = ip_address

    # Perform WHOIS lookups
    whois_data = whois_lookup(ip_address)
    results.update(whois_data)

    domain_whois_data = domain_whois_lookup(subdomain)
    results.update(domain_whois_data)

    # Merge other scan results
    for key, value in scan_results.items():
        if key not in ["ip_address"]:
            results[key] = value

    logging.info(f"Completed scans for {subdomain}")
    return results

# Save results to a JSON file
def save_to_json(data, filename='vulnerability_results.json'):
    with open(filename, 'w') as json_file:
        json.dump(data, json_file, indent=4)
    logging.info(f"Results saved to {filename}")

# Save results to a CSV file
def save_to_csv(data, filename='vulnerability_results.csv'):
    with open(filename, 'w', newline='', encoding='utf-8') as csv_file:
        # Determine all possible keys
        fieldnames = set()
        for entry in data:
            fieldnames.update(entry.keys())
        fieldnames = sorted(list(fieldnames))  # Sorted for consistency

        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for entry in data:
            writer.writerow(entry)
    logging.info(f"Results saved to {filename}")

# Ensure output directories exist
def setup_output_directories():
    os.makedirs('outputs', exist_ok=True)
    logging.info("Output directories are set up.")

# Main function
def main(subdomains_file):
    try:
        setup_output_directories()
        check_tools()
        subdomains = load_subdomains(subdomains_file)

        active_subdomains = []
        inactive_subdomains = []
        # Check subdomains' activity
        logging.info("Starting subdomain validation...")
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_subdomain = {executor.submit(is_subdomain_active, subdomain): subdomain for subdomain in subdomains}
            for future in as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    is_active = future.result()
                    if is_active:
                        active_subdomains.append(subdomain)
                    else:
                        inactive_subdomains.append(subdomain)
                except Exception as exc:
                    logging.error(f"Error checking subdomain {subdomain}: {exc}")
                    inactive_subdomains.append(subdomain)

        logging.info(f"Subdomain validation completed. {len(active_subdomains)} active, {len(inactive_subdomains)} inactive.")

        if active_subdomains:
            all_results = []
            # Use ThreadPoolExecutor for parallel scanning
            max_workers = min(10, len(active_subdomains))  # Adjust based on your system
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_subdomain = {executor.submit(run_scans, subdomain): subdomain for subdomain in active_subdomains}
                for future in as_completed(future_to_subdomain):
                    subdomain = future_to_subdomain[future]
                    try:
                        result = future.result()
                        all_results.append(result)
                    except Exception as exc:
                        logging.error(f"{subdomain} generated an exception: {exc}")
                        all_results.append({"subdomain": subdomain, "errors": [str(exc)]})

            # Save results to both JSON and CSV formats
            save_to_json(all_results)
            save_to_csv(all_results)
            logging.info("All scans completed successfully.")
        else:
            logging.warning("No active subdomains to scan.")

        if inactive_subdomains:
            # Optionally, save inactive subdomains to a separate file
            with open('inactive_subdomains.txt', 'w') as file:
                for sub in inactive_subdomains:
                    file.write(f"{sub}\n")
            logging.info(f"Inactive subdomains saved to inactive_subdomains.txt")

    except Exception as e:
        logging.critical(f"Script terminated due to an error: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scan_script.py <subdomains_file>")
        sys.exit(1)
    subdomains_file = sys.argv[1]
    main(subdomains_file)
