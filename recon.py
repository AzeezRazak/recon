import os
import json
import csv
import subprocess

# Load subdomains from a file or a list
def load_subdomains(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

# Nuclei scan function
def nuclei_scan(subdomain):
    print(f"[*] Running Nuclei on {subdomain}")
    output_file = f"{subdomain}_nuclei.txt"
    try:
        subprocess.run(['nuclei', '-u', subdomain, '-o', output_file], check=True)
        with open(output_file, 'r') as file:
            return {"nuclei_vulnerabilities": file.read()}
    except subprocess.CalledProcessError as e:
        return {"error": f"Nuclei scan failed: {str(e)}"}

# Nikto scan function
def nikto_scan(subdomain):
    print(f"[*] Running Nikto on {subdomain}")
    output_file = f"{subdomain}_nikto.txt"
    try:
        subprocess.run(['nikto', '-host', subdomain, '-output', output_file], check=True)
        with open(output_file, 'r') as file:
            return {"nikto_results": file.read()}
    except subprocess.CalledProcessError as e:
        return {"error": f"Nikto scan failed: {str(e)}"}

# Dirsearch scan function
def dirsearch_scan(subdomain):
    print(f"[*] Running Dirsearch on {subdomain}")
    output_file = f"{subdomain}_dirsearch.json"
    try:
        subprocess.run(['dirsearch', '-u', f"http://{subdomain}", '--json-report', output_file], check=True)
        with open(output_file, 'r') as file:
            return json.load(file)
    except subprocess.CalledProcessError as e:
        return {"error": f"Dirsearch scan failed: {str(e)}"}

# Nmap scan function
def nmap_scan(subdomain):
    print(f"[*] Running Nmap on {subdomain}")
    output_file = f"{subdomain}_nmap.txt"
    try:
        subprocess.run(['nmap', '-sV', subdomain, '-oN', output_file], check=True)
        with open(output_file, 'r') as file:
            return {"nmap_results": file.read()}
    except subprocess.CalledProcessError as e:
        return {"error": f"Nmap scan failed: {str(e)}"}

# OWASP ZAP scan function
def zap_scan(subdomain):
    print(f"[*] Running OWASP ZAP on {subdomain}")
    try:
        subprocess.run(['zap-cli', 'quick-scan', '--self-contained', '--spider', '--scan', subdomain], check=True)
        return {"zap_results": "Scan completed (OWASP ZAP)"}
    except subprocess.CalledProcessError as e:
        return {"error": f"OWASP ZAP scan failed: {str(e)}"}

# Function to run all scans on a single subdomain
def run_scans(subdomain):
    results = {"subdomain": subdomain}
    
    # Run each scan in sequence and store results
    results.update(nuclei_scan(subdomain))
    results.update(nikto_scan(subdomain))
    results.update(dirsearch_scan(subdomain))
    results.update(nmap_scan(subdomain))
    results.update(zap_scan(subdomain))
    
    return results

# Save results to a JSON file
def save_to_json(data, filename='vulnerability_results.json'):
    with open(filename, 'w') as json_file:
        json.dump(data, json_file, indent=4)
    print(f"Results saved to {filename}")

# Save results to a CSV file
def save_to_csv(data, filename='vulnerability_results.csv'):
    with open(filename, 'w', newline='') as csv_file:
        fieldnames = ['subdomain', 'nuclei_vulnerabilities', 'nikto_results', 'dirsearch_results', 'nmap_results', 'zap_results', 'errors']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for entry in data:
            writer.writerow(entry)
    print(f"Results saved to {filename}")

# Main function
def main(subdomains_file):
    subdomains = load_subdomains(subdomains_file)
    
    all_results = []
    for subdomain in subdomains:
        result = run_scans(subdomain)
        all_results.append(result)
    
    # Save results to both JSON and CSV formats
    save_to_json(all_results)
    save_to_csv(all_results)

if __name__ == "__main__":
    # Provide the path to the subdomains file
    subdomains_file = 'subdomains.txt'
    main(subdomains_file)
