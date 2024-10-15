import requests
from bs4 import BeautifulSoup
import urllib.parse
import csv
import json
import time
import os

# Malicious redirect URL
malicious_url = "http://evil.com"

# Potential redirect parameters
redirect_params = ["redirect", "url", "next", "continue", "return", "redir"]

# Initialize CSV and JSON files
redirect_csv_file = "redirect_results.csv"
redirect_json_file = "redirect_results.json"

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

# Function to extract URLs with potential redirect parameters
def extract_redirect_urls(domain):
    urls = set()
    try:
        response = requests.get(domain, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = urllib.parse.urljoin(domain, link['href'])
                parsed = urllib.parse.urlparse(href)
                for param in redirect_params:
                    if param in urllib.parse.parse_qs(parsed.query):
                        urls.add(href)
    except requests.RequestException as e:
        print(f"Error accessing {domain}: {e}")
    return urls

# Function to test open redirect on a single URL
def test_open_redirect(url):
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)

    for param in redirect_params:
        if param in query_params:
            original_values = query_params[param]
            for original_value in original_values:
                # Inject malicious URL into the redirect parameter
                injected_params = query_params.copy()
                injected_params[param] = malicious_url
                new_query = urllib.parse.urlencode(injected_params, doseq=True)
                injected_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
                try:
                    response = requests.get(injected_url, timeout=10, allow_redirects=False)
                    # Check if the response is a redirection to the malicious URL
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if malicious_url in location:
                            print(f"[!] Open Redirect vulnerability found: {injected_url} -> {location}")
                            log_data = {
                                "url": injected_url,
                                "parameter": param,
                                "redirect_to": location,
                                "response_status": response.status_code,
                                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
                            }
                            log_to_csv([injected_url, param, location, response.status_code, time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())], redirect_csv_file)
                            log_to_json(log_data, redirect_json_file)
                except requests.RequestException as e:
                    print(f"Error testing open redirect on {injected_url}: {e}")
                # Optional: Add delay to avoid rate limiting
                time.sleep(0.5)

# Main function to run open redirect detection
def main():
    # Check if the domain list file exists
    domain_file = "domains.txt"
    domains = read_domains(domain_file)
    if not domains:
        print("No domains to scan. Please add domains to 'domains.txt'.")
        return

    # Initialize CSV with headers
    with open(redirect_csv_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["URL", "Parameter", "Redirect To", "Response Status", "Timestamp"])

    # Iterate over each domain and test for open redirects
    for domain in domains:
        print(f"Scanning for Open Redirects on: {domain}")
        urls = extract_redirect_urls(domain)
        print(f"Found {len(urls)} URLs with potential redirect parameters on {domain}")
        for url in urls:
            test_open_redirect(url)

    print("Open Redirect detection completed. Check 'redirect_results.csv' and 'redirect_results.json' for potential vulnerabilities.")

if __name__ == "__main__":
    main()
