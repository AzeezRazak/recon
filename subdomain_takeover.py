import requests
import urllib.parse
import csv
import json
import time
import os

# Initialize CSV and JSON files
takeover_csv_file = "takeover_results.csv"
takeover_json_file = "takeover_results.json"

def log_to_csv(data, file):
    with open(file, mode='a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(data)

def log_to_json(data, file):
    with open(file, mode='a', encoding='utf-8') as f:
        json.dump(data, f)
        f.write('\n')

# Function to read subdomains from a text file
def read_subdomains(file_path):
    if not os.path.exists(file_path):
        print(f"Subdomain file {file_path} does not exist.")
        return []
    with open(file_path, 'r') as file:
        subdomains = [line.strip() for line in file if line.strip()]
    return subdomains

# Function to check subdomain takeover
def check_takeover(subdomain):
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; SubdomainTakeoverChecker/1.0)"
    }
    try:
        response = requests.get(subdomain, headers=headers, timeout=10, allow_redirects=True)
        # Common patterns indicating potential takeover
        takeover_patterns = [
            r"no such app|No such app|app not found",
            r"dashboard.heroku.com",
            r"amazonaws.com",
            r"azurewebsites.net",
            r"appspot.com",
            r"Heroku",
            r"AWS S3",
            r"Microsoft Azure",
            r"Google App Engine",
            r"service unavailable",
            r"Invalid bucket name",
            r"error creating app",
            r"Error creating resource",
            r"account does not exist",
            r"no bucket here",
            r"not found",
            r"Unable to resolve",
            r"Unrecognized request",
            r"Region does not exist",
            r"Certificate for this site has expired",
        ]

        content = response.text.lower()
        for pattern in takeover_patterns:
            if re.search(pattern.lower(), content):
                print(f"[!] Potential Subdomain Takeover: {subdomain}")
                log_data = {
                    "subdomain": subdomain,
                    "response_status": response.status_code,
                    "response_url": response.url,
                    "pattern_matched": pattern,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
                }
                log_to_csv([subdomain, response.status_code, response.url, pattern, time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())], takeover_csv_file)
                log_to_json(log_data, takeover_json_file)
                return
    except requests.RequestException as e:
        print(f"Error accessing {subdomain}: {e}")
    # Optional: Add delay to avoid rate limiting
    time.sleep(0.5)

# Main function to run subdomain takeover detection
def main():
    # Check if the subdomain list file exists
    subdomain_file = "subdomains.txt"
    subdomains = read_subdomains(subdomain_file)
    if not subdomains:
        print("No subdomains to scan. Please add subdomains to 'subdomains.txt'.")
        return

    # Initialize CSV with headers
    with open(takeover_csv_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Subdomain", "Response Status", "Response URL", "Pattern Matched", "Timestamp"])

    # Iterate over each subdomain and check for takeover
    for subdomain in subdomains:
        print(f"Checking subdomain: {subdomain}")
        check_takeover(subdomain)

    print("Subdomain takeover detection completed. Check 'takeover_results.csv' and 'takeover_results.json' for potential takeovers.")

if __name__ == "__main__":
    main()
