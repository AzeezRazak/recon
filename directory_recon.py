import requests
import urllib.parse
import csv
import json
import time
import os

# Directory wordlist
wordlist = [
    "admin",
    "login",
    "dashboard",
    "test",
    "dev",
    "backup",
    "uploads",
    "images",
    "css",
    "js",
    "config",
    "api",
    "private",
    "scripts",
    "includes"
]

# Initialize CSV and JSON files
dir_csv_file = "dir_results.csv"
dir_json_file = "dir_results.json"

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

# Function to enumerate directories on a single domain
def enumerate_directories(domain, wordlist):
    print(f"Enumerating directories for {domain}...")
    found_dirs = []
    for directory in wordlist:
        dir_url = urllib.parse.urljoin(domain, directory + "/")
        try:
            response = requests.get(dir_url, timeout=5)
            if response.status_code == 200:
                print(f"[+] Found directory: {dir_url}")
                found_dirs.append((dir_url, response.status_code))
                log_data = {
                    "url": dir_url,
                    "response_status": response.status_code,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
                }
                log_to_csv([dir_url, response.status_code, time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())], dir_csv_file)
                log_to_json(log_data, dir_json_file)
            elif response.status_code == 403:
                print(f"[!] Forbidden directory: {dir_url}")
                # Optionally log forbidden directories
        except requests.RequestException as e:
            print(f"Error accessing {dir_url}: {e}")
        # Optional: Add delay to avoid rate limiting
        time.sleep(0.5)
    return found_dirs

# Main function to run directory enumeration
def main():
    # Check if the domain list file exists
    domain_file = "domains.txt"
    domains = read_domains(domain_file)
    if not domains:
        print("No domains to scan. Please add domains to 'domains.txt'.")
        return

    # Initialize CSV with headers
    with open(dir_csv_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["URL", "Response Status", "Timestamp"])

    # Iterate over each domain
    for domain in domains:
        enumerate_directories(domain, wordlist)

    print("Directory enumeration completed. Check 'dir_results.csv' and 'dir_results.json' for found directories.")

if __name__ == "__main__":
    main()
