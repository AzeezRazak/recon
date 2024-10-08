import json
import csv

# Function to load JSON data
def load_json(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

# Function to remove sensitive data (e.g., IP addresses, internal paths)
def remove_sensitive_data(data):
    # Remove or mask any fields you consider sensitive
    for entry in data:
        if "subdomain" in entry:
            entry["subdomain"] = "REDACTED"  # Example: Mask subdomain
        # Add more sensitive fields to redact as needed
    return data

# Function to remove duplicates from JSON
def remove_duplicates(data):
    seen = set()
    unique_data = []
    for entry in data:
        entry_tuple = tuple(entry.items())  # Convert dict to tuple for comparison
        if entry_tuple not in seen:
            seen.add(entry_tuple)
            unique_data.append(entry)
    return unique_data

# Function to categorize vulnerabilities by severity
def categorize_by_severity(data):
    categorized_data = {"critical": [], "high": [], "medium": [], "low": []}
    
    for entry in data:
        severity = entry.get('severity', 'low')  # Assume 'low' if not provided
        if severity == "critical":
            categorized_data["critical"].append(entry)
        elif severity == "high":
            categorized_data["high"].append(entry)
        elif severity == "medium":
            categorized_data["medium"].append(entry)
        else:
            categorized_data["low"].append(entry)
    return categorized_data

# Function to save cleaned data to JSON
def save_to_json(data, filename):
    with open(filename, 'w') as json_file:
        json.dump(data, json_file, indent=4)
    print(f"Cleaned data saved to {filename}")

# Function to clean CSV results (anonymizing and deduplication)
def clean_csv(input_file, output_file):
    seen = set()
    with open(input_file, 'r') as csv_in, open(output_file, 'w', newline='') as csv_out:
        reader = csv.DictReader(csv_in)
        fieldnames = reader.fieldnames
        
        writer = csv.DictWriter(csv_out, fieldnames=fieldnames)
        writer.writeheader()
        
        for row in reader:
            # Example anonymization
            row["subdomain"] = "REDACTED" if "subdomain" in row else row["subdomain"]
            
            # Deduplication check
            row_tuple = tuple(row.items())
            if row_tuple not in seen:
                seen.add(row_tuple)
                writer.writerow(row)
    print(f"Cleaned CSV saved to {output_file}")

# Main function to clean both JSON and CSV files
def main():
    # Clean JSON data
    json_data = load_json('vulnerability_results.json')
    json_data = remove_sensitive_data(json_data)
    json_data = remove_duplicates(json_data)
    categorized_data = categorize_by_severity(json_data)
    save_to_json(categorized_data, 'cleaned_vulnerability_results.json')

    # Clean CSV data
    clean_csv('vulnerability_results.csv', 'cleaned_vulnerability_results.csv')

if __name__ == "__main__":
    main()
