import json
import webbrowser

# Define vulnerability keywords for critical types
critical_keywords = {
    "SQL Injection": "https://www.owasp.org/index.php/SQL_Injection",
    "XSS": "https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)",
    "RCE": "https://www.owasp.org/index.php/Remote_Code_Execution",
    "CSRF": "https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)",
    "Open Ports": "https://nmap.org/book/man-port-scanning-basics.html",
    "Sensitive Data Exposure": "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
    "Unauthorized Access": "https://owasp.org/www-community/attacks/Authorization_Bypass"
}

# Load vulnerability results (assumes JSON format)
def load_results(filename):
    with open(filename, "r") as file:
        return json.load(file)

# Filter and add manual action steps
def process_results(results):
    detailed_results = []
    for res in results:
        for vuln, link in critical_keywords.items():
            if vuln.lower() in res.lower():
                detailed_results.append({
                    "vulnerability": vuln,
                    "details": res,
                    "action": f"Research more: {link}"
                })
    return detailed_results

# Save enhanced output to a new file
def save_results(detailed_results, output_file):
    with open(output_file, "w") as file:
        json.dump(detailed_results, file, indent=4)

# Open the link in the browser for further research
def open_links(detailed_results):
    for result in detailed_results:
        print(f"Found {result['vulnerability']}. Opening research link...")
        webbrowser.open(result["action"].split()[-1])

# Main function
def main():
    input_file = "clean_results.json"  # replace with your clean.py results file
    output_file = "enhanced_results.json"

    results = load_results(input_file)
    detailed_results = process_results(results)

    save_results(detailed_results, output_file)
    open_links(detailed_results)  # Opens relevant research links automatically

    print(f"Enhanced results saved to {output_file}")

if __name__ == "__main__":
    main()
