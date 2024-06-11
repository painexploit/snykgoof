import json
import os
from datetime import datetime

# Function to load JSON data from a file
def load_json(filename):
    with open(filename, 'r') as file:
        return json.load(file)

# Function to save JSON data to a file
def save_json(data, filename):
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)

# Function to calculate the age of a bug
def calculate_bug_age(current_report, previous_report):
    previous_bugs = {(bug['ruleName'], bug['path'], bug['line']): bug for bug in previous_report}
    
    for bug in current_report:
        bug_id = (bug['ruleName'], bug['path'], bug['line'])
        if bug_id in previous_bugs:
            previous_timestamp = datetime.strptime(previous_bugs[bug_id]['timestamp'], '%Y-%m-%d %H:%M:%S')
            current_timestamp = datetime.strptime(bug['timestamp'], '%Y-%m-%d %H:%M:%S')
            age_days = (current_timestamp - previous_timestamp).days
            bug['age'] = previous_bugs[bug_id].get('age', 0) + age_days
            previous_bugs[bug_id] = bug  # Update the bug with the new timestamp and age
        else:
            bug['age'] = 0  # New bug
            previous_bugs[bug_id] = bug

    return list(previous_bugs.values())

# Check if .github/data directory exists, if not, create it
data_dir = '.github/data'
if not os.path.exists(data_dir):
    os.makedirs(data_dir)

# Load the SARIF file
with open('snyk.sarif', 'r') as file:
    sarif_data = json.load(file)

# Extract runs, results, and rules
runs_data = sarif_data['runs']
rules = runs_data[0]['tool']['driver']['rules']
results = runs_data[0]['results']

# Initialize counters and storage for vulnerabilities
total_vulnerabilities = 0
high_vulnerabilities = []
medium_vulnerabilities = []
low_vulnerabilities = []

# Severity mapping
severity_mapping = {
    "error": "High",
    "warning": "Medium",
    "note": "Low"
}

# Current timestamp
current_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# Find matches between rule ids and result rule ids
for rule in rules:
    rule_id = rule['id']
    rule_severity = severity_mapping.get(rule.get('defaultConfiguration', {}).get('level'), "Unknown")
    rule_description = rule['shortDescription']['text']
    
    for result in results:
        if result['ruleId'] == rule_id:
            result_severity = severity_mapping.get(result['level'], "Unknown")
            for location in result['locations']:
                vulnerability = {
                    'ruleName': rule_description,
                    'path': location['physicalLocation']['artifactLocation']['uri'],
                    'line': location['physicalLocation']['region']['startLine'],
                    'severity': result_severity,
                    'timestamp': current_timestamp
                }
                if result_severity == "High":
                    high_vulnerabilities.append(vulnerability)
                elif result_severity == "Medium":
                    medium_vulnerabilities.append(vulnerability)
                elif result_severity == "Low":
                    low_vulnerabilities.append(vulnerability)
                total_vulnerabilities += 1

# Determine the report file path
report_json_filename = os.path.join(data_dir, 'vulnerability_report.json')

# Load the previous report for comparison
if os.path.exists(report_json_filename):
    previous_report = load_json(report_json_filename)
else:
    previous_report = {'high': [], 'medium': [], 'low': []}

# Calculate the age of vulnerabilities and update the report
high_vulnerabilities = calculate_bug_age(high_vulnerabilities, previous_report.get('high', []))
medium_vulnerabilities = calculate_bug_age(medium_vulnerabilities, previous_report.get('medium', []))
low_vulnerabilities = calculate_bug_age(low_vulnerabilities, previous_report.get('low', []))

# Save the current report for future comparison
current_report = {
    'timestamp': current_timestamp,
    'high': high_vulnerabilities,
    'medium': medium_vulnerabilities,
    'low': low_vulnerabilities
}
save_json(current_report, report_json_filename)

# Generate report
report = []
report.append(f"Total Vulnerabilities: {total_vulnerabilities}")
report.append(f"High: {len(high_vulnerabilities)}")
for vuln in high_vulnerabilities:
    report.append(f"{vuln['ruleName']}, Path: {vuln['path']}, Line: {vuln['line']}, Age: {vuln['age']} days")

report.append(f"Medium: {len(medium_vulnerabilities)}")
for vuln in medium_vulnerabilities:
    report.append(f"{vuln['ruleName']}, Path: {vuln['path']}, Line: {vuln['line']}, Age: {vuln['age']} days")

report.append(f"Low: {len(low_vulnerabilities)}")
for vuln in low_vulnerabilities:
    report.append(f"{vuln['ruleName']}, Path: {vuln['path']}, Line: {vuln['line']}, Age: {vuln['age']} days")

# Save report to a text file with timestamp
report_filename = os.path.join(data_dir, 'vulnerability_report.txt')
with open(report_filename, 'w') as output_file:
    output_file.write("\n".join(report))

print(f"Report generation completed. Results saved in '{report_filename}'.")
