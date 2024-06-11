#!/bin/bash

echo "Starting SARIF processing script..."

# Define the SARIF file
sarif_file=".github/workflows/snyk.sarif"
echo "SARIF file: $sarif_file"

# Generate the timestamp for the filename
timestamp=$(date +"%Y%m%d_%H%M%S")
output_json=".github/data/vulnerability_report_${timestamp}.json"
echo "Output JSON: $output_json"

# Check if .github/data folder exists, if not create it
if [ ! -d ".github/data" ]; then
  mkdir -p .github/data
  echo "Created directory .github/data"
else
  echo "Directory .github/data already exists"
fi

# Find the latest file in the .github/data directory
latest_file=$(ls -t .github/data/vulnerability_report_*.json 2>/dev/null | head -n 1)
echo "Latest file to be used for age calculation: $latest_file"

# Retrieve the descriptions and levels dynamically and store them in arrays
descriptions=()
levels=()
while IFS= read -r line; do
  descriptions+=("$line")
done < <(jq -r '.runs[].tool.driver.rules[].shortDescription.text' "$sarif_file")
echo "Descriptions retrieved: ${#descriptions[@]}"

while IFS= read -r line; do
  levels+=("$line")
done < <(jq -r '.runs[].tool.driver.rules[].defaultConfiguration.level' "$sarif_file")
echo "Levels retrieved: ${#levels[@]}"

# Define the severity mapping
declare -A severity_mapping
severity_mapping=( ["error"]="High" ["warning"]="Medium" ["note"]="Low" )

# Function to calculate age of a vulnerability based on previous files in .github/data
calculate_age_and_timestamp() {
  local description="$1"
  local uri="$2"
  local start_line="$3"
  local earliest_timestamp=""
  local age=0

  if [[ -z "$latest_file" ]]; then
    echo "0" "new"
    return
  fi

  vulnerabilities=$(jq -c '.[]' "$latest_file")
  while IFS= read -r vulnerability; do
    vuln_desc=$(echo "$vulnerability" | jq -r '.shortDescription')
    vuln_uri=$(echo "$vulnerability" | jq -r '.artifactLocationUri')
    vuln_line=$(echo "$vulnerability" | jq -r '.startLine')
    vuln_timestamp=$(echo "$vulnerability" | jq -r '.timestamp')
    if [[ "$description" == "$vuln_desc" && "$uri" == "$vuln_uri" && "$start_line" == "$vuln_line" ]]; then
      if [[ -z "$earliest_timestamp" || "$vuln_timestamp" < "$earliest_timestamp" ]]; then
        earliest_timestamp="$vuln_timestamp"
      fi
    fi
  done <<< "$vulnerabilities"

  if [[ -n "$earliest_timestamp" ]]; then
    start_date=$(date -d "${earliest_timestamp:0:8}" +%s)
    current_date=$(date +%s)
    age=$(( (current_date - start_date) / 86400 ))
    echo "$age" "$earliest_timestamp"
  else
    echo "0" "new"
  fi
}

# Initialize a temporary file to hold JSON objects
temp_json="temp.json"
echo "[]" > "$temp_json"
echo "Initialized temporary JSON file: $temp_json"

# Extract the required fields and store in the JSON array
for index in "${!descriptions[@]}"; do
  severity="${severity_mapping[${levels[$index]}]}"
  
  vulnerabilities=$(jq --arg index "$index" --arg desc "${descriptions[$index]}" --arg severity "$severity" --arg timestamp "$timestamp" -r \
    '.runs[].results[] | select(.ruleIndex == ($index|tonumber)) | {index: $index|tonumber, shortDescription: $desc, artifactLocationUri: .locations[].physicalLocation.artifactLocation.uri, startLine: .locations[].physicalLocation.region.startLine, severity: $severity, timestamp: $timestamp}' \
    "$sarif_file")

  echo "$vulnerabilities" | jq -c '.' | while IFS= read -r vulnerability; do
    description=$(echo "$vulnerability" | jq -r '.shortDescription')
    uri=$(echo "$vulnerability" | jq -r '.artifactLocationUri')
    start_line=$(echo "$vulnerability" | jq -r '.startLine')
    read -r age original_timestamp <<< $(calculate_age_and_timestamp "$description" "$uri" "$start_line")
    
    if [[ "$original_timestamp" != "new" ]]; then
      timestamp="$original_timestamp"
    fi
    
    updated_vulnerability=$(echo "$vulnerability" | jq --argjson age "$age" --arg timestamp "$timestamp" '. + {age: $age, timestamp: $timestamp}')
    jq ". += [$updated_vulnerability]" "$temp_json" > temp.json.tmp && mv temp.json.tmp "$temp_json"
  done
done

# Move the temporary JSON to the output file in .github/data
mv "$temp_json" "$output_json"
echo "Moved temporary JSON to $output_json"

# Create the summary report
high_count=$(jq '[.[] | select(.severity == "High")] | length' "$output_json")
medium_count=$(jq '[.[] | select(.severity == "Medium")] | length' "$output_json")
low_count=$(jq '[.[] | select(.severity == "Low")] | length' "$output_json")

summary="Total Vulnerabilities: $((high_count + medium_count + low_count))\n"
summary+="High: $high_count\n"
summary+=$(jq -r '.[] | select(.severity == "High") | "\(.shortDescription), Path: \(.artifactLocationUri), Line: \(.startLine), Age: \(.age) days"' "$output_json")
summary+="\nMedium: $medium_count\n"
summary+=$(jq -r '.[] | select(.severity == "Medium") | "\(.shortDescription), Path: \(.artifactLocationUri), Line: \(.startLine), Age: \(.age) days"' "$output_json")
summary+="\nLow: $low_count\n"
summary+=$(jq -r '.[] | select(.severity == "Low") | "\(.shortDescription), Path: \(.artifactLocationUri), Line: \(.startLine), Age: \(.age) days"' "$output_json")

echo -e "$summary"

# Send the summary to Slack
slack_webhook_url="${SLACK_WEBHOOK_URL}"

payload=$(jq -n --arg text "$summary" '{text: $text}')
curl -X POST -H 'Content-type: application/json' --data "$payload" "$slack_webhook_url"

echo "Sent summary to Slack"

# Print the name of the latest file checked
echo "Latest file checked for age calculation: $latest_file"
