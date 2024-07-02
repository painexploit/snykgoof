import json
import boto3
import sys
import uuid
import os

def parse_sarif(file_path):
    with open(file_path, 'r') as f:
        sarif_data = json.load(f)
    
    counts = {
        'Critical': 0,
        'High': 0,
        'Medium': 0,
        'Low': 0
    }

    # SARIF structure might vary, adjust the parsing as per the actual SARIF structure
    for run in sarif_data.get('runs', []):
        for result in run.get('results', []):
            severity = result.get('level')
            if severity == 'error':
                counts['Critical'] += 1
            elif severity == 'warning':
                counts['High'] += 1
            elif severity == 'note':
                counts['Medium'] += 1
            else:
                counts['Low'] += 1
    
    return counts

def upload_to_dynamodb(file_path, table_name):
    counts = parse_sarif(file_path)

    # Initialize DynamoDB client
    dynamodb = boto3.resource('dynamodb', region_name=region_name)
    table = dynamodb.Table(table_name)

    # Upload the counts
    response = table.put_item(
        Item={
            'id': str(uuid.uuid4()),
            'critical': ['Critical'],
            'high': ['High'],
            'medium': ['Medium'],
            'low': ['Low']
        }
    )
    return response

if __name__ == '__main__':
    file_path = sys.argv[1]
    table_name = os.getenv('DYNAMODB_TABLE_NAME')
    region_name = os.getenv('AWS_REGION')
    upload_to_dynamodb(file_path, table_name)
