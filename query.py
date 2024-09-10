import json
import os
from collections import defaultdict
import pandas as pd

# Define the folder containing your log files
folder_path = r'C:\Security\Blogs\Security_List\Logs\downloads'

# Dictionary to store the results
results = defaultdict(lambda: {'Count': 0, 'Traffic Direction': None, 'Security List OCID': None, 'Oracle Fields': {}})

# Loop through each file in the folder
for filename in os.listdir(folder_path):
    if filename.endswith('.json'):  # Assuming your log files are in JSON format
        file_path = os.path.join(folder_path, filename)

        try:
            # Check if the file is empty before opening
            if os.path.getsize(file_path) == 0:
                print(f"Skipping empty file: {filename}")
                continue

            with open(file_path, 'r') as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    print(f"Skipping malformed JSON file: {filename}")
                    continue

                for record in data:
                    # Filter by protocolName 'TCP'
                    if record.get('protocolName') == 'TCP':
                        # Extract relevant fields
                        source_address = record.get('sourceAddress')
                        destination_address = record.get('destinationAddress')
                        destination_port = record.get('destinationPort')
                        traffic_direction = record.get('traffic_direction')
                        security_list_ocid = record.get('security_list_ocid')

                        # Create a unique key for each occurrence
                        key = (source_address, destination_address, destination_port)

                        # Update the results dictionary
                        results[key]['Count'] += 1
                        results[key]['Traffic Direction'] = traffic_direction
                        results[key]['Security List OCID'] = security_list_ocid

                        # Store all other Oracle-specific fields
                        oracle_fields = {k: v for k, v in record.items() if k not in ['sourceAddress', 'destinationAddress', 'destinationPort', 'traffic_direction', 'security_list_ocid']}
                        results[key]['Oracle Fields'] = oracle_fields

        except OSError as e:
            print(f"Error reading file {filename}: {e}")

# Convert the results to a list of dictionaries for DataFrame
output_data = []
for k, v in results.items():
    # Flatten the Oracle fields for better readability in Excel
    oracle_fields_flattened = {f"Oracle {key}": value for key, value in v['Oracle Fields'].items()}

    # Prepare the row data including source, destination, port, and additional fields
    row_data = {
        'Source Address': k[0],
        'Destination Address': k[1],
        'Destination Port': k[2],
        'Count': v['Count'],
        'Traffic Direction': v['Traffic Direction'],
        'Security List OCID': v['Security List OCID']
    }

    # Combine row data with flattened Oracle fields
    row_data.update(oracle_fields_flattened)
    output_data.append(row_data)

# Create a DataFrame from the list of dictionaries
df = pd.DataFrame(output_data)

# Write the DataFrame to an Excel file
output_file = r'C:\Security\Blogs\Security_List\Logs\downloads\response_data.xlsx'
df.to_excel(output_file, index=False)

print(f"Results written to {output_file}")
