import json
import os
import itertools

# Set the directory path where the JSON files are located
directory_path = r'C:\Security\Blogs\Security_List\Logs\parsed_data'

# Create a dictionary to store the extracted data
data_dict = {}

# Loop through all the JSON files in the directory
for filename in os.listdir(directory_path):
    if filename.endswith('.json'):
        # Open the JSON file and load the data
        try:
            with open(os.path.join(directory_path, filename)) as f:
                data = json.load(f)
        
            # Loop through each item in the data
            for item in data:
                # Get the VNIC subnet OCID
                vnicsubnetocid = item['oracle']['vnicsubnetocid']
                
                # Get the protocolName and destinationPort
                protocol_name = item['protocolName']
                destination_port = item['destinationPort']
                
                # Check if protocolName is TCP or UDP
                if protocol_name in ['TCP', 'UDP']:
                    # Add the data to the dictionary
                    if vnicsubnetocid not in data_dict:
                        data_dict[vnicsubnetocid] = {'protocolNames': set(), 'destinationPorts': {}}
                    
                    # Add protocolName to the set (no duplicates)
                    data_dict[vnicsubnetocid]['protocolNames'].add(protocol_name)
                    
                    # Add destinationPort to the dictionary (no duplicates)
                    if protocol_name not in data_dict[vnicsubnetocid]['destinationPorts']:
                        data_dict[vnicsubnetocid]['destinationPorts'][protocol_name] = set()
                    data_dict[vnicsubnetocid]['destinationPorts'][protocol_name].add(destination_port)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON file {filename}: {e}")
            continue
# Create a new JSON file for each VNIC subnet OCID
for vnicsubnetocid, data in data_dict.items():
    # Convert sets to lists and create a comma-separated string for destinationPorts
    protocol_names = list(data['protocolNames'])
    destination_ports = {}
    for protocol_name, ports in data['destinationPorts'].items():
        ports = sorted(ports)
        ranges = []
        for k, g in itertools.groupby(enumerate(ports), key=lambda x: x[0] - x[1]):
            group = list(map(lambda x: x[1], g))
            if len(group) > 1:
                ranges.append(f"{group[0]}-{group[-1]}")
            else:
                ranges.append(str(group[0]))
        destination_ports[protocol_name] = ','.join(ranges)
    
    # Create the output dictionary
    output_data = {
        'protocolNames': protocol_names,
        'destinationPorts': destination_ports
    }
    
    # Write the output dictionary to a JSON file
    filename = rf'C:\Security\Blogs\Security_List\Logs\final_results\{vnicsubnetocid}.json'
    with open(filename, 'w') as f:
        json.dump(output_data, f, indent=4)