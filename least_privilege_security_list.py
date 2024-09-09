import json
import oci
import itertools

# OCI configuration
config = oci.config.from_file("~/.oci/config")  # Modify if your config file is located elsewhere
object_storage_client = oci.object_storage.ObjectStorageClient(config)
namespace = "ociateam"  # OCI Object Storage namespace
bucket_name = "parsed-flow-log-data"  # Bucket name containing JSON files

# Create a dictionary to store the extracted data
data_dict = {}

# List all objects in the bucket
objects = object_storage_client.list_objects(namespace, bucket_name).data.objects

# Loop through all the JSON files in the bucket
for obj in objects:
    if obj.name.endswith('.json'):
        # Get the JSON file from Object Storage
        try:
            file_stream = object_storage_client.get_object(namespace, bucket_name, obj.name).data.raw
            data = json.load(file_stream)
        
            # Loop through each item in the data
            for item in data:
                # Filter data based on traffic direction
                if item.get('traffic_direction') == 'ingress':
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
            print(f"Error decoding JSON file {obj.name}: {e}")
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
    
    # Write the output dictionary to a JSON file in Object Storage
    filename = f"{vnicsubnetocid}.json"
    object_storage_client.put_object(namespace, "final_results", filename, json.dumps(output_data).encode('utf-8'))