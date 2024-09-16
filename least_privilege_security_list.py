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
                    internal_or_external_source = item['internal_or_external_source']
                    source_address = item['sourceAddress']
                    destination_address = item.get('destinationAddress')  # New field

                    # Check if protocolName is TCP or UDP
                    if protocol_name in ['TCP', 'UDP']:
                        # Add the data to the dictionary
                        if vnicsubnetocid not in data_dict:
                            data_dict[vnicsubnetocid] = {
                                'TCP_Internal': {'ports': set(), 'port_counts': {}, 'records': {}},
                                'TCP_External': {'ports': set(), 'port_counts': {}, 'records': {}},
                                'UDP_Internal': {'ports': set(), 'port_counts': {}, 'records': {}},
                                'UDP_External': {'ports': set(), 'port_counts': {}, 'records': {}}
                            }
                        
                        # Create a unique key to count occurrences (source_address, destination_address, destination_port)
                        key = (source_address, destination_address, destination_port)

                        # Count per port
                        if internal_or_external_source == 'internal':
                            protocol_key = f'{protocol_name}_Internal'
                        else:
                            protocol_key = f'{protocol_name}_External'
                        
                        data_dict[vnicsubnetocid][protocol_key]['ports'].add(destination_port)
                        data_dict[vnicsubnetocid][protocol_key]['port_counts'][destination_port] = \
                            data_dict[vnicsubnetocid][protocol_key]['port_counts'].get(destination_port, 0) + 1

                        # Count for (source, destination, port) combination
                        data_dict[vnicsubnetocid][protocol_key]['records'][key] = \
                            data_dict[vnicsubnetocid][protocol_key]['records'].get(key, 0) + 1
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON file {obj.name}: {e}")
            continue

# Create a new JSON file for each VNIC subnet OCID
for vnicsubnetocid, data in data_dict.items():
    output_data = {
        "vnicsubnetocid": vnicsubnetocid,  # Add vnicsubnetocid at the top
        "protocols": {}
    }
    
    for protocol in ['TCP_Internal', 'TCP_External', 'UDP_Internal', 'UDP_External']:
        ports = sorted(data[protocol]['ports'])
        ranges = []
        
        # Generate port ranges
        for k, g in itertools.groupby(enumerate(ports), key=lambda x: x[0] - x[1]):
            group = list(map(lambda x: x[1], g))
            if len(group) > 1:
                ranges.append(f"{group[0]}-{group[-1]}")
            else:
                ranges.append(str(group[0]))
        
        # Sort port_counts based on count value in descending order
        port_counts = sorted(
            [{"port": port, "count": count} for port, count in data[protocol]['port_counts'].items()],
            key=lambda x: x['count'], 
            reverse=True
        )

        # Add port ranges and sorted port_counts to the output
        output_data['protocols'][protocol] = {
            'port_ranges': ','.join(ranges),
            'port_counts': port_counts,
            'detailed_records': []  # For the detailed section
        }
        
        # Process each record for this protocol (source_address, destination_address, destination_port, count)
        for (source_address, destination_address, destination_port), count in data[protocol]['records'].items():
            output_data['protocols'][protocol]['detailed_records'].append({
                'source_address': source_address,
                'destination_address': destination_address,
                'destination_port': destination_port,
                'count': count
            })
    
    # Write the output dictionary to a JSON file in Object Storage
    filename = f"{vnicsubnetocid}.json"
    object_storage_client.put_object(namespace, "final_results", filename, json.dumps(output_data).encode('utf-8'))
