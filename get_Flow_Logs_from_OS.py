import oci
import sys
import gzip
import json
import os
import ipaddress
from datetime import datetime, timedelta
import pandas as pd  # To handle writing to Excel
from concurrent.futures import ThreadPoolExecutor, as_completed

# OCI configuration
config = oci.config.from_file("~/.oci/config")  # Modify if your config file is located elsewhere
object_storage_client = oci.object_storage.ObjectStorageClient(config)
virtual_network_client = oci.core.VirtualNetworkClient(config)

namespace = "ociateam"  # OCI Object Storage namespace
bucket_name = "Flow-Logs"  # Replace with your bucket name

# Time filter (e.g., last 30 days)
time_threshold = datetime.utcnow() - timedelta(days=30)

# Private IP ranges
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16")
]

# List all objects in the bucket and group them by folders
def list_log_files(client, namespace, bucket_name):
    objects = []
    list_objects_response = client.list_objects(namespace, bucket_name)
    for obj in list_objects_response.data.objects:
        if not obj.name.endswith("/"):  # Exclude folders
            objects.append(obj)
    return objects

# Download and extract .log.gz files
def download_and_extract_file(client, namespace, bucket_name, object_name):
    file_stream = client.get_object(namespace, bucket_name, object_name).data.raw
    local_file_name = os.path.join('flowlogs',object_name.split('/')[-1])

    with open(local_file_name, 'wb') as f:
        f.write(file_stream.read())

    # Extract the .log.gz file
    if local_file_name.endswith('.gz'):
        with gzip.open(local_file_name, 'rb') as f_in:
            extracted_file = local_file_name.replace('.gz', '')
            with open(extracted_file, 'wb') as f_out:
                f_out.write(f_in.read())
        os.remove(local_file_name)  # Remove the original .gz file
        return extracted_file
    return local_file_name

# Determine if an IP is internal or external
def is_internal_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net in PRIVATE_IP_RANGES:
            if ip_obj in net:
                return "internal"
        return "external"
    except ValueError:
        return "invalid"

# Get subnet CIDR from the vnicsubnetocid
def get_subnet_cidr(subnet_ocid):
    try:
        subnet_response = virtual_network_client.get_subnet(subnet_ocid)
        return subnet_response.data.cidr_block
    except oci.exceptions.ServiceError as e:
        print(f"Failed to get subnet CIDR: {e}")
        return None

# Check if the IP is part of the subnet CIDR
def is_ip_in_subnet(ip, cidr):
    try:
        ip_obj = ipaddress.ip_address(ip)
        subnet = ipaddress.ip_network(cidr)
        return ip_obj in subnet
    except ValueError:
        return False

# Parse the JSON data and filter based on action 'ACCEPT'
def parse_log_file(file_name):
    result_list = []
    with open(file_name, 'r') as f:
        for line in f:
            try:
                log_entry = json.loads(line)

                # Filter based on ingestedtime (last 30 days)
                ingested_time = log_entry['oracle']['ingestedtime']
                ingested_datetime = datetime.strptime(ingested_time, "%Y-%m-%dT%H:%M:%S.%fZ")
                if ingested_datetime < time_threshold:
                    continue

                # Filter for 'ACCEPT' action only
                if log_entry['data'].get('action') == 'ACCEPT':
                    # Extract variables
                    destination_address = log_entry['data'].get('destinationAddress', 'N/A')
                    destination_port = log_entry['data'].get('destinationPort', 'N/A')
                    protocol = log_entry['data'].get('protocol', 'N/A')
                    protocol_name = log_entry['data'].get('protocolName', 'N/A')
                    source_address = log_entry['data'].get('sourceAddress', 'N/A')
                    vnic_subnet_ocid = log_entry['oracle'].get('vnicsubnetocid', 'N/A')
                    oracle_data = log_entry.get('oracle', {})

                    # Determine if the sourceAddress and destinationAddress are internal or external
                    internal_or_external_source = is_internal_ip(source_address)
                    internal_or_external_destination = is_internal_ip(destination_address)

                    # Check if sourceAddress or destinationAddress matches subnet CIDR
                    traffic_direction = "N/A"
                    traffic_type = "external traffic"
                    if vnic_subnet_ocid != 'N/A':
                        subnet_cidr = get_subnet_cidr(vnic_subnet_ocid)

                        # Determine traffic direction (egress, ingress) based on source or destination match
                        if subnet_cidr:
                            if is_ip_in_subnet(source_address, subnet_cidr):
                                traffic_direction = "egress"
                            elif is_ip_in_subnet(destination_address, subnet_cidr):
                                traffic_direction = "ingress"

                        # Check if both source and destination addresses are internal
                        if internal_or_external_source == "internal" and internal_or_external_destination == "internal":
                            traffic_type = "internal traffic"

                    # Add extracted data to the result list
                    result_list.append({
                        "destinationAddress": destination_address,
                        "destinationPort": destination_port,
                        "protocol": protocol,
                        "protocolName": protocol_name,
                        "sourceAddress": source_address,
                        "internal_or_external_source": internal_or_external_source,
                        "internal_or_external_destination": internal_or_external_destination,
                        "traffic_direction": traffic_direction,
                        "traffic_type": traffic_type,
                        "oracle": oracle_data
                    })
            except json.JSONDecodeError:
                print(f"Skipping invalid JSON: {line}")

    return result_list

# Write the result to JSON and Excel
def write_output_to_files(output_data, log_file_name):
    # Write to JSON file
    json_output_file = f'C:\\Security\\Blogs\\Security_List\\Logs\\{log_file_name}_output.json'
    with open(json_output_file, 'w') as json_file:
        json.dump(output_data, json_file, indent=4)

    # Write to Excel file
    df = pd.DataFrame(output_data)
    excel_output_file = r'C:\\Security\\Blogs\\Security_List\\Logs\\flow_logs_output.xlsx'
    df.to_excel(excel_output_file, index=False)

# Process a single log file
def process_single_log_file(client, namespace, bucket_name, obj_name):
    log_file_name = obj_name.split('/')[-1].replace('.gz', '')  # Extract log file name
    extracted_file = download_and_extract_file(client, namespace, bucket_name, obj_name)
    parsed_data = parse_log_file(extracted_file)
    os.remove(extracted_file)  # Clean up extracted file

    # Write output to files (JSON per log file)
    write_output_to_files(parsed_data, log_file_name)
    return parsed_data

# Main function to process logs with parallelism
def process_flow_logs_in_parallel():
    objects = list_log_files(object_storage_client, namespace, bucket_name)
    extracted_data = []

    # Use ThreadPoolExecutor for parallel processing of files
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {
            executor.submit(process_single_log_file, object_storage_client, namespace, bucket_name, obj.name): obj
            for obj in objects if obj.name.endswith('.log.gz')
        }

        for future in as_completed(futures):
            try:
                data = future.result()
                extracted_data.extend(data)
            except Exception as e:
                print(f"Error processing file: {e}")

    # Write final output to Excel file
    if extracted_data:
        df = pd.DataFrame(extracted_data)
        excel_output_file = r'C:\\Security\\Blogs\\Security_List\\Logs\\flow_logs_final_output.xlsx'
        df.to_excel(excel_output_file, index=False)
        print(f"Final data has been written to {excel_output_file}")

if __name__ == "__main__":
    process_flow_logs_in_parallel()
