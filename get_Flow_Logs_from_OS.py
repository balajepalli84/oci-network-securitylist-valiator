import oci
import sys
import gzip
import json
import os
import ipaddress
import threading
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import tempfile
import shutil

# OCI configuration
config = oci.config.from_file("~/.oci/config")  # Modify if your config file is located elsewhere
object_storage_client = oci.object_storage.ObjectStorageClient(config)
virtual_network_client = oci.core.VirtualNetworkClient(config)
subnet_cache = {}
security_list_cache = {}
namespace = "ociateam"  # OCI Object Storage namespace
bucket_name = "Flow-Logs"  # Replace with your bucket name
parsed_data_bucket_name = "parsed-flow-log-data"
# Time filter (e.g., last 30 days)
time_threshold = datetime.utcnow() - timedelta(days=30)

# Private IP ranges
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16")
]

# Lock for thread-safe operations
lock = threading.Lock()

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
    local_file_name = os.path.join(r'C:\Security\Blogs\Security_List\Logs\downloads', object_name.split('/')[-1])

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

def get_subnet_cidr(subnet_ocid):
    if subnet_ocid in subnet_cache:
        return subnet_cache[subnet_ocid]
    try:
        subnet_response = virtual_network_client.get_subnet(subnet_ocid)
        subnet_cidr = subnet_response.data.cidr_block
        subnet_security_list = subnet_response.data.security_list_ids
        subnet_cache[subnet_ocid] = (subnet_cidr, subnet_security_list)
        return subnet_cidr, subnet_security_list
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

def extract_ingress_rule_attributes(rule):
    return {
        "description": rule.description,
        "icmp_options": rule.icmp_options,
        "is_stateless": rule.is_stateless,
        "protocol": rule.protocol,
        "source": rule.source,
        "source_type": rule.source_type,
        "tcp_options": {
            "destination_port_range": {
                "max": rule.tcp_options.destination_port_range.max if rule.tcp_options and rule.tcp_options.destination_port_range else None,
                "min": rule.tcp_options.destination_port_range.min if rule.tcp_options and rule.tcp_options.destination_port_range else None
            },
            "source_port_range": {
                "max": rule.tcp_options.source_port_range.max if rule.tcp_options and rule.tcp_options.source_port_range else None,
                "min": rule.tcp_options.source_port_range.min if rule.tcp_options and rule.tcp_options.source_port_range else None
            }
        } if rule.tcp_options else None,
        "udp_options": {
            "destination_port_range": {
                "max": rule.udp_options.destination_port_range.max if rule.udp_options and rule.udp_options.destination_port_range else None,
                "min": rule.udp_options.destination_port_range.min if rule.udp_options and rule.udp_options.destination_port_range else None
            },
            "source_port_range": {
                "max": rule.udp_options.source_port_range.max if rule.udp_options and rule.udp_options.source_port_range else None,
                "min": rule.udp_options.source_port_range.min if rule.udp_options and rule.udp_options.source_port_range else None
            }
        } if rule.udp_options else None
    }

def extract_egress_rule_attributes(rule):
    return {
        "description": rule.description,
        "icmp_options": rule.icmp_options,
        "is_stateless": rule.is_stateless,
        "protocol": rule.protocol,
        "destination": rule.destination,
        "destination_type": rule.destination_type,
        "tcp_options": {
            "destination_port_range": {
                "max": rule.tcp_options.destination_port_range.max if rule.tcp_options and rule.tcp_options.destination_port_range else None,
                "min": rule.tcp_options.destination_port_range.min if rule.tcp_options and rule.tcp_options.destination_port_range else None
            },
            "source_port_range": {
                "max": rule.tcp_options.source_port_range.max if rule.tcp_options and rule.tcp_options.source_port_range else None,
                "min": rule.tcp_options.source_port_range.min if rule.tcp_options and rule.tcp_options.source_port_range else None
            }
        } if rule.tcp_options else None,
        "udp_options": {
            "destination_port_range": {
                "max": rule.udp_options.destination_port_range.max if rule.udp_options and rule.udp_options.destination_port_range else None,
                "min": rule.udp_options.destination_port_range.min if rule.udp_options and rule.udp_options.destination_port_range else None
            },
            "source_port_range": {
                "max": rule.udp_options.source_port_range.max if rule.udp_options and rule.udp_options.source_port_range else None,
                "min": rule.udp_options.source_port_range.min if rule.udp_options and rule.udp_options.source_port_range else None
            }
        } if rule.udp_options else None
    }

def get_security_list_details(security_list_ids):
    if tuple(security_list_ids) in security_list_cache:
        return security_list_cache[tuple(security_list_ids)]
    security_list_details = []
    for security_list_id in security_list_ids:
        try:
            security_list_response = virtual_network_client.get_security_list(security_list_id)
            security_list_data = security_list_response.data
            ingress_rules = [extract_ingress_rule_attributes(rule) for rule in security_list_data.ingress_security_rules]
            egress_rules = [extract_egress_rule_attributes(rule) for rule in security_list_data.egress_security_rules]
            security_list_details.append({
                "display_name": security_list_data.display_name,
                "security_list_ocid": security_list_data.id,
                "ingress_security_rules": ingress_rules,
                "egress_security_rules": egress_rules
            })
        except oci.exceptions.ServiceError as e:
            print(f"Failed to get security list: {e}")
            continue
    security_list_cache[tuple(security_list_ids)] = security_list_details
    return security_list_details

# Parse the JSON data and filter based on action 'ACCEPT'
def parse_log_file(file_name):
    result_list = []
    with open(file_name, 'r') as f:
        for line in f:
            try:
                log_entry = json.loads(line)
                # Filter based on ingestedtime (last 30 days)
                ingested_time = log_entry['oracle']['ingestedtime']
                try:
                    ingested_datetime = datetime.strptime(ingested_time, "%Y-%m-%dT%H:%M:%S.%fZ")
                except ValueError:
                    # If the above fails, try without microseconds
                    ingested_datetime = datetime.strptime(ingested_time, "%Y-%m-%dT%H:%M:%SZ")
                
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
                    security_list_details = []
                    if vnic_subnet_ocid != 'N/A':
                        subnet_cidr, subnet_security_list = get_subnet_cidr(vnic_subnet_ocid)

                        # Fetch security list details for all security lists in the subnet
                        if subnet_security_list:
                            security_list_details = get_security_list_details(subnet_security_list)

                        # Determine traffic direction (egress, ingress) based on source or destination match
                        if subnet_cidr:
                            if is_ip_in_subnet(source_address, subnet_cidr):
                                traffic_direction = "egress"
                            elif is_ip_in_subnet(destination_address, subnet_cidr):
                                traffic_direction = "ingress"

                        # Check if both source and destination addresses are internal
                        if internal_or_external_source == "internal" and internal_or_external_destination == "internal":
                            traffic_type = "internal traffic"

                    # Add extracted data to the result list, including security list details
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
                        "security_lists": security_list_details,  # Contains details of all security lists
                        "oracle": oracle_data
                    })
            except json.JSONDecodeError:
                print(f"Skipping invalid JSON: {line}")

    return result_list

# Write the result to JSON and Excel
def write_output_to_files(output_data, log_file_name):
    # Use the lock to ensure thread-safe file writing
    with lock:
        # Write to JSON file
        json_output_file = f'C:\\Security\\Blogs\\Security_List\\Logs\\parsed_data\\{log_file_name}_output.json'
        with open(json_output_file, 'w') as json_file:
            json.dump(output_data, json_file, indent=4)

def upload_to_object_storage(file_path, bucket_name, object_name):
    with open(file_path, 'rb') as f:
        object_storage_client.put_object(
            namespace,
            bucket_name,
            object_name,
            f
        )

def write_output_to_bucket(parsed_data, bucket_name, thread_id):
    output_file_name = f"parsed_data_{thread_id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
    temp_file_path = os.path.join(tempfile.gettempdir(), output_file_name)

    # Write to a temporary file first
    with open(temp_file_path, 'w') as f:
        json.dump(parsed_data, f, indent=4)

    # Upload to Object Storage
    upload_to_object_storage(temp_file_path, bucket_name, output_file_name)

    # Clean up the temporary file
    os.remove(temp_file_path)

# Process a single log file
def process_single_log_file(client, namespace, bucket_name, obj_name, thread_id):
    log_file_name = obj_name.split('/')[-1].replace('.gz', '')  # Extract log file name
    extracted_file = download_and_extract_file(client, namespace, bucket_name, obj_name)
    parsed_data = parse_log_file(extracted_file)

    # Write each thread's output to a separate file
    write_output_to_bucket(parsed_data, parsed_data_bucket_name, thread_id)

    os.remove(extracted_file)  # Clean up extracted files
    return parsed_data

def process_flow_logs_in_parallel():
    objects = list_log_files(object_storage_client, namespace, bucket_name)
    extracted_data = []

    # Use ThreadPoolExecutor for parallel processing of files
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(process_single_log_file, object_storage_client, namespace, bucket_name, obj.name, idx): obj
            for idx, obj in enumerate(objects) if obj.name.endswith('.log.gz')
        }

        for future in as_completed(futures):
            try:
                data = future.result()
                extracted_data.extend(data)
            except Exception as e:
                print(f"Error processing file: {e}")

if __name__ == "__main__":
    process_flow_logs_in_parallel()
