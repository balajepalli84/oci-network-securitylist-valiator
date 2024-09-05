import oci,sys
import pandas as pd
import datetime
import json
import ipaddress


# Initialize the config and clients
config = oci.config.from_file()
virtual_network_client = oci.core.VirtualNetworkClient(config)
logging_client = oci.logging.LoggingManagementClient(config)
identity_client = oci.identity.IdentityClient(config)

def list_all_compartments(tenancy_id):
    try:
        compartments = oci.pagination.list_call_get_all_results(
            identity_client.list_compartments,
            tenancy_id,
            compartment_id_in_subtree=True
        ).data
        return compartments
    except Exception as e:
        print(f"Failed to list compartments: {e}")
        return []

def list_all_vcns(compartment_id):
    try:
        vcn_list = oci.pagination.list_call_get_all_results(
            virtual_network_client.list_vcns,
            compartment_id
        ).data
        return vcn_list
    except Exception as e:
        print(f"Failed to list VCNs: {e}")
        return []

def list_all_subnets(compartment_id,vcn_id):
    try:
        subnet_list = oci.pagination.list_call_get_all_results(
            virtual_network_client.list_subnets,
            compartment_id=compartment_id,
            vcn_id=vcn_id
        ).data
        return subnet_list
    except Exception as e:
        print(f"Failed to list subnets for VCN {vcn_id}: {e}")
        return []

def check_flow_logs_enabled(compartment_id, subnet_id):
    try:
        log_groups = oci.pagination.list_call_get_all_results(
            logging_client.list_log_groups,
            compartment_id,
            is_compartment_id_in_subtree=True
        ).data
        
        for log_group in log_groups:
            list_logs_response = logging_client.list_logs(
                log_group_id=log_group.id,
                log_type="SERVICE"
            ).data
            for log in list_logs_response:
                if log.configuration.source.service in ['flowlogstest', 'flowlogs'] and log.configuration.source.resource == subnet_id:
                    return True, log_group.id,log_group.display_name,log.id, log.display_name
        return False, None, None, None, None
    except Exception as e:
        print(f"Failed to check flow logs for subnet {subnet_id}: {e}")
        return False, None, None, None, None

def query_flow_logs(query_id, limit=500):
    logging_client = oci.loggingsearch.LogSearchClient(config)
    end_time = datetime.datetime.utcnow()
    start_time = end_time - datetime.timedelta(days=13)
    search_query = f'search "{query_id}" | sort by datetime desc'
    search_logs_response = logging_client.search_logs(
        search_logs_details=oci.loggingsearch.models.SearchLogsDetails(
            time_start=start_time,
            time_end=end_time,
            search_query=search_query
        ),
        limit=limit
    ).data

    # Initialize a list to hold the results
    log_results = []

    # Get the data from response and store in the list of dictionaries
    for log in search_logs_response.results:
        log_data = log.data['logContent']['data']
        oracle_data = log.data['logContent']['oracle']       
        
        log_dict = {
            "sourceAddress": log_data.get('sourceAddress'),
            "sourcePort": log_data.get('sourcePort'),
            "destinationAddress": log_data.get('destinationAddress'),
            "destinationPort": log_data.get('destinationPort'),
            "action": log_data.get('action'),
            "protocolName": log_data.get('protocolName'),
            "compartmentid": oracle_data.get('compartmentid'),
            "resourceId": oracle_data.get('resourceId'),
            "resourceType": oracle_data.get('resourceType'),
            "vcnOcid": oracle_data.get('vcnOcid'),
            "vnicocid": oracle_data.get('vnicocid'),
            "vnicsubnetocid": oracle_data.get('vnicsubnetocid')
        }

        # Append the log dictionary to the list
        log_results.append(log_dict)

    return log_results


def validate_security_list(data):
    security_list_response = virtual_network_client.get_security_list(data["Security_List_ID"]).data
    query_flow_logs_response = query_flow_logs(f'{data["Compartment_ID"]}/{data["Log_Group_ID"]}/{data["Log_id"]}')
    subnet = virtual_network_client.get_subnet(data['Subnet_ID']).data

    # Mapping for protocols
    Protocol_mapping = {
        "1": "ICMP",
        "2": "IGMP",
        "6": "TCP",
        "17": "UDP",
        "41": "IPv6",
        "47": "GRE",
        "50": "ESP",
        "51": "AH",
        "58": "ICMPv6",
        "88": "EIGRP",
        "89": "OSPF",
        "132": "SCTP",
        "112": "VRRP",
        "115": "L2TP",
        "118": "STP",
        "121": "SMP",
        "123": "NTP",
        "137": "NETBIOS",
        "138": "NETBIOS Datagram Service",
        "139": "NETBIOS Session Service",
        "142": "IRTP",
        "161": "SNMP",
        "162": "SNMP Trap",
        "179": "BGP",
        "199": "SMUX",
        "204": "ATMP",
        "224": "NCP",
        "255": "Reserved"
    }

    sl_matched_records = []  # To store matched records
    sl_unmatched_records = []  # To store unmatched records

    for flow_log_record in query_flow_logs_response:
        try:
            ip_address = ipaddress.ip_address(flow_log_record["destinationAddress"])
        except ValueError:
            continue

        network = ipaddress.ip_network(subnet.cidr_block, strict=False)
        if ip_address in network and flow_log_record["action"] == 'ACCEPT':
            for security_list_rule in security_list_response.ingress_security_rules:
                # Check if the protocol name (from log) matches the protocol number (from rule)
                record_protocol = flow_log_record["protocolName"].upper()  # Log's protocol (like 'TCP')
                rule_protocol_number = str(security_list_rule.protocol)  # Security rule protocol number

                if rule_protocol_number in Protocol_mapping and Protocol_mapping[rule_protocol_number] == record_protocol:
                    # Check TCP Options
                    if record_protocol == "TCP" and security_list_rule.tcp_options:
                        destination_port = int(flow_log_record["destinationPort"])
                        if security_list_rule.tcp_options.destination_port_range:
                            port_range = security_list_rule.tcp_options.destination_port_range
                            if port_range.min <= destination_port <= port_range.max:
                                sl_matched_records.append({
                                    "Compartment_ID": data["Compartment_ID"],
                                    "Subnet_ID": data['Subnet_ID'],
                                    "Security_List_ID": data["Security_List_ID"],
                                    "Port": destination_port,
                                    "Port_range":port_range,
                                    "reason": "TCP port match"
                                })
                    elif record_protocol == "UDP" and security_list_rule.udp_options:
                        destination_port = int(flow_log_record["destinationPort"])
                        if security_list_rule.udp_options.destination_port_range:
                            port_range = security_list_rule.udp_options.destination_port_range
                            if port_range.min <= destination_port <= port_range.max:
                                sl_matched_records.append({
                                    "Compartment_ID": data["Compartment_ID"],
                                    "Subnet_ID": data['Subnet_ID'],
                                    "Security_List_ID": data["Security_List_ID"],
                                    "Port": destination_port,
                                    "Port_range":port_range,
                                    "reason": "UDP port match"
                                })
                    else:
                        destination_port = int(flow_log_record["destinationPort"])
                        sl_matched_records.append({
                                    "Compartment_ID": data["Compartment_ID"],
                                    "Subnet_ID": data['Subnet_ID'],
                                    "Security_List_ID": data["Security_List_ID"],
                                    "Port": destination_port,
                                    "Port_range":'NA',
                                    "reason": "Other port match"
                                })
                else:
                    sl_unmatched_records.append({
                        "Compartment_ID": data["Compartment_ID"],
                        "Subnet_ID": data['Subnet_ID'],
                        "Security_List_ID": data["Security_List_ID"],
                        "Port": flow_log_record["destinationPort"],
                        "Port_range":'NA',
                        "mismatch_reason": f"Protocol mismatch: Flow Log Protocol {record_protocol} != Security Rule Protocol number {rule_protocol_number} and {Protocol_mapping.get(rule_protocol_number, 'Unknown')}"
                    })
        else:
            print(f"{ip_address} is not part of CIDR {network}")

    return sl_matched_records,sl_unmatched_records

def main(tenancy_id):
    # Prepare lists to store data
    data = []
    matched_records = []  # Initialize globally
    unmatched_records = []  # Initialize globally

    compartments = list_all_compartments(tenancy_id)
    for compartment in compartments:
        print(f"Checking compartment_id:{compartment.id}")
        compartment_id = compartment.id
        vcns = list_all_vcns(compartment_id)
        for vcn in vcns:
            print(f"Checking VCN:{vcn.id}")
            subnets = list_all_subnets(compartment_id,vcn.id)
            for subnet in subnets:
                print(f"checking subnet:{subnet.id}")
                flow_logs_enabled, log_group_id, log_group_name, log_id, log_name = check_flow_logs_enabled(compartment_id, subnet.id)
                security_lists = subnet.security_list_ids
                # Flow Logs available, so go over each security list and make note of SL that allowed the traffic and port.
                for security_list in security_lists:
                    print(f"checking security list:{security_list}")      
                    val = [{
                        "Compartment_ID": compartment_id,
                        "VCN_ID": vcn.id,
                        "VCN_Name": vcn.display_name,
                        "Subnet_ID": subnet.id,
                        "Subnet_Name": subnet.display_name,
                        "Flow_Logs_Enabled": flow_logs_enabled,
                        "Log_Group_ID": log_group_id,
                        "Log_Group_Name": log_group_name,
                        "Log_id": log_id,
                        "Log_Name": log_name,
                        "Security_List_ID": security_list
                    }]
                    
                    if flow_logs_enabled:
                        new_matched, new_unmatched = validate_security_list(val[0])
                        matched_records.extend(new_matched)  # Accumulate matched records
                        unmatched_records.extend(new_unmatched)  # Accumulate unmatched records

                    data.append(val[0])  # Fix the append issue for data

    # Convert data to DataFrame and save to Excel
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    df = pd.DataFrame(data)
    df.to_excel(rf"C:\Security\Blogs\Security_List\Logs\raw_subnet_info_{timestamp}.xlsx", index=False)

    # Save matched records to Excel
    df_matched = pd.DataFrame(matched_records)
    df_matched.to_excel(rf"C:\Security\Blogs\Security_List\Logs\raw_data_matched_records_{timestamp}.xlsx", index=False)

    # Save unmatched records to Excel
    df_unmatched = pd.DataFrame(unmatched_records)
    df_unmatched.to_excel(rf"C:\Security\Blogs\Security_List\Logs\4_raw_data_unmatched_records_{timestamp}.xlsx", index=False)

if __name__ == "__main__":
    tenancy_id = config['tenancy']  # Get the tenancy ID from the config
    main(tenancy_id)
