import oci,sys
import pandas as pd

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

def check_flow_logs_enabled(compartment_id,subnet_id):
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
                    return True
        return False
    except Exception as e:
        print(f"Failed to check flow logs for subnet {subnet_id}: {e}")
        return False

def main(tenancy_id):
    # Prepare lists to store data
    data = []

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
                if check_flow_logs_enabled(compartment_id,subnet.id):
                    security_lists = subnet.security_list_ids
                    for security_list in security_lists:
                        print(f"checking security list:{security_list}")
                        data.append({
                            "Compartment ID": compartment_id,
                            "VCN ID": vcn.id,
                            "VCN Name": vcn.display_name,
                            "Subnet ID": subnet.id,
                            "Subnet Name": subnet.display_name,
                            "Flow Logs Enabled": "Yes",
                            "Security List ID": security_list
                        })
                '''        
                else:
                    for security_list in security_lists:
                        print(f"checking security list:{security_list}")
                        data.append({
                            "Compartment ID": compartment_id,
                            "VCN ID": vcn.id,
                            "VCN Name": vcn.display_name,
                            "Subnet ID": subnet.id,
                            "Subnet Name": subnet.display_name,
                            "Flow Logs Enabled": "No",
                            "Security List ID": security_list
                        })
                '''    

    # Convert to DataFrame and save to Excel
    df = pd.DataFrame(data)
    df.to_excel(r"C:\Security\Blogs\Security_List\Logs\raw_subnet_info.xlsx", index=False)

if __name__ == "__main__":
    tenancy_id = config['tenancy']  # Get the tenancy ID from the config
    main(tenancy_id)
