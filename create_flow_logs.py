import oci, sys
import random,string

# Initialize OCI config and clients
config = oci.config.from_file() 
virtual_network_client = oci.core.VirtualNetworkClient(config)
identity_client = oci.identity.IdentityClient(config)
logging_client = oci.logging.LoggingManagementClient(config)

# Get the tenancy's OCID from the config
tenancy_id = config["tenancy"]

# Function to list all compartments in the tenancy
def list_compartments(identity_client, tenancy_id):
    compartments = []
    compartment_response = identity_client.list_compartments(
        tenancy_id, 
        compartment_id_in_subtree=True, 
        access_level="ACCESSIBLE"
    )
    compartments = compartment_response.data
    compartments.append(identity_client.get_compartment(tenancy_id).data)  # Add root compartment
    return compartments

# Function to fetch log groups and logs once and store them in a dict for lookup
def fetch_log_groups_and_logs(tenancy_id):
    log_dict = {}
    
    log_groups = oci.pagination.list_call_get_all_results(
        logging_client.list_log_groups,
        tenancy_id,
        is_compartment_id_in_subtree=True
    ).data
    
    for log_group in log_groups:
        logs = logging_client.list_logs(
            log_group_id=log_group.id,
            log_type="SERVICE"
        ).data
        for log in logs:
            log_dict[log.configuration.source.resource] = {
                "log_group_id": log_group.id,
                "log_group_display_name": log_group.display_name,
                "log_id": log.id,
                "log_display_name": log.display_name
            }
    
    return log_dict

# Function to create a new log group if not exists
def create_log_group_if_missing(tenancy_id, log_group_name="subnet_flow_log_group"):
    # Check if the log group already exists
    existing_log_groups = logging_client.list_log_groups(tenancy_id).data    
    check_log_group=False
    if existing_log_groups:
        for log_group in existing_log_groups:
            if log_group.display_name == log_group_name:
                check_log_group=True
                return log_group.id, log_group.display_name
    
    # If not exists, create the log group
    if check_log_group == False:
        log_group_details = oci.logging.models.CreateLogGroupDetails(
            compartment_id=tenancy_id,
            display_name=log_group_name
        )
        log_group = logging_client.create_log_group(log_group_details)
        #log_group.data returns none. without OCID, we cant get the details, so we have to list the groups and match name again
        existing_log_groups = logging_client.list_log_groups(tenancy_id).data 
        for log_group in existing_log_groups:
            if log_group.display_name == log_group_name:
                check_log_group=True
                return log_group.id, log_group.display_name

def create_flow_log_for_subnet(subnet, log_group_id, compartment_name, vcn_name):
    try:
        random_letters = ''.join(random.choices(string.ascii_lowercase, k=2))
        display_name = f"{compartment_name}_{vcn_name}_flow_log_{random_letters}".replace(' ', '_')
        print(f"Creating flow log for subnet {subnet.display_name} with display name {display_name}")
        log_details = oci.logging.models.CreateLogDetails(
            display_name=display_name,
            log_type="SERVICE",
            configuration=oci.logging.models.Configuration(
                source=oci.logging.models.OciService(
                    source_type="OCISERVICE",
                    service="flowlogs",
                    resource=subnet.id,
                    category="all"
                )
            )
        )
        logging_client.create_log(log_group_id, log_details)
        print(f"Created flow log for subnet {subnet.display_name} with display name {display_name}")
    except oci.exceptions.ServiceError as e:
        print(f"Failed to create flow log for subnet {subnet.display_name}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def check_and_enable_flow_logs_in_subnets(virtual_network_client, compartment_id, log_dict, log_group_id):
    subnets = virtual_network_client.list_subnets(compartment_id).data        
    compartment_name = identity_client.get_compartment(compartment_id).data.name

    for subnet in subnets:
        print(f"Checking subnet: {subnet.display_name} in VCN {subnet.vcn_id} and compartment {compartment_id}")
        if subnet.id in log_dict:
            log_info = log_dict[subnet.id]
            print(f"Flow logs already enabled for subnet {subnet.display_name}: "
                  f"Log Group: {log_info['log_group_display_name']}, Log: {log_info['log_display_name']}")
        else:
            print(f"Flow logs not enabled for subnet: {subnet.display_name} in VCN {subnet.vcn_id}. Creating new flow log.")
            vcn_name = virtual_network_client.get_vcn(subnet.vcn_id).data.display_name
            create_flow_log_for_subnet(subnet, log_group_id, compartment_name, vcn_name)

# Main script execution
def main():
    log_group_id, log_group_name = create_log_group_if_missing(tenancy_id)
    compartments = list_compartments(identity_client, tenancy_id)
    log_dict = fetch_log_groups_and_logs(tenancy_id)
    for compartment in compartments:
        if compartment.lifecycle_state == 'ACTIVE':
            print(f"Processing compartment: {compartment.name}")            
            check_and_enable_flow_logs_in_subnets(virtual_network_client, compartment.id, log_dict, log_group_id)

if __name__ == "__main__":
    main()