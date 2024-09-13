import oci

# Initialize OCI config and clients
config = oci.config.from_file()  # Make sure you have your ~/.oci/config file set up
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
def fetch_log_groups_and_logs(compartment_id):
    log_dict = {}
    
    log_groups = oci.pagination.list_call_get_all_results(
        logging_client.list_log_groups,
        compartment_id,
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
def create_log_group_if_missing(compartment_id, log_group_name="subnet_flow_log_group"):
    # Check if the log group already exists
    existing_log_groups = logging_client.list_log_groups(compartment_id).data
    for log_group in existing_log_groups:
        if log_group.display_name == log_group_name:
            return log_group.id, log_group.display_name

    # If not exists, create the log group
    log_group_details = oci.logging.models.CreateLogGroupDetails(
        compartment_id=compartment_id,
        display_name=log_group_name
    )
    log_group = logging_client.create_log_group(log_group_details).data
    return log_group.id, log_group.display_name

# Function to create a flow log for a subnet
def create_flow_log_for_subnet(subnet, log_group_id):
    log_details = oci.logging.models.CreateLogDetails(
        display_name=f"{subnet.display_name}_flow_log",
        log_type="SERVICE",
        configuration=oci.logging.models.ServiceLogConfiguration(
            source=oci.logging.models.ServiceLogSource(
                service="flowlogs",
                resource=subnet.id
            )
        )
    )
    logging_client.create_log(log_group_id, log_details)
    print(f"Created flow log for subnet {subnet.display_name}")

# Function to check and enable flow logs for each subnet in a compartment
def check_and_enable_flow_logs_in_subnets(virtual_network_client, compartment_id, log_dict):
    subnets = virtual_network_client.list_subnets(compartment_id).data
    
    log_group_id, log_group_name = create_log_group_if_missing(compartment_id)

    for subnet in subnets:
        print(f"Checking subnet: {subnet.display_name} in compartment {compartment_id}")
        if subnet.id in log_dict:
            log_info = log_dict[subnet.id]
            print(f"Flow logs already enabled for subnet {subnet.display_name}: "
                  f"Log Group: {log_info['log_group_display_name']}, Log: {log_info['log_display_name']}")
        else:
            print(f"Flow logs not enabled for subnet: {subnet.display_name}. Creating new flow log.")
            create_flow_log_for_subnet(subnet, log_group_id)

# Main script execution
def main():
    compartments = list_compartments(identity_client, tenancy_id)
    for compartment in compartments:
        print(f"Processing compartment: {compartment.name}")
        log_dict = fetch_log_groups_and_logs(compartment.id)
        check_and_enable_flow_logs_in_subnets(virtual_network_client, compartment.id, log_dict)

if __name__ == "__main__":
    main()
