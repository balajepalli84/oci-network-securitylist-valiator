import oci,sys

# Initialize the config and client
config = oci.config.from_file()  # Assumes a config file at ~/.oci/config
logging_client = oci.logging.LoggingManagementClient(config)
identity_client = oci.identity.IdentityClient(config)

def list_all_log_groups(compartment_id):
    try:
        # Create a list to hold all log groups
        all_log_groups = []

        # List log groups
        log_group_list = oci.pagination.list_call_get_all_results(
            logging_client.list_log_groups,
            compartment_id,
            is_compartment_id_in_subtree=True
        ).data       
        
        for log_group in log_group_list:
            list_logs_response = logging_client.list_logs(
                log_group_id=log_group.id,
                log_type="SERVICE").data
            for list in list_logs_response:
                print(list)
                sys.exit()
                if list.configuration.source.service == 'flowlogstest' or list.configuration.source.service == 'flowlogs':
                    print(f"subnet has flow logs enabled {list.configuration.source.resource}")
        return all_log_groups
    except Exception as e:
        print(f"Failed to list log groups: {e}")
        return None

def list_all_compartments(tenancy_id):
    try:
        # Create a list to hold all compartments
        all_compartments = []

        # List compartments
        compartment_list = oci.pagination.list_call_get_all_results(
            identity_client.list_compartments,
            tenancy_id,
            compartment_id_in_subtree=True
        ).data

        for compartment in compartment_list:
            all_compartments.append(compartment)
            #print(f"Compartment: {compartment.name} (ID: {compartment.id})")
        
        return all_compartments
    except Exception as e:
        print(f"Failed to list compartments: {e}")
        return None

def main():
    # Replace with your tenancy ID
    tenancy_id = config["tenancy"]

    # List all compartments in the tenancy
    compartments = list_all_compartments(tenancy_id)

    if compartments:
        # Iterate through each compartment and list all log groups
        for compartment in compartments:
            #print(f"Listing log groups for compartment: {compartment.name}")
            list_all_log_groups(compartment.id)


if __name__ == "__main__":
    main()
