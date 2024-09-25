import oci

# Initialize OCI config and clients
config = oci.config.from_file()
logging_client = oci.logging.LoggingManagementClient(config)

# Specify the log group OCID
log_group_id = "ocid1.loggroup.oc1.iad.amaaaaaac3adhhqak3nytmqyql6pbjqepqwkfvhniktutfku454i46nuvjlq"

# Get the list of logs in the log group
logs = logging_client.list_logs(log_group_id).data

# Delete each log in the log group
for log in logs:
    logging_client.delete_log(log_group_id, log.id)
    print(f"Deleted log {log.display_name} with OCID {log.id}")