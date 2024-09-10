import oci
import os

# Initialize OCI config
config = oci.config.from_file()  # Use the default location ~/.oci/config

# Define the Object Storage client
object_storage_client = oci.object_storage.ObjectStorageClient(config)

# Namespace and bucket name
namespace = "ociateam"  # OCI Object Storage namespace
bucket_name = "parsed-flow-log-data"  # Replace with your bucket name

# Define local download directory
download_directory = r'C:\Security\Blogs\Security_List\Logs\downloads'  # Define the local directory where files will be saved

# Create the directory if it doesn't exist
if not os.path.exists(download_directory):
    os.makedirs(download_directory)

# List objects in the bucket
objects = object_storage_client.list_objects(namespace, bucket_name)

for obj in objects.data.objects:
    object_name = obj.name
    print(f"Downloading {object_name}...")

    # Download object from OCI Object Storage
    get_object_response = object_storage_client.get_object(namespace, bucket_name, object_name)

    # Save the object to the local directory
    local_file_path = os.path.join(download_directory, object_name)
    with open(local_file_path, 'wb') as f:
        f.write(get_object_response.data.content)

    print(f"{object_name} downloaded to {local_file_path}")

print("All objects downloaded successfully.")
