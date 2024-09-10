import oci

# OCI configuration
config = oci.config.from_file("~/.oci/config")  # Modify if your config file is located elsewhere
object_storage_client = oci.object_storage.ObjectStorageClient(config)
namespace = "ociateam"  # OCI Object Storage namespace
bucket_name = "parsed-flow-log-data"  # Replace with your bucket name

def delete_all_objects_in_bucket(namespace, bucket_name):
    try:
        # List all objects in the bucket
        list_objects_response = object_storage_client.list_objects(namespace, bucket_name)
        objects = list_objects_response.data.objects
        
        if not objects:
            print("No objects found in the bucket.")
            return

        for obj in objects:
            # Delete each object
            print(f"Deleting object: {obj.name}")
            object_storage_client.delete_object(namespace, bucket_name, obj.name)
        
        print("All objects have been deleted.")
    except oci.exceptions.ServiceError as e:
        print(f"Service error: {e}")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    delete_all_objects_in_bucket(namespace, bucket_name)
