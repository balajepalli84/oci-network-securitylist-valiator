import os
import json
import pandas as pd
from sklearn import svm
from sklearn.preprocessing import StandardScaler

def ip2int(ip):
    return sum([int(octet) << (24 - i * 8) for i, octet in enumerate(ip.split('.'))])

# Set the directory path and anomaly threshold
directory_path = r'C:\Security\Blogs\Security_List\Logs\ml_parsed_data'
anomaly_threshold = -1.0  # adjust this value to change the anomaly detection sensitivity

# Initialize the feature extractor and anomaly detector
feature_extractor = pd.DataFrame(columns=['source_address', 'destination_address', 'port_number', 'protocol'])
original_data = []  # store the original data records
anomaly_detector = svm.OneClassSVM(kernel='rbf', gamma=0.1, nu=0.1)

# Iterate through all JSON files in the directory
for filename in os.listdir(directory_path):
    if filename.endswith('.json'):
        # Load the JSON file
        with open(os.path.join(directory_path, filename), 'r') as f:
            data = json.load(f)
        
        # Store the original data records
        original_data.extend(data)
        
        # Extract features from the JSON data
        features = pd.DataFrame({
            'source_address': [ip2int(x['sourceAddress']) for x in data],
            'destination_address': [ip2int(x['destinationAddress']) for x in data],
            'port_number': [x['destinationPort'] for x in data],
            'protocol': [x['protocol'] for x in data]
        })
        
        # Append the features to the feature extractor
        feature_extractor = pd.concat([feature_extractor, features], ignore_index=True)

# Scale the features using StandardScaler
scaler = StandardScaler()
feature_extractor_scaled = scaler.fit_transform(feature_extractor)

# Train the anomaly detector
anomaly_detector.fit(feature_extractor_scaled)

# Predict anomalies
anomaly_scores = anomaly_detector.decision_function(feature_extractor_scaled)

# Identify anomalies
anomaly_indices = [i for i, score in enumerate(anomaly_scores) if score < anomaly_threshold]

# Create a list to store the anomaly records with reasons
anomaly_records = []

# Iterate through the anomaly indices
for index in anomaly_indices:
    # Get the original data record
    record = original_data[index]
    
    # Get the feature vector for the anomaly record
    feature_vector = feature_extractor_scaled[index]
    
    # Calculate the anomaly scores for each feature
    feature_scores = {}
    for i, feature_name in enumerate(feature_extractor.columns):
        feature_score = anomaly_detector.decision_function([feature_vector])[0]
        feature_scores[feature_name] = feature_score
    
    # Create an anomaly record with reasons
    anomaly_record = {
        'record': record,
        'reasons': feature_scores
    }
    
    # Append the anomaly record to the list
    anomaly_records.append(anomaly_record)

# Write the anomaly records to a JSON file
with open(os.path.join(directory_path, 'anomaly_response.json'), 'w') as f:
    json.dump(anomaly_records, f, indent=4)