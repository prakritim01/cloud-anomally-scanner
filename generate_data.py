import pandas as pd
import random
from datetime import datetime, timedelta

# Lock the randomness so the dataset is the exact same every time
random.seed(42)

# Define what "Normal" looks like
normal_ips = ["192.168.1.10", "192.168.1.11", "10.0.0.5"]
normal_users = ["alice-dev", "bob-ops", "system-role"]
normal_events = ["DescribeInstances", "ListBuckets", "GetCallerIdentity", "ConsoleLogin"]

# Define what "Hackers/Anomalies" look like
evil_ips = ["203.0.113.50", "198.51.100.22"]
evil_users = ["unauthorized-user", "root"]
evil_events = ["DeleteTrail", "StopLogging", "DeleteBucket", "CreateUser"]

data = []
# Start time: March 20, 2026
start_time = datetime(2026, 3, 20, 8, 0, 0)

# 1. Generate 500 normal, safe logs
for i in range(500):
    event_time = start_time + timedelta(minutes=random.randint(1, 10000))
    data.append({
        "Timestamp": event_time.strftime("%Y-%m-%d %H:%M:%S"),
        "UserIdentity": random.choice(normal_users),
        "EventName": random.choice(normal_events),
        "SourceIPAddress": random.choice(normal_ips),
        "UserAgent": "AWS Internal/Safe",
        "IsAnomaly": 0  # 0 means safe. We use this later to check our ML model's accuracy.
    })

# 2. Inject 15 dangerous, anomalous logs
for i in range(15):
    event_time = start_time + timedelta(minutes=random.randint(1, 10000))
    data.append({
        "Timestamp": event_time.strftime("%Y-%m-%d %H:%M:%S"),
        "UserIdentity": random.choice(evil_users),
        "EventName": random.choice(evil_events),
        "SourceIPAddress": random.choice(evil_ips),
        "UserAgent": "Unknown Script/Kali",
        "IsAnomaly": 1  # 1 means threat!
    })

# 3. Shuffle the data so the threats are hidden, and save to CSV
df = pd.DataFrame(data)
df = df.sample(frac=1).reset_index(drop=True)
df.to_csv("cloudtrail_logs.csv", index=False)

print("✅ Successfully generated 515 AWS CloudTrail logs (with 15 hidden anomalies)!")