import json
import requests
import pandas as pd

CSV_PATH = r"data\Training and Testing Sets\UNSW_NB15_testing-set.csv"
API_URL = "http://127.0.0.1:8000/api/analyze"

# Load actual UNSW-NB15 testing dataset
df = pd.read_csv(CSV_PATH)

# ---------------------------------------------------------
# Record #1
# ---------------------------------------------------------
row = df.iloc[0]

# Exact 42 model features
MODEL_FEATURES = [
    "dur",
    "proto",
    "service",
    "state",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sttl",
    "dttl",
    "sload",
    "dload",
    "sloss",
    "dloss",
    "sinpkt",
    "dinpkt",
    "sjit",
    "djit",
    "swin",
    "stcpb",
    "dtcpb",
    "dwin",
    "tcprtt",
    "synack",
    "ackdat",
    "smean",
    "dmean",
    "trans_depth",
    "response_body_len",
    "ct_srv_src",
    "ct_state_ttl",
    "ct_dst_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "is_ftp_login",
    "ct_ftp_cmd",
    "ct_flw_http_mthd",
    "ct_src_ltm",
    "ct_srv_dst",
    "is_sm_ips_ports",
]

network_record = {}

for feature in MODEL_FEATURES:
    value = row[feature]

    if feature in ["proto", "service", "state"]:
        network_record[feature] = str(value)
    else:
        network_record[feature] = float(value)


# ---------------------------------------------------------
# Ground truth
# ---------------------------------------------------------
dataset_id = int(row["id"])
ground_truth_attack = str(row["attack_cat"])
ground_truth_label = int(row["label"])


# ---------------------------------------------------------
# Security log
# ---------------------------------------------------------
security_log = (
    f"UNSW-NB15 Record #{dataset_id}. "
    f"Network traffic observed using protocol {row['proto']}. "
    f"Service {row['service']}. "
    f"Connection state {row['state']}. "
    f"Duration {float(row['dur']):.6f} seconds. "
    f"Source packets {row['spkts']}. "
    f"Destination packets {row['dpkts']}. "
    f"Source bytes {row['sbytes']}. "
    f"Destination bytes {row['dbytes']}."
)


payload = {
    "security_log": security_log,
    "network_record": network_record,
    "dataset_id": dataset_id,
    "ground_truth_attack": ground_truth_attack,
    "ground_truth_label": ground_truth_label,
}


print("\n========== RECORD #1 ==========")
print("Dataset ID:", dataset_id)
print("Ground Truth Attack:", ground_truth_attack)
print("Ground Truth Label:", ground_truth_label)
print("Feature Count:", len(network_record))

print("\n========== REQUEST ==========")
print(json.dumps(payload, indent=2))


response = requests.post(
    API_URL,
    json=payload,
    timeout=30
)

print("\n========== API STATUS ==========")
print(response.status_code)

print("\n========== API RESPONSE ==========")
print(json.dumps(response.json(), indent=2))