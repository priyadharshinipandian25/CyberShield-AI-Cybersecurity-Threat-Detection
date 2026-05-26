import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

df = pd.read_csv("DrDoS_DNS.csv")

df.columns = df.columns.str.strip()

features = [
    'protocol',
    'flow_duration',
    'total_forward_packets',
    'total_backward_packets',
    'total_forward_packets_length',
    'total_backward_packets_length',
    'forward_packet_length_mean',
    'backward_packet_length_mean',
    'forward_packets_per_second',
    'backward_packets_per_second',
    'forward_iat_mean',
    'backward_iat_mean',
    'flow_iat_mean',
    'flow_packets_per_seconds',
    'flow_bytes_per_seconds'
]

label_col = 'label'

X = df[features]

y = df[label_col]

y = y.apply(lambda x: 0 if str(x).upper() == "BENIGN" else 1)

X = X.replace([float("inf"), -float("inf")], 0)
X = X.fillna(0)

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

model = RandomForestClassifier()

model.fit(X_train, y_train)

pred = model.predict(X_test)

accuracy = accuracy_score(y_test, pred)

print("Model Accuracy:", accuracy)

joblib.dump(model, "cyber_model.pkl")

print("Model trained successfully")