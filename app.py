import streamlit as st
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

# 1. Page Configuration (Must be the first Streamlit command)
st.set_page_config(page_title="AWS Threat Scanner", page_icon="🛡️", layout="wide")

# 2. Load and Cache Data (Makes the app blazing fast)
@st.cache_data
def load_data():
    df = pd.read_csv("cloudtrail_logs.csv")
    return df

# 3. Machine Learning Engine
@st.cache_data
def detect_anomalies(df):
    # ML models need numbers, not text. We use LabelEncoder to convert strings to numbers.
    le = LabelEncoder()
    ml_df = pd.DataFrame()
    ml_df['UserIdentity'] = le.fit_transform(df['UserIdentity'])
    ml_df['EventName'] = le.fit_transform(df['EventName'])
    ml_df['SourceIPAddress'] = le.fit_transform(df['SourceIPAddress'])
    
    # Train the Isolation Forest model
    # contamination=0.03 means we expect roughly 3% of our data to be hackers (15 out of 515)
    model = IsolationForest(contamination=0.03, random_state=42)
    model.fit(ml_df)
    
    # Predict (-1 means Anomaly/Hacker, 1 means Normal)
    predictions = model.predict(ml_df)
    
    # Add predictions back to our original dataframe for the UI
    df['Threat_Detected'] = predictions
    # Convert -1/1 to True/False for easier reading
    df['Threat_Detected'] = df['Threat_Detected'].apply(lambda x: True if x == -1 else False)
    
    return df

# --- UI DASHBOARD ---

st.title("🛡️ AWS CloudTrail Anomaly Scanner")
st.markdown("Powered by Unsupervised Machine Learning (Isolation Forest)")
st.divider()

# Load data and run ML
raw_data = load_data()
processed_data = detect_anomalies(raw_data)

# Calculate metrics for the dashboard
total_logs = len(processed_data)
threats_found = len(processed_data[processed_data['Threat_Detected'] == True])

# Display Top Level KPIs
col1, col2, col3 = st.columns(3)
with col1:
    st.metric(label="Total Logs Scanned", value=total_logs)
with col2:
    st.metric(label="Security Threats Detected", value=threats_found, delta="- Action Required", delta_color="inverse")
with col3:
    st.metric(label="Model Algorithm", value="Isolation Forest")

st.divider()

# Split UI into two tabs
tab1, tab2 = st.tabs(["🚨 Critical Threats", "📊 Full Log Database"])

with tab1:
    st.subheader("High Priority Security Alerts")
    # Filter the dataframe to only show the rows where Threat_Detected is True
    threats_df = processed_data[processed_data['Threat_Detected'] == True]
    
    if threats_found > 0:
        st.error(f"CRITICAL: {threats_found} unauthorized actions detected in the cloud environment.")
        # We drop the fake 'IsAnomaly' column we made earlier so it looks like a real tool
        st.dataframe(threats_df.drop(columns=['IsAnomaly']), use_container_width=True)
    else:
        st.success("No threats detected. Cloud environment is secure.")

with tab2:
    st.subheader("All CloudTrail Logs")
    st.dataframe(processed_data.drop(columns=['IsAnomaly']), use_container_width=True)