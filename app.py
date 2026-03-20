import streamlit as st
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

# 1. Page Configuration
st.set_page_config(page_title="AWS Threat Scanner", page_icon="🛡️", layout="wide")

# 2. Load and Cache Data
@st.cache_data
def load_data():
    df = pd.read_csv("cloudtrail_logs.csv")
    return df

# Helper function to let users download the CSV report
@st.cache_data
def convert_df(df):
    return df.to_csv(index=False).encode('utf-8')

# 3. Machine Learning Engine
@st.cache_data
def detect_anomalies(df):
    le = LabelEncoder()
    ml_df = pd.DataFrame()
    ml_df['UserIdentity'] = le.fit_transform(df['UserIdentity'])
    ml_df['EventName'] = le.fit_transform(df['EventName'])
    ml_df['SourceIPAddress'] = le.fit_transform(df['SourceIPAddress'])
    
    model = IsolationForest(contamination=0.03, random_state=42)
    model.fit(ml_df)
    
    # Predict Threats
    predictions = model.predict(ml_df)
    df['Threat_Detected'] = [True if x == -1 else False for x in predictions]
    
    # Calculate Risk Score (1-100)
    # The model's decision_function gives a raw anomaly score. We invert and scale it to 1-100.
    scores = model.decision_function(ml_df)
    min_score, max_score = scores.min(), scores.max()
    risk_scores = 100 - (((scores - min_score) / (max_score - min_score)) * 100)
    df['Risk_Score'] = risk_scores.round().astype(int)
    
    # Reorder columns so Risk Score is highly visible
    cols = ['Timestamp', 'UserIdentity', 'EventName', 'SourceIPAddress', 'Risk_Score', 'Threat_Detected']
    df = df[cols]
    
    return df

# --- UI DASHBOARD ---
st.title("🛡️ AWS CloudTrail Anomaly Scanner")
st.markdown("Powered by Unsupervised Machine Learning (Isolation Forest)")
st.divider()

raw_data = load_data()
processed_data = detect_anomalies(raw_data)

total_logs = len(processed_data)
threats_df = processed_data[processed_data['Threat_Detected'] == True].sort_values(by='Risk_Score', ascending=False)
threats_found = len(threats_df)

col1, col2, col3 = st.columns(3)
with col1:
    st.metric(label="Total Logs Scanned", value=total_logs)
with col2:
    st.metric(label="Security Threats Detected", value=threats_found, delta="- Action Required", delta_color="inverse")
with col3:
    st.metric(label="Highest Risk Score", value=f"{threats_df['Risk_Score'].max()}/100" if threats_found > 0 else "0/100")

st.divider()

tab1, tab2 = st.tabs(["🚨 Critical Threats", "📊 Full Log Database"])

with tab1:
    col_a, col_b = st.columns([3, 1])
    with col_a:
        st.subheader("High Priority Security Alerts")
    with col_b:
        # The Export Report Button
        if threats_found > 0:
            csv = convert_df(threats_df)
            st.download_button(label="📥 Download Threat Report", data=csv, file_name='threat_report.csv', mime='text/csv')

    if threats_found > 0:
        st.error(f"CRITICAL: {threats_found} unauthorized actions detected.")
        st.dataframe(threats_df, use_container_width=True)
    else:
        st.success("No threats detected. Cloud environment is secure.")

with tab2:
    st.subheader("All CloudTrail Logs")
    st.dataframe(processed_data.sort_values(by='Risk_Score', ascending=False), use_container_width=True)