import streamlit as st
import pandas as pd
from sklearn.ensemble import IsolationForest

# 1. Page Configuration
st.set_page_config(page_title="AWS Threat Scanner", page_icon="🛡️", layout="wide")

# 2. Load and Cache Data
@st.cache_data
def load_data():
    try:
        df = pd.read_csv("cloudtrail_logs.csv")
        return df
    except FileNotFoundError:
        # Fallback in case the file hasn't been generated yet
        return pd.DataFrame()

# Helper function to let users download the CSV report
@st.cache_data
def convert_df(df):
    return df.to_csv(index=False).encode('utf-8')

# 3. Machine Learning Engine
@st.cache_data
def detect_anomalies(df):
    if df.empty:
        return df
        
    # UPGRADE: Using One-Hot Encoding (get_dummies) instead of LabelEncoder 
    # This prevents the model from assuming numerical relationships between categorical strings
    ml_df = pd.get_dummies(df[['UserIdentity', 'EventName', 'SourceIPAddress']])
    
    # Isolation Forest Model
    model = IsolationForest(contamination=0.03, random_state=42)
    model.fit(ml_df)
    
    # Predict Threats
    predictions = model.predict(ml_df)
    df['Threat_Detected'] = [True if x == -1 else False for x in predictions]
    
    # Calculate Risk Score (1-100)
    scores = model.decision_function(ml_df)
    min_score, max_score = scores.min(), scores.max()
    
    # Prevent division by zero if all scores are identical
    if max_score != min_score:
        risk_scores = 100 - (((scores - min_score) / (max_score - min_score)) * 100)
    else:
        risk_scores = 0
        
    df['Risk_Score'] = risk_scores.round().astype(int)
    
    # Reorder columns so Risk Score is highly visible
    cols = ['Timestamp', 'UserIdentity', 'EventName', 'SourceIPAddress', 'Risk_Score', 'Threat_Detected']
    # Ensure we only select columns that exist in the dataframe
    cols = [c for c in cols if c in df.columns]
    df = df[cols]
    
    return df

# --- UI DASHBOARD ---
st.title("🛡️ AWS CloudTrail Anomaly Scanner")
st.markdown("Powered by Unsupervised Machine Learning (Isolation Forest)")
st.divider()

# UPGRADE: Interactive File Upload in the Sidebar
st.sidebar.header("Data Source")
st.sidebar.markdown("Upload your own CloudTrail CSV or use the default synthetic data.")
uploaded_file = st.sidebar.file_uploader("Upload CloudTrail Logs (CSV)", type="csv")

if uploaded_file is not None:
    raw_data = pd.read_csv(uploaded_file)
else:
    raw_data = load_data()

if raw_data.empty:
    st.warning("No data found. Please run `generate_data.py` to create the default dataset or upload a CSV in the sidebar.")
else:
    processed_data = detect_anomalies(raw_data)

    total_logs = len(processed_data)
    threats_df = processed_data[processed_data['Threat_Detected'] == True].sort_values(by='Risk_Score', ascending=False)
    threats_found = len(threats_df)

    # Top Metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric(label="Total Logs Scanned", value=total_logs)
    with col2:
        st.metric(label="Security Threats Detected", value=threats_found, delta="- Action Required" if threats_found > 0 else "Secure", delta_color="inverse")
    with col3:
        st.metric(label="Highest Risk Score", value=f"{threats_df['Risk_Score'].max()}/100" if threats_found > 0 else "0/100")

    st.divider()
    
    # UPGRADE: Visual Data Storytelling
    st.subheader("📈 Threat Detection Timeline")
    # Streamlit's native scatter chart easily plots anomalies visually
    st.scatter_chart(
        data=processed_data, 
        x='Timestamp', 
        y='Risk_Score', 
        color='Threat_Detected'
    )

    st.divider()

    # Data Tables
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