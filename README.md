#  AWS CloudTrail Anomaly Scanner

An enterprise-grade, unsupervised Machine Learning tool designed to detect unauthorized and suspicious activities within AWS CloudTrail security logs. 

Built as a code sample for the **MLH Fellowship (Software Engineering Track)**.

##  The Dashboard
<img width="1910" height="888" alt="Screenshot 2026-06-02 010658" src="https://github.com/user-attachments/assets/92662ddf-2b53-464e-b678-0a8f21004940" />

<img width="1890" height="838" alt="Screenshot 2026-06-02 010711" src="https://github.com/user-attachments/assets/26f0e5b7-d874-4303-978e-9592ac7cfda2" />


##  How It Works
This project uses the **Isolation Forest** algorithm (an unsupervised Machine Learning model) to hunt for anomalies in cloud environments. Unlike traditional rule-based security tools, this model does not need to know what a "hacker" looks like; it mathematically isolates data points that deviate from normal baseline behavior using rigorous One-Hot Encoding for categorical event data.

##  System Architecture
```mermaid
graph TD;
    A[Synthetic AWS CloudTrail Logs] --> B[Pandas Data Processing & Encoding];
    B --> C[Isolation Forest ML Model];
    C --> D{Anomaly Detected?};
    D -- Yes --> E[Flag as Threat & Assign Risk Score 1-100];
    D -- No --> F[Mark as Safe];
    E --> G[Streamlit UI Dashboard & Timeline];
    F --> G[Streamlit UI Dashboard & Timeline];
