# 🛡️ AWS CloudTrail Anomaly Scanner

An enterprise-grade, unsupervised Machine Learning tool designed to detect unauthorized and suspicious activities within AWS CloudTrail security logs. 

Built as a code sample for the **MLH Fellowship (Software Engineering Track)**.

## 🚀 The Dashboard
*(Add your first screenshot here: `![Dashboard](link-to-image)`)*
*(Add your second screenshot here: `![Threats](link-to-image)`)*

## 🧠 How It Works
This project uses the **Isolation Forest** algorithm (an unsupervised Machine Learning model) to hunt for anomalies in cloud environments. Unlike traditional rule-based security tools, this model does not need to know what a "hacker" looks like; it mathematically isolates data points that deviate from normal baseline behavior.

## 🏗️ System Architecture
```mermaid
graph TD;
    A[Synthetic AWS CloudTrail Logs] --> B[Pandas Data Processing];
    B --> C[Label Encoding];
    C --> D[Isolation Forest ML Model];
    D --> E{Anomaly Detected?};
    E -- Yes --> F[Flag as Threat & Assign Risk Score 1-100];
    E -- No --> G[Mark as Safe];
    F --> H[Streamlit UI Dashboard];
    G --> H[Streamlit UI Dashboard];

**Key Features:**
* **Synthetic Data Generation:** Includes a secure script to generate realistic AWS CloudTrail logs with hidden, randomized cyber threats (e.g., unauthorized `DeleteTrail` or `StopLogging` events).
* **Unsupervised Threat Detection:** Uses `scikit-learn`'s Isolation Forest to automatically flag high-risk IP addresses and anomalous user behavior.
* **Real-time Dashboard:** A blazing-fast UI built with Streamlit to visualize security postures and isolate critical alerts.

## 🛠️ Tech Stack
* **Language:** Python 3.11+
* **Machine Learning:** Scikit-Learn (Isolation Forest)
* **Data Processing:** Pandas
* **Frontend:** Streamlit

## 💻 How to Run Locally

**1. Clone the repository**
```bash
git clone [https://github.com/YOUR-USERNAME/cloud-anomaly-scanner.git](https://github.com/YOUR-USERNAME/cloud-anomaly-scanner.git)
cd cloud-anomaly-scanner