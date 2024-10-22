# 🛡️ **Himaya** 🛡️

### 🚨 **Protecting Gmail Users from Ransomware Threats** 🚨

**Himaya** is an innovative Gmail add-on for Kenyan health organizatios that scans incoming emails for malicious links and attachments in real-time, providing early warnings to users by integrating with [VirusTotal](https://www.virustotal.com), [MalwareBazaar](https://bazaar.abuse.ch), and [AlienVault OTX](https://otx.alienvault.com). This tool is aimed at enhancing email security and keeping users safe from ransomware, phishing, and other cyber threats.

---

## ✨ **Features**

- 🛑 **Automatic Threat Detection**: Scans links and attachments in emails for malware or suspicious content.
- 📊 **Threat Analysis**: Integrates with VirusTotal, MalwareBazaar, and AlienVault OTX for comprehensive malware and phishing detection.
- 🔔 **Real-time Alerts**: Notifies users immediately upon detection of malicious content.
- 🎯 **Recommendations**: Provides clear actions and suggestions for users when threats are found.
- 🔊 **Very Visual Alerts**: Urgent alerts include red alert visuals for severe threats.

---

## 📚 **Table of Contents**

1. [Overview](#-himaya)
2. [Features](#-features)
3. [Installation](#-installation)
4. [How It Works](#-how-it-works)
5. [Usage](#-usage)
6. [Documentation](#-documentation)

---

## 🖥️ **Installation**

To install Himaya:

1. Clone the repository from GitHub:
   ```bash
   git clone https://github.com/Wambuapeter/Himaya.git
   ```
2. Open your Google Apps Script dashboard in Gmail.
3. Import the necessary scripts into your Google Apps Script project.
4. Set up your API keys for VirusTotal, MalwareBazaar, and AlienVault OTX.
5. Deploy the script and authorize it to scan your Gmail inbox.

---

## 🛠️ **How It Works**

**Himaya** works by integrating directly into your Gmail and analyzing emails in real-time:

- **Email Scanning**: When an email arrives, Himaya automatically extracts links and attachments.
- **Threat Assessment**: These elements are sent to VirusTotal, MalwareBazaar, and AlienVault OTX for analysis.
- **Alerting**: If any malicious content is detected, the user is notified with a pop-up alert, which is a red warning card.
- **Recommendations**: Users are advised not to click on links or attachments and are prompted to consult the IT/security specialist for further action.

---

## 📖 **Usage**

- Install Himaya following the [Installation](#-installation) instructions.
- Once deployed, Himaya will scan every new email automatically.
- If malicious content is detected, an alert card will appear in the Gmail interface with detailed recommendations.

---

## 📘 **Documentation**

For the full documentation about the problem, the research, solution idea etc , please visit the [Himaya Documentation](https://github.com/Wambuapeter/Himaya/tree/master/Documentation).
