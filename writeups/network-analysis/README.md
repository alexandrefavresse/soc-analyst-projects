## Introduction

This network traffic investigation report was made during a homemade lab and simulates a real network traffic investigation report that a SOC Analyst would write after taking ownership of an alert.

For this purpose, I used a .pcap file from [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/web-investigation/) to conduct my own investigation.

The goal of this exercise is to practice my analysis and reporting skills in an environment as realistic as possible, as writing reports is an important part of a SOC Analyst's duties.

I chose to conduct a network traffic investigation to sharpen my investigation skills using Wireshark, and because the attack analysed in this report, a SQL injection, is one of the most common and impactful web application threats, ranked under **A05:2025 – Injection** in the [**OWASP Top 10**](https://owasp.org/Top10/2025/A05_2025-Injection/). Being able to detect and investigate injection attacks from network traffic is a valuable, real-world skill for a SOC Analyst.

*Disclaimer: All data is from a public sample created for educational purposes, credentials have been hidden to mimic professional practices.*

## Methodology

This report follows the same structure a SOC Analyst would use when documenting an investigation:

- **Classification** – I classify the incident, assign a severity level, and provide a confidence score reflecting how certain I am that the classification is correct.

- **Executive & Technical Summaries** – I wrote short overviews of the most important findings, one aimed at management, using non-technical vocabulary and one aimed at the SOC Lead, using technical terms, so they can quickly grasp the situation without reading the full report.

- **Alert Context** – Background on the alert that triggered the investigation.

- **Investigation Methodology** – The largest section of the report. Each step of the investigation is documented: I explain my reasoning, what led me to my conclusions, and the Wireshark filters I used along with why I used them.

- **Incident Timeline** – A chronological overview of the attack, reconstructing the attack chain and mapping it to the MITRE ATT&CK Framework.

- **Findings** – A breakdown of what the attacker did (and did not) achieve against the organization's web server, highlighting the impact of the attack.

- **Indicators of Compromise (IOCs)** – A list of the IOCs identified during the investigation to support defensive actions such as eradicating malicious files, blocking the malicious IP address, and blocking the User-Agents used in the attack. These IOCs can also be fed into the company's threat intelligence program.

- **Defensive Measures** – A set of recommendations to eradicate the threat and prevent similar attacks in the future, based on defense-in-depth principles.

## Tools Used

- **Wireshark** – Network traffic analysis and packet inspection.
- **Bash (Linux)** – Recreating the malicious file and computing its SHA-256 hash (`sha256sum`) for verification.
