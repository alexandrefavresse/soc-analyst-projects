## Introduction

  This Active Directory investigation report was made during a homemade lab and simulates a real investigation report that a SOC Analyst would write after taking ownership of an alert.

  To make this report and conduct my investigation, I used material from the ShadowRoast lab on CyberDefenders.* Although the material comes from this source, I went deeper in the investigation than what is asked within the framework of the lab on CyberDefenders and went out of the scope of the exercices by writing a realistic incident investigation report.

  The goal of this exercise is to practice my analysis and reporting skills in an environment as realistic as possible, as writing reports is an important part of a SOC Analyst's duties.

  I chose to conduct this investigation to sharpen my skills with Splunk, one of the most popular SIEM tools worlwide. I also found this particular material interesting because the attack was conducted in an Active Directory environment, which is used in a vast majority of organizations around the world, and it helped me understand more which tools are used to attack these systems, how they work and what to look for in this environment. 

**Source: https://cyberdefenders.org/blueteam-ctf-challenges/shadowroast/*

## Methodology

This report follows the same structure a SOC Analyst would use when documenting an investigation:

- **Classification** –  Classification of the incident, with a severity level and a confidence score reflecting how certain I am that the classification is correct.

- **Executive & Technical Summaries** – Short overviews of the most important findings, one aimed at management, using non-technical vocabulary and one aimed at the SOC Lead, using technical terms, so they can quickly grasp the situation without reading the full report.

- **Alert Context** – Background on the alert that triggered the investigation.

- **Investigation Methodology** – The largest section of the report. Each step of the investigation is documented: I explain my reasoning, what led me to my conclusions, and the Splunk filters I used along with why I used them.

- **Incident Timeline** – A chronological overview of the attack, reconstructing the attack chain and mapping it to the MITRE ATT&CK Framework.

- **Indicators of Compromise (IOCs)** – A list of the IOCs identified during the investigation to support defensive actions such as eradicating malicious files and registry keys and blocking the malicious IP address. These IOCs can also be fed into the company's threat intelligence program.

- **Defensive Measures** – A set of recommendations to eradicate the threat and prevent similar attacks in the future, based on defense-in-depth principles.

## Tools Used

- **Splunk** - I used the SIEM to analyze the logs collected from various sources and correlate them in order to retrace the timeline of the incident, identify the tactics and techniques used by the attacker and find the actions on objectives of the attacker.
- **VirusTotal & Hybrid Analysis**: I used these platforms to conduct reputation checks of the files that I suspected to be malicious by searching for their respectives hashes to confirm their nature.
