## Introduction

The phishing analysis report present in this repo was made during a homemade lab and is presented as a simulation of a real phishing report that a SOC Analyst would write after an alert. For this purpose, I used a real phishing sample from [phishing_pot](https://github.com/rf-peixoto/phishing_pot) (sample-1261.eml) to keep the simulation as realistic as possible.

The goal of this exercise is to practice my analysis and reporting skills in an environment as realistic as possible, as writing reports is an important part of a SOC Analyst's duty. I chose a phishing sample because phishing represents the main attack vector for initial access ([MITRE ATT&CK – T1566 – Phishing](https://attack.mitre.org/techniques/T1566/)).

*Disclaimer: All data is from a public sample; recipient info masked for privacy.*

## Scenario

It's 13:00, lunch is over and an alert appears in the company's SIEM, the email gateway detected a suspicious email sent to one of the company's employees, containing a file attachment ending in .htm and flagged it. Alexandre, a junior SOC Analyst, takes ownership of the alert. After investigating it, he classifies it as a true positive and sends a phishing analysis report to justify his classification. 

## Methodology and Tools

In this section I will cover the methodology and the tools I used to analyse the phishing sample. For more information and context, please refer to the phishing-analysis-report, as it is more comprehensive.

- **Initial analysis — Thunderbird:** I used **Thunderbird** to open the .eml file and preview the sample for a first-hand analysis. During this review, I noticed discrepancies between the sending address and the email signature, typosquatting techniques used in the sending address, and inconsistencies in the email layout, all of which led me to suspect that the email was used for malicious purposes.

- **Artifact extraction & authentication check — Sublime Text:** I then used **Sublime Text** to extract email artifacts such as the sending server IP and to check the authentication results. I noticed that the SPF result came back as failed, which is a strong indicator that the sending email address was spoofed.

- **IP & geolocation lookup — Whois:** I performed an IP check on **Whois** to find the geolocation of the server used to send the email, and found discrepancies between the location of the server and the location of the company the email was impersonating, which confirmed that an impersonation technique was used for phishing purposes.

- **Hash extraction — Kali Linux command line:** I noticed that the attached file had a double extension, and I used the **Kali Linux command line** to extract the SHA256 hash of the attachment for further analysis.

- **Malware analysis — VirusTotal & Hybrid Analysis:** I analysed the hash on **VirusTotal** and **Hybrid Analysis**, where the file was categorised as malicious on both platforms. I gathered information about the type of malware used in the attack (Beluga) and was able to view a preview of the opened file on **Hybrid Analysis**, which helped me understand the nature of the attack and led me to conclude that it was a credential harvesting attempt.

- **Static code analysis — Kali Linux:** After the results came back as malicious, I proceeded to a static analysis of the file's HTML code to extract the URL used in the POST method of the malware to exfiltrate credentials. I added this URL to the list of IOCs and confirmed the malicious purpose of the attached document.

- **Defensive measures:** In the final section, I present suggested defensive measures such as blocking the sending email address and domain, the file hash of the attachment, and the URL and domain of the website used for credential extraction.

## MITRE ATT&CK Mapping & IOCs gathering

I identified the tactics and techniques used according to the MITRE ATT&CK framework and highlighted them in the MITRE ATT&CK mapping in the analysis section of the report and I also made a recap of the tactics and techniques used below to allow a quick overview for the reader of the report. I also gathered all the IOCs that were found and dedicated a section to it to facilitate their extraction to add them to the threat intelligence program of the fictive company.
