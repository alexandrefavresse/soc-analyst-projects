## Introduction

The phishing analysis report present in this repo was made during a homemade lab and is presented as a simulation of a real phishing report that a SOC Analyst would write after an alert. For this purpose, I used a real phishing sample from [phishing_pot](https://github.com/rf-peixoto/phishing_pot) (sample-1261.eml) to keep the simulation as realistic as possible.

The goal of this exercise is to practice my analysis and reporting skills in an environment as realistic as possible, as writing reports is an important part of a SOC Analyst's duty. I chose a phishing sample because phishing represents the main attack vector for initial access ([MITRE ATT&CK – T1566 – Phishing](https://attack.mitre.org/techniques/T1566/)).

*Disclaimer: All data is from a public sample; recipient info masked for privacy.*

## Scenario

It's 13:00, lunch is over and an alert appears in the company's SIEM, the email gateway detected a suspicious email sent to one of the company's employees, containing a file attachment ending in .htm and flagged it. Alexandre, a junior SOC Analyst, takes ownership of the alert. After investigating it, he classifies it as a true positive and sends a phishing analysis report to justify his classification. 

## Methodology and Tools

In this section I will cover the methodology and the tools I used to analyse the phishing sample, to have more information about it and context, please refer to the phishing-analysis-report as it is more comprehensive.

I used Thunderbird to open the .eml file to have a preview of the sample and make a first-hand analysis, during which I noticed discrepancies between the sending address and the signature of the email and typo squatting techniques used for the sending address and inconsistencies in the email layout, which all lead me to think that the email was used for malicious purposes.

I then used Sublime Text editor to extract the email artifacts such as the sending server IP and also to check the authentication results and I noticed that the SPF results came back as failed, which is a strong indicator that the sending email address was spoofed.

I proceeded to an IP check on whois to find the geolocation of the server used to send the email and found discrepancies between the location of the server and the location of the company the email is trying to impersonate, which confirms that an impersonation technique was used for phishing purposes.

I noticed that the file attached had a double extension and I used the command line on Kali Linux to extract the SHA256 hash of the attached file to later on analyse it on VirusTotal and Hybrid Analysis. 
The file was categorized as malicious on both websites and I gathered information about the type of malware that was used for the attack (Beluga) and I was able to see a preview of the opened file on Hybrid Analysis, which helped to understand what kind of phishing attack it was and it led my to think that it was a credential harvesting attack. 

After the results came back as malicious from these websites, I proceeded to a static analysis of the html code of the file to extract the URL used for the POST method of the malware to extract credentials to add it to the list of the IOCs and confirm the malicious purpose of the attached document.

In the last section I present suggested defensive measures such as blocking the sending email address and domain, the file hash of the attachment and the url and domain of the website used for credentials extraction. 

## MITRE ATT&CK Mapping & IOCs gathering

I identified the tactics and techniques used according to the MITRE ATT&CK framework and highlighted them in the MITRE ATT&CK mapping in the analysis section of the report and I also made a recap of the tactics and techniques used below to allow a quick overview for the reader of the report. I also gathered all the IOCs that were found and dedicated a section to it to facilitate their extraction to add them to the threat intelligence program of the fictive company.
