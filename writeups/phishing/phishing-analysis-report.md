# Phishing analysis report:

Analyst: Alexandre Favresse

Date of Analysis: 06-07-2026

Report ID: PHISH-2026-001

Classification: Malicious (credential harvesting phishing email)

Severity: High

Confidence: High (VirusTotal, Hybrid Analysis, SPF fail, typosquat)


## Section 1 : Alert Context



## Section 2: Investigation Methodology

## Section 3: Timeline of Events

## Section 4: Findings & Impact


## Section 4: IOCs


| Type             | Indicator of compromise                                          |
| ---------------- | ---------------------------------------------------------------- |
| Sender address   | info[@]hosngpackingss[.]com                                      |
| File name        | PO45638 - PO76483.Xls.htm                                        |
| File SHA256 hash | 932e18daa8184ed41735e136cf0d7c148295064153e653ada7d79e8e80216d72 |
| URL              | hxxps://glottogonic-depende[.]000webhostapp[.]com/Excel.php      |
| Domain           | glottogonic-depende[.]000webhostapp[.]com                        |


## Section 5: MITRE ATT&CK Mapping


| Tactic          | Technique ID | Technique Name                      |
| --------------- | ------------ | ----------------------------------- |
| Initial Access  | T1566.001    | Phishing: Spearphishing Attachment  |
| Defense Evasion | T1027.006    | Obfuscated Files: HTML Smuggling    |
| Defense Evasion | T1036.007    | Masquerading: Double File Extension |
| Defense Evasion | T1656        | Impersonation                       |
| Collection      | T1056.003    | Input Capture: Web Portal Capture   |




## Section 6: Suggested Defensive Measures:




