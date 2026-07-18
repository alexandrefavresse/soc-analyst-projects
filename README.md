# soc-analyst-projects
Hello! 

Welcome to my GitHub portfolio, where I share cybersecurity projects from my learning journey as an aspiring SOC Analyst. Want to connect or recruit? Find me on [LinkedIn](https://www.linkedin.com/in/alexandrefavresse/).

Below you'll find two writeups I've published. Each report follows a structure similar to what a SOC Analyst would produce in a real investigation, from initial alert triage through to actionable defensive recommendations.

- **[Network Traffic Investigation Report](https://github.com/alexandrefavresse/soc-analyst-projects/blob/main/writeups/network-analysis/network-traffic-investigation-report.md)** — Using **Wireshark**, I analysed a .pcap file to reconstruct a web attack in which the attacker used SQL injection to extract admin credentials from the web server's database, then attempted Remote Code Execution via a PHP reverse shell. The report documents each investigative step and concludes with defensive measures to remediate the impact of the attack and prevent similar attacks in the future.

- **[Phishing Analysis Report](https://github.com/alexandrefavresse/soc-analyst-projects/blob/main/writeups/phishing/phishing-analysis-report.md)** — An analysis of a real phishing email sample, classified as a credential harvester leveraging techniques such as typosquatting, a double file extension, and a fake Excel reader web portal to capture victim credentials. I conducted the analysis by extracting the **email artifacts** and using **VirusTotal**, **Hybrid Analysis**, and **Whois**, along with a **static code analysis** of the malicious file. The report concludes with recommended defensive measures.
