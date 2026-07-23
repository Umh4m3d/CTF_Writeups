<div align="center">

# 🛡️ Cybersecurity & DFIR Journey

### Digital Forensics • Incident Response • Threat Hunting • Network Forensics • Offensive Security

**Aymane Es-salehy** ([GitHub](https://github.com/Umh4m3d) • [LinkedIn](https://www.linkedin.com/in/aymane-es-salehy-85b568282/))

![Status](https://img.shields.io/badge/status-actively%20updated-brightgreen)
![Focus](https://img.shields.io/badge/focus-Blue%20Team%20%7C%20DFIR-blue)
![Writeups](https://img.shields.io/badge/writeups-CTF%20%26%20Sherlocks-orange)

</div>

---

## 📌 About This Repository

This repository is my working lab notebook and public portfolio as I build toward a **SOC Analyst / DFIR** career. It documents real, hands-on investigations across network forensics, malware analysis, memory/disk forensics, and offensive security fundamentals.

I document on every Writeup the investigative process — what I looked at, why, what it revealed, and how it maps to a real attack chain — so the work is reproducible and the reasoning is visible, not just the final results.

What you'll find here:

- 🔎 **Forensic investigations** — PCAP analysis, host/memory triage, log and artifact examination
- 🧠 **Malware & threat analysis** — static/dynamic indicators, IOC extraction, C2 behavior in DNS/HTTP(S) traffic
- 🛠️ **Applied tool proficiency** — Wireshark, tshark, Zeek, Volatility, Autopsy, and more (see below)
- 📝 **Structured, professional writeups** — built to be readable by everyone

---

## 🗂️ Repository Structure

| Folder | Contents |
| :--- | :--- |
| [`Hack_The_Box_My_Writeups/Sherlocks_My_Writeups`](Hack_The_Box_My_Writeups/Sherlocks_My_Writeups) | HTB **Sherlocks** DFIR challenge writeups — Windows/Linux forensics, log analysis, incident scenarios |
| [`NORTHSEC26_DFIR`](NORTHSEC26_DFIR) | Writeups from **NorthSec 2026 CTF** DFIR challenges |

New categories (network forensics, malware analysis, OSINT, reverse engineering) are added as challenges are completed — see [Roadmap](#-current-focus--roadmap) below.

---

## 🛠️ Tools & Skills

| Category | Tools / Skills |
| :--- | :--- |
| **Network Forensics** | Wireshark, tshark, tcpdump, Zeek |
| **Malware Analysis** | VirusTotal, `strings`, hexdump, static PE analysis |
| **Memory & Disk Forensics** | Volatility, FTK Imager, Autopsy, Sleuth Kit |
| **Threat Intelligence** | VirusTotal, IOC correlation |
| **SIEM / Log Analysis** | Windows Event Viewer, Sysmon |
| **Offensive Security** | Nmap, Burp Suite, Metasploit, John the Ripper, Hashcat, Hydra |
| **Scripting & Automation** | Python, Bash, PowerShell |

---

## 📝 Writeup Format

Every investigation in this repo follows the same structure, so it reads like an incident report rather than a walkthrough:

1. **Scenario** — Challenge description and context
2. **Executive Summary** — High-level findings, written for a non-technical stakeholder
3. **Task Breakdown** — Question → Answer → Methodology (how the answer was actually derived)
4. **Attack Chain** — Timeline and relationships between hosts, IPs, and actions (where applicable)
5. **Indicators of Compromise (IOCs)** — Actionable, exportable intelligence (IPs, hashes, domains)
6. **Conclusion & Lessons Learned** — What this challenge taught me, and what I'd watch for in a real environment

---

## 🎯 Current Focus & Roadmap

I'm currently building a structured path toward SOC analyst readiness, with a deliberate emphasis on **DNS and HTTP/HTTPS traffic as C2 and malware communication channels** — one of the most common real-world detection surfaces for a Tier 1/2 analyst.

- [x] Network traffic fundamentals — Wireshark/tshark filtering, protocol analysis
- [x] Malware traffic analysis
- [ ] DNS/HTTP(S)-based C2 detection patterns
- [ ] Zeek-based network monitoring workflows
- [ ] SIEM correlation and alert triage
- [ ] Expanded DFIR Sherlocks and CyberDefenders case coverage

Practice is drawn exclusively from free, industry-recognized platforms: **TryHackMe, HackTheBox Sherlocks, CyberDefenders, and Blue Team Labs Online.**

---

## 👤 Why This Repository

I built this repo to make my skill growth **visible and verifiable** — every writeup here is a real investigation I performed, documented the way I'd document it on the real world scenarios.

---

## 📄 License

This repository is for educational and portfolio purposes only. All challenges, platforms, and CTF content referenced remain the property of their respective owners.

---

<div align="center">

📬 **Let's connect:** [GitHub](https://github.com/Umh4m3d) • [LinkedIn](https://www.linkedin.com/in/aymane-es-salehy-85b568282/)

*"Amateurs hack systems, professionals hack people... but analysts read the logs." — Not Important*

</div>
