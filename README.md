# PCAP & Phishing Analysis

Hands-on network forensics and phishing analysis portfolio

## Purpose

This repo documents real analysis of malware PCAPs and phishing samples. Each analysis includes attack chain reconstruction, IOC extraction, MITRE ATT&CK mapping, and detection recommendations.

## Contents

### PCAP Analyses

| # | Title | Attack Type | Status |
|---|---|---|---|
| 1 | [Whitehole Exploit Kit](pcaps/analysis-01-whitehole-ek.md) | Drive-by Java exploit | ✅ Complete |

### Phishing Analyses

| # | Title | Attack Type | Status |
|---|---|---|---|
| 1 | *(coming soon)* | | 🚧 |

## Skills demonstrated

- **Wireshark** — display filters, follow streams, export objects
- **PCAP analysis** — reconstruct attack chains, identify IOCs
- **Malware identification** — via Windows Defender + manual analysis
- **Phishing analysis** — email headers, URL inspection, attachment triage
- **Threat intelligence** — MITRE ATT&CK mapping, indicator documentation

## Structure
pcap-phishing-analysis/
├── README.md
├── pcaps/ # PCAP investigations
├── phishing/ # Phishing email analyses
├── filters/ # Wireshark filter cheatsheets
├── iocs/ # Aggregated indicators of compromise
└── screenshots/ # Visual evidence

text

## Notes

All investigation was performed on public malware samples and datasets. No real client or production data is included. Extracted malware is never executed.


