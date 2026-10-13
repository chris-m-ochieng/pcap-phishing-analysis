# IOCs — Whitehole Exploit Kit (2013-12-09)

**Incident:** Drive-by infection via compromised news site
**PCAP source:** malware-traffic-analysis.net (2013-12-09)
**Malware family:** Exploit:Java/Wacole.A
**Analysis file:** [pcaps/analysis-01-whitehole-ek.md](../pcaps/analysis-01-whitehole-ek.md)

---

## Network IOCs

### Attacker IPs

| IP | Role |
|---|---|
| 23.218.156.83 | Compromised news site |
| 88.198.0.59 | Exploit kit landing |
| 217.23.15.220 | Payload delivery server |
| 50.22.134.3 | Ad network redirect |
| 108.168.246.235 | Cleanup redirect host |

### Victim

| IP | Notes |
|---|---|
| 172.16.2.139 | Windows 7 + IE8 workstation |

---

## Domain IOCs

| Domain | Role |
|---|---|
| www.kff1.com | Compromised news site (initial lure) |
| aa1386641701.ponytherabbit.biz | Malicious exploit delivery domain |
| www.dana123.com | Additional ad script domain |
| www.rightmedia.com | Legitimate ad network (used as cover — do not block) |

---

## URL IOCs

### Initial lure

/gnews.php?id=884107-mlb-jeff-francoeur-had-lasik-surgery

### Exploit kit

/web1.php
/temp/support/30f29ae/?cmpid=333333
/temp/support/dj.js
/temp/support/931b3/?java=333333
/temp/support/7e.jar?java=333333
/temp/support/30f29ae/app.jnlp
/index.php?ref=mediaclickinc

### Malware payloads

/temp/333333.exe
/temp/min.exe

---

## File IOCs

| Filename | Size | Notes |
|---|---|---|
| 7e.jar | 8069 B | Java exploit — Exploit:Java/Wacole.A |
| app.jnlp | 75 B | Java Web Start launcher |
| dj.js | 15 KB | JavaScript fingerprinting |
| 333333.exe | (streamed) | Malware dropper |
| min.exe | (streamed) | Second malware |
| TestByteBl.class | (internal) | Class inside 7e.jar |

**Note on hashes:** The PCAP capture does not include full file contents for all payloads. Run extracted files in a sandbox to compute SHA256 hashes.

---

## Campaign identifiers

| Indicator | Value |
|---|---|
| Campaign ID | cmpid=333333 |
| Java marker | ?java=333333 |
| PHPSESSID (victim) | 2hdbgdpv8e3d1sc8po437tcro7 |

---

## User-Agent (victim)

Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)

Identifies: Windows 7 (NT 6.1), 64-bit (WOW64), Internet Explorer 8

---

## Server fingerprints

| Server | Software |
|---|---|
| 88.198.0.59 | Apache/2.2.22 (Ubuntu), PHP/5.3.10-1ubuntu3.8 |
| 217.23.15.220 | nginx/1.2.1, PHP/5.3.3-7+squeeze17 |

---

## Detection rules

### Suricata / IDS

alert http any any -> any any (msg:"Whitehole EK campaign ID"; content:"cmpid=333333"; http_uri; sid:1000001; rev:1;)

alert http any any -> any any (msg:"Whitehole EK Java marker"; content:"?java=333333"; http_uri; sid:1000002; rev:1;)

alert http any any -> any any (msg:"Suspicious .biz redirect"; content:".biz"; http_header; content:"Location"; http_header; sid:1000003; rev:1;)

### Splunk (HTTP proxy logs)

index=proxy http.uri="*cmpid=333333*"
| stats count by src_ip, http.uri

index=proxy http.uri="*ponytherabbit*"
| stats count by src_ip, http.host

### Windows Defender / EDR

- Alert on javaws.exe launching .jnlp files from external URLs
- Alert on file creations named TestByteBl.class
- Alert on outbound connections to 217.23.15.220 or 50.22.134.3
- Alert on executables named 333333.exe or min.exe

---

## MITRE ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1189 | Hidden iframe redirect from compromised site |
| Execution | T1203 | Java exploit (Wacole.A) |
| Execution | T1204.002 | 7e.jar executed via JNLP |
| C2 | T1071.001 | HTTP callbacks to payload server |
| Ingress Tool Transfer | T1105 | 333333.exe, min.exe downloads |
| Defense Evasion | T1036 | Cleanup redirect to rightmedia.com |

---

## References

- malware-traffic-analysis.net — 2013-12-09 Whitehole EK exercise
- Microsoft Threat Encyclopedia — Exploit:Java/Wacole.A
- MITRE ATT&CK — T1189, T1203, T1204, T1105
