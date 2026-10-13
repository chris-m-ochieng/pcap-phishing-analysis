# Wireshark Filter Cheatsheet

A reference of display filters used during PCAP analysis in this repo. 

## Core protocol filters

| Filter | Shows |
|---|---|
| http | Only HTTP traffic |
| dns | Only DNS queries and responses |
| tls | Only TLS handshakes |
| tcp | Only TCP packets |
| udp | Only UDP packets |
| icmp | Only ICMP packets |

## HTTP filters

| Filter | Shows |
|---|---|
| http.request | Only HTTP requests |
| http.response | Only HTTP responses |
| http.request.method == "GET" | Only HTTP GET requests |
| http.request.method == "POST" | Only HTTP POST requests |
| http.response.code == 200 | Only successful responses |
| http.response.code == 302 | Only redirects |
| http.host == "example.com" | Traffic to/from a specific host |
| http contains "keyword" | HTTP packets containing a string |

## TCP filters

| Filter | Shows |
|---|---|
| tcp.flags.syn == 1 && tcp.flags.ack == 0 | TCP SYN packets (connection starts) |
| tcp.flags.reset == 1 | TCP RST packets (connection resets) |
| tcp.flags.fin == 1 | TCP FIN packets (connection closes) |
| tcp.stream eq N | Only TCP stream number N |
| tcp.port == 80 | Traffic on port 80 |
| tcp.port == 443 | Traffic on port 443 |

## IP filters

| Filter | Shows |
|---|---|
| ip.addr == 1.2.3.4 | Traffic involving a specific IP (either direction) |
| ip.src == 1.2.3.4 | Traffic from a specific IP |
| ip.dst == 1.2.3.4 | Traffic to a specific IP |
| ip.addr == 1.2.3.4 && ip.addr == 5.6.7.8 | Traffic between two specific IPs |

## Logic operators

| Operator | Meaning |
|---|---|
| && or and | Both conditions true |
| \|\| or or | Either condition true |
| ! or not | Negate the condition |
| eq or == | Equals |
| ne or != | Not equal |
| contains | Substring match |

## Frame-level search

| Filter | Shows |
|---|---|
| frame contains "keyword" | Packets with keyword anywhere in raw bytes |

## Combined examples

Find all HTTP POST requests to a specific host:

http.request.method == "POST" && http.host == "example.com"

Find all traffic from one IP that is not DNS:

ip.src == 172.16.2.139 && !dns

Find all TCP streams that have had a reset:

tcp.flags.reset == 1

Find HTTP traffic to a specific domain:

http.host contains "example"



