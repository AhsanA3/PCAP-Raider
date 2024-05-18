# PCAP Raider - Usage Guide

This document provides detailed instructions for using each command in the PCAP Raider CLI tool.

## Commands

### 1. Load a PCAP File
Load a PCAP file for analysis. You can use either a standard file path or a URL-style path.
```shell
pcap_raider> load <filepath>
```

### 2. Display Summary of Loaded PCAP File
View a summary of the captured data, including total packets, duration, and top protocols.
```shell
pcap_raider> summary
```
### 3. Inspect Specific Packets
Inspect detailed information about a specific packet identified by its number.
```shell
pcap_raider> inspect <packet_number>
```
### 4. Inspect Packet Payload
Display the payload data of a specific packet identified by its number.
```shell
pcap_raider> inspect_payload <packet_number>
```
### 5. List HTTP Requests
List all HTTP requests found in the loaded PCAP file.
```shell
pcap_raider> http_requests
```
### 6. List DNS Queries
List all DNS queries found in the loaded PCAP file.
```shell
pcap_raider> dns_queries
```
### 7. Display Statistics
Show various statistics about the packets in the loaded PCAP file, including total packets and protocol distribution.
```shell
pcap_raider> statistics
```
### 8. Reconstruct TCP Streams
Follow TCP streams to reconstruct full conversations and analyze the data exchanged in a particular session.
```shell
pcap_raider> reconstruct_stream <IP>
```
### 9. Apply Filters
Set up filters to focus on specific traffic of interest, such as traffic to/from a particular IP address or port.
```shell
pcap_raider> filter <expression>
```
### 10. Save Filtered Packets
Apply a filter and save the matching packets to a new PCAP file.
```shell
pcap_raider> save_filtered <filter expression> <output file>
```
### 11. Export Packet Summary to CSV
Export a summary of each packet to a CSV file.
```shell
pcap_raider> export_csv <output file>
```
### 12. Exit the CLI
Exit the PCAP Raider CLI tool.
```shell
pcap_raider> exit
```
