# PCAP Raider - PCAP Analysis CLI Tool

## Project Overview
PCAP Raider is an interactive command-line interface (CLI) tool for analyzing PCAP files. It allows users to load PCAP files, perform advanced packet analysis, and get feedback on specific queries. The tool is designed to be useful for anyone learning or using networking.

## Features
- **Load and Analyze PCAP Files**: Load PCAP files for detailed analysis.
- **Display Summary**: View a summary of the captured data, including total packets, duration, and top protocols.
- **Inspect Packets**: Inspect detailed information and payloads of specific packets.
- **HTTP Requests and DNS Queries**: List all HTTP requests and DNS queries found in the PCAP file.
- **Statistics**: Display various statistics about the packets, including protocol distribution.
- **Stream Reconstruction**: Reconstruct TCP streams to analyze full conversations.
- **Apply Filters**: Focus on specific traffic using custom filters.
- **Save Filtered Packets**: Save filtered packets to a new PCAP file.
- **Export to CSV**: Export packet summaries to a CSV file.
- **Exit**: Exit the PCAP Raider CLI tool.

## Technologies Used
- Python
- Scapy
- cmd module for CLI

## Setup Instructions
1. **Set Up Environment:**
   - Install VirtualBox and set up a Kali Linux VM.

2. **Install Required Tools:**
   - Python and Pip: `sudo apt install python3 python3-pip`
   - Scapy: `pip3 install scapy`

3. **Create and Run the CLI Tool:**
   - Create a project directory and add `pcap_raider.py`.
   - Run the tool: `python3 pcap_raider.py`

## Usage
1. **Load a PCAP File:**
   ```shell
   pcap_raider> load <filepath>
