# PCAP Raider - PCAP Analysis CLI Tool

## Project Overview
This project provides an interactive command-line interface (CLI) tool for analysing PCAP files. It allows users to load PCAP files, perform advanced packet analysis, and get feedback on specific queries.

## Features
- Load and analyse PCAP files
- Display summary and detailed packet information
- Filter packets by criteria
- Inspect specific packets
- Protocol analysis (HTTP, DNS, TCP, UDP)
- Statistics and metrics extraction
- Detect anomalies and suspicious activities

## Technologies Used
- Python
- Scapy
- cmd module for CLI

## Setup Instructions
1. **Set Up Environment:**
   - Install Virtualization software (VMWare or Virtualbox) and set up a Linux VM.

2. **Install Required Tools:**
   - Python and Pip: `sudo apt install python3 python3-pip`
   - Scapy: `pip3 install scapy`

3. **Create and Run the CLI Tool:**
   - Create a project directory and add `pcap_raider.py`.
   - Run the tool: `python3 pcap_raider.py`
