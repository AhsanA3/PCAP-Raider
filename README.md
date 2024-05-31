# PCAP Raider - Advanced PCAP Analysis CLI Tool (Under Development)

## Project Overview
PCAP Raider is an interactive command-line interface (CLI) tool for analyzing PCAP files. It allows users to load PCAP files, perform advanced packet analysis, and get feedback on specific queries. The tool is designed to be useful for network administrators, NOC, or SOC analysts.

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
   - Install Virtualization software (VMWare or Virtualbox) and set up a Linux VM.

2. **Install Required Tools:**
   - Python
   - Scapy

3. **Create and Run the CLI Tool:**
   - Create a project directory and add `pcap_raider.py`.
   - Run the tool: `python3 pcap_raider.py`

## Usage
Detailed usage instructions can be found in the [USAGE.md](USAGE.md) file.

## Quick Start
To quickly get started, use the following commands:

1. Clone the repository:

    ```bash
    git clone https://github.com/AhsanA3/PCAP-Raider.git
    ```

2. Navigate to the project directory:

    ```bash
    cd PCAP-Raider
    ```

3. Run the CLI tool:

    ```bash
    python3 pcap_raider.py
    ```

## License
This project is licensed under the MIT License. See the [LICENSE](https://github.com/AhsanA3/PCAP-Raider/blob/main/LICENSE) file for details.

## Authors
- [Ahsan Akoshile](https://github.com/AhsanA3)
- [Bilal Lawal Alhassan](https://github.com/1bilal)

