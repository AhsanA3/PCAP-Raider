import os
import scapy.all as scapy
from cmd import Cmd
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import TCP, IP, UDP
from urllib.parse import urlparse

class PcapRaider(Cmd):
    prompt = "pcap_raider> "
    intro = "Welcome to the PCAP Raider CLI tool! Type ? to list commands."

    def do_load(self, filepath):
        """Load a PCAP file: load <filepath>

        Load a PCAP file for analysis. Provide either a standard file path
        or a URL-style path.
        """
        parsed_url = urlparse(filepath)
        if parsed_url.scheme == "file":
            filepath = parsed_url.path

        if not os.path.isfile(filepath):
            print(f"File {filepath} does not exist.")
            return
        self.packets = scapy.rdpcap(filepath)
        print(f"Loaded {len(self.packets)} packets from {filepath}")

    def do_summary(self, line):
        """Print a summary of the loaded PCAP file

        Display a summary of the captured data, including total packets, 
        duration, and top protocols.
        """
        if not hasattr(self, 'packets'):
            print("No PCAP file loaded. Use the 'load' command first.")
            return

        total_packets = len(self.packets)
        start_time = self.packets[0].time
        end_time = self.packets[-1].time
        duration = end_time - start_time

        protocol_counts = {}
        for pkt in self.packets:
            proto = pkt.sprintf("%IP.proto%")
            if proto not in protocol_counts:
                protocol_counts[proto] = 0
            protocol_counts[proto] += 1

        top_protocols = sorted(protocol_counts.items(), key=lambda item: item[1], reverse=True)

        print(f"Total packets: {total_packets}")
        print(f"Duration: {duration} seconds")
        print("Top protocols:")
        for proto, count in top_protocols:
            print(f"  {proto}: {count}")

    def do_inspect(self, pkt_num):
        """Inspect a specific packet by its number: inspect <packet_number>

        Display detailed information about a specific packet identified
        by its number.
        """
        if not hasattr(self, 'packets'):
            print("No PCAP file loaded. Use the 'load' command first.")
            return
        try:
            pkt_num = int(pkt_num)
            pkt = self.packets[pkt_num]
            pkt.show()
        except (IndexError, ValueError):
            print("Invalid packet number")

    def do_inspect_payload(self, pkt_num):
        """Inspect the payload of a specific packet: inspect_payload <packet_number>

        Display the payload data of a specific packet identified by its number.
        """
        if not hasattr(self, 'packets'):
            print("No PCAP file loaded. Use the 'load' command first.")
            return
        try:
            pkt_num = int(pkt_num)
            pkt = self.packets[pkt_num]
            if pkt.haslayer(TCP):
                print(bytes(pkt[TCP].payload))
            else:
                print("No TCP payload found in this packet.")
        except (IndexError, ValueError):
            print("Invalid packet number")

    def do_http_requests(self, line):
        """List all HTTP requests in the loaded PCAP file

        Display all HTTP requests found in the loaded PCAP file.
        """
        if not hasattr(self, 'packets'):
            print("No PCAP file loaded. Use the 'load' command first.")
            return
        http_requests = [pkt for pkt in self.packets if pkt.haslayer(HTTPRequest)]
        print(f"Found {len(http_requests)} HTTP requests")
        for pkt in http_requests:
            print(pkt[HTTPRequest].Host, pkt[HTTPRequest].Path)

    def do_dns_queries(self, line):
        """List all DNS queries in the loaded PCAP file

        Display all DNS queries found in the loaded PCAP file.
        """
        if not hasattr(self, 'packets'):
            print("No PCAP file loaded. Use the 'load' command first.")
            return
        dns_queries = [pkt for pkt in self.packets if pkt.haslayer(DNS) and pkt[DNS].qd]
        print(f"Found {len(dns_queries)} DNS queries")
        for pkt in dns_queries:
            print(pkt[DNSQR].qname)

    def do_statistics(self, line):
        """Display statistics of the loaded PCAP file

        Show various statistics about the packets in the loaded PCAP file,
        including total packets and protocol distribution.
        """
        if not hasattr(self, 'packets'):
            print("No PCAP file loaded. Use the 'load' command first.")
            return
        stats = {
            "total_packets": len(self.packets),
            "protocols": {},
        }
        for pkt in self.packets:
            proto = pkt.__class__.__name__
            if proto not in stats["protocols"]:
                stats["protocols"][proto] = 0
            stats["protocols"][proto] += 1
        print("Statistics:")
        print(f"Total Packets: {stats['total_packets']}")
        print("Protocols:")
        for proto, count in stats["protocols"].items():
            print(f"  {proto}: {count}")

    def do_reconstruct_stream(self, line):
        """Reconstruct TCP streams: reconstruct_stream <IP>

        Follow TCP streams to reconstruct full conversations and analyze
        the data exchanged in a particular session.
        """
        if not hasattr(self, 'packets'):
            print("No PCAP file loaded. Use the 'load' command first.")
            return

        sessions = self.packets.sessions()
        for session in sessions:
            if line in session:
                print(f"Stream {session}:")
                for packet in sessions[session]:
                    try:
                        if packet.haslayer(TCP):
                            print(bytes(packet[TCP].payload))
                    except:
                        continue

    def do_filter(self, line):
        """Apply filters to focus on specific traffic: filter <expression>

        Set up filters to focus on specific traffic of interest, such as
        traffic to/from a particular IP address or port.
        """
        if not hasattr(self, 'packets'):
            print("No PCAP file loaded. Use the 'load' command first.")
            return

        filtered_packets = [pkt for pkt in self.packets if eval(line)]
        print(f"Found {len(filtered_packets)} packets with filter '{line}'")
        for pkt in filtered_packets:
            print(pkt.summary())

    def do_save_filtered(self, line):
        """Save filtered packets to a new PCAP file: save_filtered <filter expression> <output file>

        Apply a filter and save the matching packets to a new PCAP file.
        """
        if not hasattr(self, 'packets'):
            print("No PCAP file loaded. Use the 'load' command first.")
            return

        try:
            filter_expr, output_file = line.split(' ', 1)
        except ValueError:
            print("Usage: save_filtered <filter expression> <output file>")
            return

        filtered_packets = [pkt for pkt in self.packets if eval(filter_expr)]
        scapy.wrpcap(output_file, filtered_packets)
        print(f"Saved {len(filtered_packets)} filtered packets to {output_file}")

    def do_export_csv(self, line):
        """Export packet summary to a CSV file: export_csv <output file>

        Export a summary of each packet to a CSV file.
        """
        if not hasattr(self, 'packets'):
            print("No PCAP file loaded. Use the 'load' command first.")
            return

        try:
            output_file = line
        except ValueError:
            print("Usage: export_csv <output file>")
            return

        with open(output_file, 'w') as f:
            f.write("No.,Timestamp,Source,Destination,Protocol,Length\n")
            for i, pkt in enumerate(self.packets):
                ts = pkt.time
                src = pkt[IP].src if pkt.haslayer(IP) else 'N/A'
                dst = pkt[IP].dst if pkt.haslayer(IP) else 'N/A'
                proto = pkt.sprintf("%IP.proto%")
                length = len(pkt)
                f.write(f"{i},{ts},{src},{dst},{proto},{length}\n")
        print(f"Exported packet summary to {output_file}")

    def do_exit(self, line):
        """Exit the CLI

        Exit the PCAP Raider CLI tool.
        """
        print("Exiting...")
        return True

    def do_help(self, line):
        """Display the list of commands with descriptions

        Show detailed help for each command.
        """
        commands = [
            ("load", "Load a PCAP file for analysis. Provide either a standard file path or a URL-style path."),
            ("summary", "Display a summary of the captured data, including total packets, duration, and top protocols."),
            ("inspect", "Inspect a specific packet by its number."),
            ("inspect_payload", "Display the payload data of a specific packet identified by its number."),
            ("http_requests", "Display all HTTP requests found in the loaded PCAP file."),
            ("dns_queries", "Display all DNS queries found in the loaded PCAP file."),
            ("statistics", "Show various statistics about the packets in the loaded PCAP file, including total packets and protocol distribution."),
            ("reconstruct_stream", "Follow TCP streams to reconstruct full conversations and analyze the data exchanged in a particular session."),
            ("filter", "Set up filters to focus on specific traffic of interest, such as traffic to/from a particular IP address or port."),
            ("save_filtered", "Apply a filter and save the matching packets to a new PCAP file."),
            ("export_csv", "Export a summary of each packet to a CSV file."),
            ("exit", "Exit the PCAP Raider CLI tool.")
        ]
        print("\nDocumented commands (type help <topic>):")
        print("========================================")
        for cmd, desc in commands:
            print(f"{cmd:<20} {desc}")

if __name__ == '__main__':
    PcapRaider().cmdloop()
