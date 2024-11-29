from nfstream import NFStreamer
from report import Report
from scapy.all import *
import time


class Analyzer:
    def __init__(self, pcap_filename: str) -> None:
        self.network_flow_stream = NFStreamer(source=pcap_filename)
        self.scapy_packets = rdpcap(pcap_filename)
        self.report = Report()
    
    def detect_suspicious_domains(self, blacklist):
        for packet in self.scapy_packets:
            if packet.haslayer(DNS) and packet.qr == 0:
                domain = packet.qd.qname.decode("utf-8")[:-1]
                if domain in blacklist:
                    self.report.add_alert("MALICIOUS", "Malicious domain detected", int(packet.time), {"domain": domain})
    
    
    def get_flow_statistics(self):
        for flow in self.network_flow_stream:
            self.report.add_flow_statistic(
                flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, flow.protocol, 
                flow.src2dst_bytes, flow.dst2src_bytes, flow.bidirectional_bytes, 
                flow.bidirectional_packets, flow.bidirectional_duration_ms, 
                flow.bidirectional_first_seen_ms, flow.bidirectional_last_seen_ms
                )
    

if __name__ == "__main__":
    analyzer = Analyzer("test.pcap")
    analyzer.get_flow_statistics()
    analyzer.detect_suspicious_domains(["madmrx.duckdns.org"])
    print(analyzer.report.to_json())
        