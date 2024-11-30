import os
from nfstream import NFStreamer
from report import Report
from scapy.all import *
from sigma.collection import SigmaCollection


class Analyzer:

    def __init__(self, pcap_filename: str) -> None:
        # Requirement A.1
        self.network_flow_stream = NFStreamer(source=pcap_filename)
        self.scapy_packets = rdpcap(pcap_filename)
        self.report = Report()
        self.sigma_content: List = self._load_sigma_rules("sigma_rules")
    
    def _load_sigma_rules(self, sigma_rules_path):
        # Requirement D.2
            sigma_content: List = []
            for filename in os.listdir(sigma_rules_path):
                if filename.endswith(".yml") or filename.endswith(".yaml"):
                    with open(os.path.join(sigma_rules_path, filename), "r") as f:
                        sigma_rule = SigmaCollection.from_yaml(f)
                        sigma_content.append(sigma_rule.rules)      
            self.sigma_content = sigma_content
    
    def detect_suspicious_domains(self, blacklist):
        # Requirement D.1
        for packet in self.scapy_packets:
            if packet.haslayer(DNS) and packet.qr == 0:
                domain = packet.qd.qname.decode("utf-8")[:-1]
                if domain in blacklist:
                    self.report.add_alert("MALICIOUS_DNS", "Malicious domain detected", int(packet.time), {"domain": domain})

    def apply_sigma_rules(self):
        # Requirement D.2
        pass
    
    def get_flow_statistics(self):
        # Requirement A.2
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