from nfstream import NFStreamer
from src.report import Report
from scapy.all import *
from src.ml_model import MLModel
from src.sigma import Sigma


class AnalyticEngine:

    def __init__(self, malicious_stream: str, normal_stream: str) -> None:
        # Requirement A.1
        self.mal_network_flow_stream = NFStreamer(source=malicious_stream, statistical_analysis=True)
        self.norm_network_flow_stream = NFStreamer(source=normal_stream, statistical_analysis=True)
        self.scapy_packets = rdpcap(malicious_stream)
        self.report = Report()
        self.blacklist = self._load_suspicious_domains()
        self.ml_model = self._build_ml_model()

        self.get_flow_statistics()
        self.detect_suspicious_domains(self.blacklist)
        self.detect_denial_of_service()
        self.sigma = Sigma(self.scapy_packets, self.report)
    

    def _build_ml_model(self):
        model = MLModel(self.norm_network_flow_stream, self.mal_network_flow_stream)
        self.report.add_ml_info(model.X_train, model.tree_model, model.accuracy, model.conf_matrix, model.recall, model.precision)
    
    def _load_suspicious_domains(self):
        with open("src/utils/blacklist.txt") as f:
            return f.readlines()

    def detect_suspicious_domains(self, blacklist):
        # Requirement D.1
        for packet in self.scapy_packets:
            if packet.haslayer(DNS) and packet.qr == 0:
                domain = packet.qd.qname.decode("utf-8")[:-1]
                # check domain wasnt already reported
                if domain in blacklist and self.report.alerts.get("MALICIOUS_DNS") is None:
                    self.report.add_alert("MALICIOUS_DNS", "Malicious domain detected", int(packet.time), {"domain": domain})
                    self.report._suspicious_ips.append(packet[IP].dst)

    def detect_denial_of_service(self):
        reported_ips = []
        for flow in self.mal_network_flow_stream:
            if flow.bidirectional_bytes > 100_000:
                ip_pair = (flow.src_ip, flow.dst_ip)
                if ip_pair not in reported_ips:
                    self.report.add_alert("DOS", "Denial of Service detected", int(flow.bidirectional_first_seen_ms), {"src_ip": flow.src_ip, "dst_ip": flow.dst_ip})
                    reported_ips.append(ip_pair)
                    if flow.src_ip not in self.report._suspicious_ips or flow.dst_ip not in self.report._suspicious_ips:
                        self.report._suspicious_ips.append(flow.src_ip)

    def get_flow_statistics(self):
        # Requirement A.2
        for flow in self.mal_network_flow_stream:
            self.report.add_flow_statistic(
                flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, flow.protocol, 
                flow.src2dst_bytes, flow.dst2src_bytes, flow.bidirectional_bytes, 
                flow.bidirectional_packets, flow.bidirectional_duration_ms, 
                flow.bidirectional_first_seen_ms, flow.bidirectional_last_seen_ms
            )
            
    
