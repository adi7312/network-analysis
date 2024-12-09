from nfstream import NFStreamer
from report import Report
from scapy.all import *
from ml_model import MLModel
from sigma import Sigma


class Analyzer:

    def __init__(self, malicious_pcap_filename: str, normal_pcap_filename=None) -> None:
        # Requirement A.1
        self.mal_network_flow_stream = NFStreamer(source=malicious_pcap_filename, statistical_analysis=True)
        if normal_pcap_filename is not None:
            self.norm_network_flow_stream = NFStreamer(source=normal_pcap_filename, statistical_analysis=True)
        self.scapy_packets = rdpcap(malicious_pcap_filename)
        self.report = Report()
        self.ml_model = self._build_ml_model()
        self.sigma = Sigma(self.scapy_packets, self.report)
        


    def _build_ml_model(self):
        model = MLModel(self.norm_network_flow_stream, self.mal_network_flow_stream)
        print(model.accuracy)
        self.report.add_ml_info(model.X_train, model.tree_model, model.accuracy, model.conf_matrix, model.recall, model.precision)
    
    
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
            
  

if __name__ == "__main__":
    # mal5.pcap: https://malware-traffic-analysis.net/2024/05/14/index.html
    # normal_traffic.pcap: previous lab
    analyzer = Analyzer(malicious_pcap_filename="mal5.pcap", normal_pcap_filename="normal_traffic.pcap")
    analyzer.get_flow_statistics()
    analyzer.detect_suspicious_domains(["www.rockcreekdds.com", "flexiblemaria.com"])
    analyzer.detect_denial_of_service()
    print(analyzer.report.to_json())