from nfstream import NFStreamer
from src.report import Report
from scapy.all import *
from src.ml_model import MLModel, ModelPrediction
from src.sigma import Sigma


class AnalyticEngine:
    def __init__(self, input_stream: str, is_live: bool, ml_normal_stream, ml_malicious_stream) -> None:
        # Requirement A.1
        self.report = Report()
        self.model = self._build_ml_model("src/utils/normal_traffic.pcap", "src/utils/malicious_traffic.pcap")
        if ml_malicious_stream != "" and ml_normal_stream != "":
            self.model.retrain_model(ml_normal_stream, ml_malicious_stream)
        self.input_stream = NFStreamer(source=input_stream, 
                                       idle_timeout=1,
                                       active_timeout=1,
                                       udps=ModelPrediction(my_model=self.model.tree_model), 
                                       statistical_analysis=True
                                       )
        self.get_flow_statistics()
        self.detect_exfiltration()
        if is_live:
            self.scapy_packets = sniff()
        else: 
            self.scapy_packets = rdpcap(input_stream)

        self.blacklist = self._load_suspicious_domains()
        self.detect_suspicious_domains(self.blacklist)
        self.sigma = Sigma(self.scapy_packets, self.report)
   
     

    def _build_ml_model(self, normal_stream, malicious_stream):
        norm_network_flow_stream = NFStreamer(source=normal_stream, statistical_analysis=True)
        mal_network_flow_stream = NFStreamer(source=malicious_stream, statistical_analysis=True)
        model = MLModel(norm_network_flow_stream, mal_network_flow_stream)
        self.report.add_ml_info(model.X_train, model.tree_model, model.accuracy, model.conf_matrix, model.recall, model.precision)
        return model
    
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

    def detect_exfiltration(self, threshold=1000):
        reported_ips = []
        for flow in self.input_stream:
            if flow.src2dst_bytes > threshold:
                ip_pair = (flow.src_ip, flow.dst_ip)
                if ip_pair not in reported_ips:
                    self.report.add_alert(
                        "EXFILTRATION", 
                        "High volume traffic detected to suspicious IP", 
                        int(flow.bidirectional_first_seen_ms),
                          {"src_ip": flow.src_ip, "dst_ip": flow.dst_ip}
                          )
                    reported_ips.append(ip_pair)
                    if flow.src_ip not in self.report._suspicious_ips or flow.dst_ip not in self.report._suspicious_ips:
                        self.report._suspicious_ips.append(flow.dst_ip)

    def get_flow_statistics(self):
        # Requirement A.2
        for flow in self.input_stream:
            self.report.add_flow_statistic(
                flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, flow.protocol, 
                flow.src2dst_bytes, flow.dst2src_bytes, flow.bidirectional_bytes, 
                flow.bidirectional_packets, flow.bidirectional_duration_ms, 
                flow.bidirectional_first_seen_ms, flow.bidirectional_last_seen_ms, flow.udps.model_prediction
            )
            
    
