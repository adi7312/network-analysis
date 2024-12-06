import os
from nfstream import NFStreamer
from report import Report
from scapy.all import *
from sigma.collection import SigmaCollection
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.model_selection import cross_val_score


class Analyzer:

    def __init__(self, malicious_pcap_filename: str, normal_pcap_filename=None) -> None:
        # Requirement A.1
        self.mal_network_flow_stream = NFStreamer(source=malicious_pcap_filename, statistical_analysis=True)
        if normal_pcap_filename is not None:
            self.norm_network_flow_stream = NFStreamer(source=normal_pcap_filename, statistical_analysis=True)
        self.scapy_packets = rdpcap(malicious_pcap_filename)
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
                # check domain wasnt already reported
                if domain in blacklist and self.report.alerts.get("MALICIOUS_DNS") is None:
                    self.report.add_alert("MALICIOUS_DNS", "Malicious domain detected", int(packet.time), {"domain": domain})

    def detect_denial_of_service(self):
        reported_ips = []
        for flow in self.mal_network_flow_stream:
            if flow.bidirectional_bytes > 100_000:
                ip_pair = (flow.src_ip, flow.dst_ip)
                if ip_pair not in reported_ips:
                    self.report.add_alert("DOS", "Denial of Service detected", int(flow.bidirectional_first_seen_ms), {"src_ip": flow.src_ip, "dst_ip": flow.dst_ip})
                    reported_ips.append(ip_pair)


    def apply_sigma_rules(self):
        # Requirement D.2
        pass
    
    def get_flow_statistics(self):
        # Requirement A.2
        for flow in self.mal_network_flow_stream:
            self.report.add_flow_statistic(
                flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, flow.protocol, 
                flow.src2dst_bytes, flow.dst2src_bytes, flow.bidirectional_bytes, 
                flow.bidirectional_packets, flow.bidirectional_duration_ms, 
                flow.bidirectional_first_seen_ms, flow.bidirectional_last_seen_ms
            )
            
    def _prepare_data(self):
        # Requirement ML.1
        normal_flows = self.norm_network_flow_stream.to_pandas()
        normal_flows["label"] = 0
        malicious_flows = self.mal_network_flow_stream.to_pandas()
        malicious_flows["label"] = 1
        data = pd.concat([normal_flows, malicious_flows], ignore_index=True)
        for col in data.columns:
            if data[col].nunique() == 1 or data[col].isnull().any():
                data.drop(columns=[col], inplace=True, axis=1)

        data = data.select_dtypes(include=[np.number])

        X = data.drop(columns=["label"], axis=1)
        Y = data["label"]

        X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.4, random_state=42)
        return X_train, X_test, Y_train, Y_test
    
    def train_model(self, max_depth=3, criterion="gini", min_samples_split=5, min_samples_leaf=2):
        # Requirement ML.1 + ML.2
        X_train, X_test, Y_train, Y_test = self._prepare_data()
        
        
        tree_model = DecisionTreeClassifier(
            max_depth=max_depth,  
            criterion=criterion,
            min_samples_split=min_samples_split,
            min_samples_leaf=min_samples_leaf,
            random_state=42,
            ccp_alpha=0.01
        )
        
        tree_model.fit(X_train, Y_train)
        
        predictions = tree_model.predict(X_test)
        accuracy = accuracy_score(Y_test, predictions)
        conf_matrix = confusion_matrix(Y_test, predictions)
        recall = conf_matrix[1][1] / (conf_matrix[1][0] + conf_matrix[1][1])
        precision = conf_matrix[1][1] / (conf_matrix[0][1] + conf_matrix[1][1])
        self.report.add_ml_info(X_train, tree_model, accuracy, conf_matrix, recall, precision)
        
        
        return tree_model, accuracy, conf_matrix
    

    

if __name__ == "__main__":
    # mal5.pcap: https://malware-traffic-analysis.net/2024/05/14/index.html
    # normal_traffic.pcap: previous lab
    analyzer = Analyzer(malicious_pcap_filename="mal5.pcap", normal_pcap_filename="normal_traffic.pcap")
    analyzer.get_flow_statistics()
    analyzer.detect_suspicious_domains(["www.rockcreekdds.com", "flexiblemaria.com"])
    analyzer.detect_denial_of_service()
    analyzer.train_model()
    print(analyzer.report.to_json())