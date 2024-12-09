import json
from typing import List, Dict
from uuid import uuid4
import time
from os import environ
import requests
import seaborn as sns
from sklearn.tree import plot_tree
import matplotlib.pyplot as plt
import folium

class Report:
    def __init__(self) -> None:
        self.report_id: str = str(uuid4())
        self.timestamp: int = int(time.time() * 1000)
        self.flow_metadata: List = []
        self.alerts: Dict = {}
        self._ml_info: Dict = {}
        self._suspicious_ips: List = []

    def add_flow_statistic(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str, src2dst_bytes: int, dst2src_bytes: int, bidirectional_bytes: int, bidirectional_packets: int, bidirectional_duration_ms: int, bidirectional_first_seen_ms: int, bidirectional_last_seen_ms: int) -> None:
        flow_statistic = {
            "type": "normal",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "src2dst_bytes": src2dst_bytes,
            "dst2src_bytes": dst2src_bytes,
            "bidirectional_bytes": bidirectional_bytes,
            "bidirectional_packets": bidirectional_packets,
            "bidirectional_duration": bidirectional_duration_ms,
            "bidirectional_first_seen": bidirectional_first_seen_ms,
            "bidirectional_last_seen": bidirectional_last_seen_ms
        }
        self.flow_metadata.append(flow_statistic)

    def add_alert(self, alert_type: str, alert_title: str, timestamp: int, raw_data: Dict) -> None:
        entry = {
            "id": str(uuid4()),
            "title": alert_title,
            "timestamp": timestamp,
            "data": raw_data
        }
        if (alert_type == "MALICIOUS_DNS"):
            self._dns_enrichment(entry)
        self.alerts[alert_type].append(entry) if alert_type in self.alerts else self.alerts.update({alert_type: [entry]})


    def add_ml_info(self, X_train, tree_model, accuracy, confusion_matrix, recall, precision):
        self._ml_info["X_train"] = X_train
        self._ml_info["tree_model"] = tree_model
        self._ml_info["accuracy"] = accuracy
        self._ml_info["confusion_matrix"] = confusion_matrix
        self._ml_info["recall"] = recall
        self._ml_info["precision"] = precision

    def visualize_threats(self):
        threat_count = {}
        for alert_type in self.alerts:
            threat_count[alert_type] = len(self.alerts[alert_type])
        plt.figure(figsize=(10, 5))
        plt.pie(threat_count.values(), labels=threat_count.keys(), autopct="%1.1f%%", startangle=140)
        plt.title("Threats Detected")
        plt.savefig("threats_pie.png")
        plt.show()

    def visualize_ml_tree(self):
        plt.figure(figsize=(20, 10))
        plot_tree(self._ml_info["tree_model"], filled=True, feature_names=self._ml_info["X_train"].columns, class_names=["Normal", "Malicious"])
        plt.title("Decision Tree Classifier")
        plt.savefig("ml_tree.png")
        plt.show()

    def visualize_ml_confusion_matrix(self):
        plt.figure(figsize=(10, 5))
        plt.title("Confusion Matrix")
        sns.heatmap(self._ml_info["confusion_matrix"], annot=True, fmt="d", cmap="Blues")
        plt.xlabel("Predicted")
        plt.ylabel("Actual")
        plt.savefig("confusion_matrix.png")
        plt.show()

    def _dns_enrichment(self, alert: Dict) -> None:
        # Requirement E.1
        domain = alert["data"]["domain"]
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {
            "accept": "application/json",
            "x-apikey": environ.get("VT_API_KEY")
        }
        response = requests.get(url, headers=headers)
        alert["data"]["last_https_certificate"] = response.json()["data"]["attributes"]["last_https_certificate"]
        alert["data"]["whois"] = response.json()["data"]["attributes"]["whois"]
        alert["data"]["last_dns_records"] = response.json()["data"]["attributes"]["last_dns_records"]
        alert["data"]["last_analysis_stats"] = response.json()["data"]["attributes"]["last_analysis_stats"]

    def _get_location(self, ip: str) -> tuple:
        data = requests.get(f"https://geolocation-db.com/json/{ip}&position=true").json()
        return data["latitude"], data["longitude"]
    
    def visualize_threat_map(self):
        map = folium.Map(location = [0.0, 0.0], zoom_start=3, zoom_control=False,scrollWheelZoom=False,dragging=False)
        feature_group = folium.FeatureGroup("Threats")
        for ip in self._suspicious_ips:
            lat, long = self._get_location(ip)
            if type(lat) != float or type(long) != float:
                continue
            feature_group.add_child(folium.Marker([lat, long], popup=ip))
        map.add_child(feature_group)
        map.save("threat_map.html")
                

    def parase_to_md(self):
        title = f"# Network Report {self.report_id}"

    def _ml_readable_info(self):
        return {
            "accuracy": self._ml_info["accuracy"],
            "recall": self._ml_info["recall"],
            "precision": self._ml_info["precision"]
        }

    def to_dict(self) -> Dict:
        return {
            "report_id": self.report_id,
            "timestamp": self.timestamp,
            "flow_metadata": self.flow_metadata,
            "alerts": self.alerts,
            "ml_info": self._ml_readable_info()
        }

    def to_json(self):
        self.visualize_ml_tree()
        self.visualize_ml_confusion_matrix()
        self.visualize_threats()
        self.visualize_threat_map()
        return json.dumps(self.to_dict(), indent=4)