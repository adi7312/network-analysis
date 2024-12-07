import yaml 
from scapy.all import *

class Sigma:
    def __init__(self, scapy_packets, report):
        self.scapy_packets = scapy_packets
        self.report = report
        self._apply_sigma_posh_rule()
    
    def _load_sigma_posh_rule(self, sigma_rules_path="sigma_rules/detect_powershell_http.yml"):
        # Requirement D.2
        with open(sigma_rules_path) as f:
            try:
                sigma_content = yaml.safe_load(f)
            except yaml.YAMLError as exc:
                print(exc)
        return sigma_content

    def _apply_sigma_posh_rule(self):
        findings = []
        rule = self._load_sigma_posh_rule()
        for packet in self.scapy_packets:
            if packet.haslayer(Raw) and TCP in packet:
                if packet[TCP].sport == 80 and len(packet[TCP].payload) < 500:
                    try:
                        raw_data = packet[Raw].load.decode("utf-8")
                    except:
                        continue
                    if rule.get("detection"):
                        for command in rule["detection"]["selection"]["CommandLine|contains"]:
                            if command in raw_data:
                                self.report.add_alert("COMMAND_EXECUTION", "Command execution detected by Sigma", int(packet.time), {"rule": rule["title"], "command": command})
                                break