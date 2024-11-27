from nfstream import NFStreamer
from report import Report
import time


class Analyzer:
    def __init__(self, pcap_filename: str) -> None:
        self.packet_stream = NFStreamer(source=pcap_filename)
        self.report = Report()
    
    def detect_large_traffic(self):
        for flow in self.packet_stream:
            if ((flow.dst_port == 443 or
                flow.dst_port == 80) and 
                flow.src2dst_bytes > 1000000):
                self.report.add_alert("WARNING", "Large Traffic Detected", flow.bidirectional_first_seen_ms, {"flow": "data"})
    

if __name__ == "__main__":
    analyzer = Analyzer("test.pcap")
    analyzer.detect_large_traffic()
    print(analyzer.report.to_json())
        