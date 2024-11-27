from nfstream import NFStreamer
from report import Report
import time


class Analyzer:
    def __init__(self, pcap_filename: str) -> None:
        self.packet_stream = NFStreamer(source=pcap_filename)
        self.report = Report()
    
    def detect_large_traffic(self):
        if ((self.packet_stream.destination_port == 443 or
            self.packet_stream.destination_port == 80) and 
            self.packet_stream.bytes > 1000000):
            self.report.add_alert("WARNING", "Large Traffic Detected", self.packet_stream.timestamp, self.packet_stream.to_dict())
    

if __name__ == "__main__":
    analyzer = Analyzer("test.pcap")
    analyzer.detect_large_traffic()
    print(analyzer.report.to_json())
        