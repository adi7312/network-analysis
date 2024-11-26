from nfstream import NFStreamer


class Analyzer:
    def __init__(self, pcap_filename: str) -> None:
        self.pcap_filename = pcap_filename
    
    def _load_pcap_file(self) -> NFStreamer:
        return NFStreamer(self.pcap_filename)