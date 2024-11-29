import json
from typing import List, Dict
from uuid import uuid4
import time

class Report:
    def __init__(self) -> None:
        self.report_id: str = str(uuid4())
        self.timestamp: int = int(time.time())
        self.flow_metadata: List = []
        self.alerts: List = []

    def add_flow_statistic(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str, src2dst_bytes: int, dst2src_bytes: int, bidirectional_bytes: int, bidirectional_packets: int, bidirectional_duration_ms: int, bidirectional_first_seen_ms: int, bidirectional_last_seen_ms: int) -> None:
        flow_statistic = {
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
            "type": alert_type,
            "title": alert_title,
            "timestamp": timestamp,
            "data": raw_data
        }
        self.alerts.append(entry)


    def to_dict(self) -> Dict:
        return {
            "report_id": self.report_id,
            "timestamp": self.timestamp,
            "flow_metadata": self.flow_metadata,
            "alerts": self.alerts
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=4)