import json
from typing import List, Dict
from uuid import uuid4
import time

class Report:
    def __init__(self):
        self.report_id: str = str(uuid4())
        self.timestamp: int = int(time.time())
        self.alerts: List = []

    def add_alert(self, alert_type: str, alert_title: str, timestamp: int, raw_data: dict):
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
            "alerts": self.alerts
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=4)