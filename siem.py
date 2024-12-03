import requests
import json

class SIEM:
    # Initialize SIEM
    def __init__(self, URL, index, username, password):
        self.URL = URL
        self.index = index
        self.username = username
        self.password = password

    def query_log(self, hostname, log):
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"host.name" : hostname}},
                        {"match": {"log.file.path": log}}
                    ]
                }
            }
        }
        endpoint = f"{self.URL}/{self.index}/_search"

        response = requests.post(
            endpoint,
            headers={"Content-Type":"application/json"},
            auth=(self.username, self.password),
            data=json.dumps(query)
        )
        response.raise_for_status()
        # Retrieved logs successfully
        return response.json()

        