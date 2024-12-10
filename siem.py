import datetime
import os
from elasticsearch import Elasticsearch


class SIEM:
    # Initialize SIEM
    def __init__(self, URL, index, username, password):
        self.client = Elasticsearch(f"{URL}", basic_auth=(username, password), verify_certs=False)
        self.index = index
        self.username = username
        self.password = password
    
    # TODO: https://www.elastic.co/guide/en/elasticsearch/client/python-api/current/connecting.html
    def query_log(self, hostname, log):
        # Get recent logs of today:
        current_date = datetime.datetime.now().strftime('%Y.%m.%d')
        resp = self.client.search(index=f"{self.index}{current_date}", query={
            "bool": {
                "must": [
                    { "match": {"host.name": hostname}},
                    { "match": {"log.file.path": log}}
                ]
            }
        }, )
        
        print("Got %d Hits: " % resp['hits']['total']['value'])
        return resp['hits']['hits']

    # Query for log entries within a time range
    # Start and end in this format: 2024-11-26T21:57:54.583053Z
    def query_log_range(self, hostname, log, start, end, ip=""):
        #
        resp = self.client.search(index=f"{self.index}*",size=1000,query={
            "bool": {
                "must": [
                    { "match": {"host.name": hostname}},
                    { "match": {"log.file.path": log}},
                    { "match_phrase": {"message": ip}}
                ],
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": start,
                                "lte": end,
                                "format": "strict_date_optional_time"
                            }
                        }
                    }
                ]
            }
        })
        
        print("Got %d Hits: " % resp['hits']['total']['value'])
        return resp['hits']['hits']

if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    ELASTICSEARCH = os.getenv('ELASTICSEARCH') # Something like http://10.0.2.3:9200
    SIEM_INDEX = os.getenv('SIEM_INDEX') or "logs-*"
    ESUSER = os.getenv('ESUSER')
    ESPASS = os.getenv('ESPASS')
    siem = SIEM(ELASTICSEARCH, SIEM_INDEX, ESUSER, ESPASS)

    logs = siem.query_log("webserver", "/var/log/nginx/access.log")
    # Test querying Log Time Ranges for activity from an IP
    timelogs = siem.query_log_range("webserver", "/var/log/nginx/access.log", start="2024-11-25T01:10:27.432019Z", end="2024-11-25T01:27:59.769019Z", ip="73.103.84.90")
    print(f"{len(logs)}")
    print(f"Logs in time range: {len(timelogs)}")
    
    for i,log in enumerate(timelogs[:5]):
        print(f"{i}: {log}\n")
        