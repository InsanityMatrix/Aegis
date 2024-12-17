from flask import Flask, request
import os
from dotenv import load_dotenv
from machine import Machine
from service import Service
from siem import SIEM
from threading import Thread, Semaphore
from glob import glob
import json

load_dotenv()

app = Flask(__name__)
full_network = []
homedir = os.getcwd()
machinedir = "machines/"
machine_files = glob(os.path.join(machinedir, "*.json"))
#TODO: Document all environment variables and their purpose
PM_PASS = os.getenv('PROXMOX_PASS')
TF_PROVISION = os.getenv('TF_PROVISIONING') or True
SIEM_IP = os.getenv('SIEM_IP')
ELASTICSEARCH = os.getenv('ELASTICSEARCH') # Something like http://10.0.2.3:9200
SIEM_INDEX = os.getenv('SIEM_INDEX') or "logs-"
ESUSER = os.getenv('ESUSER')
ESPASS = os.getenv('ESPASS')
VM_INT = "eth0" # TODO: Change dependent on OS of template/versions etc.

siem = SIEM(ELASTICSEARCH, SIEM_INDEX, ESUSER, ESPASS) # Used for investigating network anomalies later
semaphore = Semaphore(2)
if type(TF_PROVISION) == str and TF_PROVISION.lower() == "false":
    TF_PROVISION = False
else:
    TF_PROVISION = True


# Load Service Info
with open("data/services.json", 'r') as file:
    loaded = json.load(file)

service_info = {item['port']: item for item in loaded}

# Some globally defined Services
docker_service = Service("docker", { "container" : "jmalloc/echo-server" })

# We have been fed an anomaly as JSON data to investigate
def investigate(data):
    for anomaly in data: # May be a chance of recieving multiple anomalies in one req
        if 'ipv4_src_addr' in anomaly:
            src = anomaly['ipv4_src_addr']
            dst = anomaly['ipv4_dst_addr']
            in_bytes = anomaly['in_bytes']
            protocol = anomaly['protocol']

            # Time Range
            start_time = anomaly['first_switched']
            end_time = anomaly['last_switched']

            machine = None
            machineport = -1
            badip = None
            for m in full_network:
                if m.ip == src:
                    badip = dst
                    machine = m
                    machineport = anomaly['l4_src_port']
                    break
                elif m.ip == dst:
                    badip = src
                    machine = m
                    machineport = anomaly['l4_dst_port']
                    break
            
            if machine == None: # Neither of the machines are protected by Aegis. Disregard
                return
            
            if service_info[machineport] != None: 
                # Query potential logs that would give ideas as to whats going on
                info = service_info[machineport]
                possible_services = info['services']
                queries = []
                
                for svc in possible_services:
                    with semaphore:
                        try: 
                            logs = siem.query_log_range(logs = siem.query_log_range(machine.hostname, svc['log'], start=start_time, end=end_time, ip=badip))
                            if len(logs) > 0:
                                queries.append({'name': svc['name'], 'logs': logs})
                        except Exception as e:
                            print(f"Error querying log: {e}")
                        
                if len(queries) > 0:
                    print(f"Event Saved. IP: {machine.ip}:{machineport}, {len(queries)} hits")
                    with open(f"events/{start_time}-{machine.ip}.event", 'w') as efile:
                                efile.write(f"{anomaly}\n{queries}")
                else:
                    print(f"No logs found for event.")


@app.route('/anomaly', methods=['POST'])
def handle_anomaly():
    data = request.json
    # Start anomaly detection in another thread
    thread = Thread(target = investigate, args = (data, )) # TODO: Implement Task Queue to be conservative with resources
    thread.start()
    return 'Success', 200

"""
SIEM Alerts webhook

This is to allow the network to take action based on Alerts sent from the SIEM
Current alerts defined are
- server_shutdown: Detect when a server shutsdown and attempts to restart
- docker_stopped
"""
@app.route('/webhook', methods=['POST'])
def handle_webhook():
    #TODO: Make pattern based alert responses modular. defined by json files?
    data = request.json
    #Validate request
    # SIEM Alerts will have an 'event' field that names the type of event detected (RegEx pattern based)
    if 'event' in data and data['event'] == 'server_shutdown': 
        #Run ansible playbook to restart nginx on the balancer
        print("RECEIVED SHUTDOWN")
        if 'target Shutdown' not in data['message']:
            print("False alarm")
            return 'Success', 200
        hostname = data['host']['hostname']
        machine = [x for x in full_network if x.hostname == hostname][0]
        machine.provision("~/.ssh/id_ed25519-pwless", PM_PASS)

    elif data['event'] == 'docker_stopped':
        if 'systemd[1]: docker-' not in data['message']: # Only want the systemd docker messages
            print('Another false alarm')
            return 'Success', 200
        print(f"RCV: docker_stopped")
        message = data['message'] #Can start docker with docker start 'id'
        hostname = data['host']['hostname']
        dockerid = message[message.index('docker-')+7:message.index('docker-')+19]
        machine = [x for x in full_network if x.hostname == hostname][0]
        #Run ansible script for machine depending on type
        os.system(f"ansible-playbook -u ubuntu --key-file ~/.ssh/id_ed25519-pwless -i {machine.ip}, ansible/restart_container.yaml --ssh-extra-args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null' --extra-vars \"container={dockerid}\"")
    
    return 'Success', 200



def initialize_network():
    threads = []
    network = []

    # Load managed network from all json files
    for machine_file in machine_files: 
        network.append(Machine.load_from_file(machine_file))

    # Deploy machine and append it to our global full_network array. Also write to machines dir
    for machine in network:
        services = [ service.name for service in machine.services]
        if SIEM_IP and ('softflowd' not in services): # IF SIEM is set and not softflowd, also throw softflowd on for IsoFlow Integration
            machine.services.append(Service("softflowd", {"siem_ip": SIEM_IP, "network_interface": VM_INT}))

        if TF_PROVISION: # This could be a cemented network, in which case Aegis does not provision and it just takes security actions
            thread = Thread(target = machine.provision, args = ("~/.ssh/id_ed25519-pwless", PM_PASS))
            thread.start()
            threads.append(thread)
            
            if len(threads) == 2: # TODO: Only provision 2 machines at a time (HOTFIX)
                for t in threads:
                    t.join()
                    threads.remove(t)
        else: # Perform Service Checks
            thread = Thread(target = machine.service_check, args = ("~/.ssh/id_ed25519-pwless", ))
            thread.start()
            threads.append(thread)

            if len(threads) == 2: # TODO: Only provision 2 machines at a time (HOTFIX) - utilize resources more effectively
                for t in threads:
                    t.join()
                    threads.remove(t)
        with open(f"{machinedir}/{machine.hostname}.json", 'w') as mfile:
            mfile.write(f"{machine}")
        full_network.append(machine)

    for thread in threads:
        thread.join()

    print(f"All machines have been provisioned.")


if __name__ == '__main__': # TODO: Implement interactive start for defining machines easily?
    print("Initializing the Network")
    initialize_network() 
    print("Starting App")
    app.run(port=5000)
