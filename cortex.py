from flask import Flask, request
import os
import time
import json
from dotenv import load_dotenv
from machine import Machine
from service import Service
from threading import Thread

load_dotenv()

app = Flask(__name__)
full_network = []
homedir = os.getcwd()
PM_PASS = os.getenv('PROXMOX_PASS')
TF_PROVISION = os.getenv('TF_PROVISIONING') or True

if type(TF_PROVISION) == str and TF_PROVISION.lower() == "false":
    TF_Provision = False

# Some globally defined Services
docker_service = Service("docker", { "container" : "jmalloc/echo-server" })

# We have been fed an anomaly as JSON data to investigate
def investigate(data):
    data = data
    if 'netflow' in data:
        # This is a network anomaly
        # Figure out which machine this is on, associated services, and check logs
        # Feed whatever is found to an AI to recieve a malintent score, take action or let slide.
        print(data)

@app.route('/anomaly', methods=['POST'])
def handle_anomaly():
    data = request.json
    # Start anomaly detection in another thread
    thread = Thread(target = investigate, args = (data, ))
    thread.start()
    return 'Success', 200

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    data = request.json
    #Validate request
    if 'event' in data and data['event'] == 'server_shutdown':
        #Run ansible playbook to restart nginx on the balancer
        print("RECEIVED SHUTDOWN")
        if 'target Shutdown' not in data['message']:
            print("False alarm")
            return 'Success', 200
        hostname = data['host']['hostname']
        machine = [x for x in full_network if x.hostname == hostname][0]
        os.system(f"terraform state push {hostname}.tfstate")

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
    #Temporarily define network in code
    balancer_service = Service("balancer", { "host_ips" : [] })
    bfilebeat_service = Service("filebeat", { "hostname": "balancer", "extra_files": ["/var/log/nginx/*.log"]})
    balancer = Machine(400, "balancer", "10.0.2.5", [balancer_service, bfilebeat_service])

    network = [balancer]

    for i in range(4):
        filebeat_service = Service("filebeat", {"docker": "yes", "hostname": f"webserver{i+1}"})
        services = [docker_service, filebeat_service]
        new_webserver = Machine(401 + i, f"webserver{i+1}", f"10.0.2.{10+i}", services)
        bsrv = balancer.get_service("balancer")
        bsrv.config["host_ips"].append(f"10.0.2.{10+i}")
        balancer.set_service(bsrv.name, bsrv.config)
        network.append(new_webserver)

    print(f"{json.dumps(network)}")
    threads = []
    
    for machine in network:
        if TF_PROVISION: # This could be a cemented network, in which case Aegis does not provision and it just takes security actions
            thread = Thread(target = machine.provision, args = ("~/.ssh/id_ed25519-pwless", PM_PASS))
            thread.start()
            threads.append(thread)
            #machine.provision("~/.ssh/id_ed25519-pwless", PM_PASS)
        full_network.append(machine)

    for thread in threads:
        thread.join()

    if TF_PROVISION:
        print(f"All machines have been provisioned.")


if __name__ == '__main__':
    print("Initializing the Network")
    initialize_network()
    print("Starting App")
    app.run(port=5000)
