import json
import os
import subprocess
from service import Service
class Machine:
    #Initialize each machine. Required: vmid, hostname, ip
    def __init__(self, vmid, hostname, ip, services):
        self.vmid = vmid
        self.hostname = hostname
        self.ip = ip
        self.services = services # Array of service objects

    def __str__(self):
        return json.dumps(self.to_dict(), indent=2)
    
    def to_dict(self):
        # Convert the Machine instance to a dictionary, including its services
        return {
            "vmid": self.vmid,
            "hostname": self.hostname,
            "ip": self.ip,
            "services": [service.to_dict() for service in self.services]
        }
    
    # Create a Machine instance from a dictionary
    @classmethod
    def from_dict(cls, data):
        services = [Service.from_dict(service) for service in data.get("services", [])]
        return cls(data["vmid"], data["hostname"], data["ip"], services)
    
    # Load a Machine instance from a JSON file
    @classmethod
    def load_from_file(cls, filename):
        with open(filename, "r") as f:
            data = json.load(f)
        return cls.from_dict(data)
    
    # key = ssh key location
    def provision(self, key, pmpass):
        # Run Terraform Creation
        cmd = f"terraform apply -var vmid={self.vmid} -var hostname=\"{self.hostname}\" -var ip=\"{self.ip}\" -var proxmox_pass=\'{pmpass}\' -auto-approve -state states/{self.hostname}.tfstate"
        print(f"CREATING {self.hostname} WITH TERRAFORM")
        tfproc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        tfout, tferr = tfproc.communicate()

        print(f"Terraform Exited with code {tferr}")
        
        if 'no changes are needed'.encode() in tfout:
            self.service_check(key) # TODO: Only do service check if asked for
            return False #No Changes Applied so machine is good
        # Ansible Provisioning
        print(f"PROVISIONING {self.hostname} WITH ANSIBLE")
        base_cmd = f"ansible-playbook -u ubuntu --key-file {key} -i {self.ip}," 
        appendix = "--ssh-extra-args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'"
        # Gather Scripts
        for service in self.services: # Naming Scheme will be deploy_{service_name}.yaml
            script = f"ansible/deploy_{service.name}.yaml"
            args = f"--extra-vars '{json.dumps(service.config)}'"
            ansible_cmd = f"{base_cmd} {script} {appendix} {args}"
            os.system(ansible_cmd)

        return True

    def service_check(self, key):
        base_cmd = f"ansible-playbook -u ubuntu --key-file {key} -i {self.ip}," 
        appendix = "--ssh-extra-args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'"
        # Gather Scripts
        for service in self.services: # Naming Scheme will be deploy_{service_name}.yaml
            script = f"ansible/deploy_{service.name}.yaml"
            args = f"--extra-vars '{json.dumps(service.config)}'"
            ansible_cmd = f"{base_cmd} {script} {appendix} {args}"
            os.system(ansible_cmd)

    def get_service(self, name):
        return [x for x in self.services if x.name == name][0]

    def set_service(self, name, config):
        for i in range(len(self.services)):
            if self.services[i].name == name:
                self.services[i].config = config
                return
