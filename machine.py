import json
import os
import subprocess

class Machine:
    #Initialize each machine. Required: vmid, hostname, ip
    def __init__(self, vmid, hostname, ip, services):
        self.vmid = vmid
        self.hostname = hostname
        self.ip = ip
        self.services = services # Array of service objects

    def __str__(self):
        return json.dumps(self.__dict__)
    
    # key = ssh key location
    def provision(self, key, pmpass):
        # Run Terraform Creation
        cmd = f"terraform apply -var vmid={self.vmid} -var hostname=\"{self.hostname}\" -var ip=\"{self.ip}\" -var proxmox_pass=\'{pmpass}\' -auto-approve -state states/{self.hostname}.tfstate"
        print(f"CREATING {self.hostname} WITH TERRAFORM")
        tfproc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        tfout, tferr = tfproc.communicate()

        print(f"Terraform Exited with code {tferr}")
        
        if 'no changes are needed'.encode() in tfout:
            return #No Changes Applied so machine is good
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
