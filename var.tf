variable "proxmox_host" {
	type = map
	default = {
		pm_api_url = "https://192.168.1.37:8006/api2/json"
		pm_user = "root@pam"
		target_node = "proxmox"
	}
}

variable "proxmox_pass" {
	type = string
	description = "Password for proxmox user"
}

variable "vmid" {
	default = 400
	description = "Starting ID for the Webservers"
}

variable "hostname" {
	default = "unset"
	description = "Hostname of new machine"
}

variable "ip" {
	description = "IP of machine"
	type = string
	default = "10.0.2.5"
}

variable "ssh_keys" {
	type = map
	default = {
		pub = "~/.ssh/id_ed25519-pwless.pub"
		priv = "~/.ssh/id_ed25519-pwless"
	}
}

variable "nginx_logs" {
	description = "Logs to collect from load balancer"
	type = list(string)
	default = ["/var/log/nginx/*.log"]
}
variable "user" {
	default = "ubuntu"
	description = "User used to SSH into the machine and provision it"
}
