provider "proxmox" {
	pm_api_url = var.proxmox_host["pm_api_url"]
	pm_user = var.proxmox_host["pm_user"]
	pm_password = var.proxmox_pass
	pm_tls_insecure = true
}

resource "proxmox_vm_qemu" "proxvm" {
	name = var.hostname
	target_node = var.proxmox_host["target_node"]
	vmid = var.vmid
	full_clone = true
	tablet = false
	clone = "default-cloudinit"
	pool = "Lab"
	cores = 2
	sockets = 1
	vcpus = 2
	memory = 2048
	balloon = 2048
	boot = "c"
	scsihw = "virtio-scsi-pci"
	onboot = false
	agent = 1
	numa = true
	hotplug = "network,disk,cpu,memory"

	network {
		bridge = "vmbr1"
		model = "virtio"
	}

	ciuser = "ubuntu"
	sshkeys = <<EOF
${file("~/.ssh/id_ed25519-pwless.pub")}
EOF

	ipconfig0 = "ip=${var.ip}/24,gw=10.0.2.1"
	nameserver = "10.0.2.1"
	disks {
		ide {
			ide2 {
				cloudinit {
					storage = "vm1"
				}
			}
		}
		scsi {
			scsi0 {
				disk {
					storage = "vm1"
					size = "32G"
				}
			}
		}
	}

	os_type = "cloud-init"

	connection {
		host = var.ip
		user = var.user
		private_key = file(var.ssh_keys["priv"])
		agent = false
		timeout = "3m"
	}

	provisioner "remote-exec" {
		inline = [ "echo 'Machine Provisioned'"]
	}
}
