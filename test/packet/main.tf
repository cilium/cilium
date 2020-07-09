variable "private_key_path" {
}

variable "packet_token" {
}

variable "packet_project_id" {
}

variable "packet_plan" {
    default="baremetal_0"
}

variable "packet_location" {
    default="sjc1"
}

variable "nodes" {
    default =  1
}

provider "packet" {
  auth_token = var.packet_token
}

# Create a device and add it to tf_project_1
resource "packet_device" "test" {
    count            = var.nodes
    hostname         = "test-${count.index}"
    plan             = var.packet_plan
    facilities       = [ var.packet_location ]
    operating_system = "ubuntu_18_04"
    billing_cycle    = "hourly"
    project_id       = var.packet_project_id

	connection {
      type = "ssh"
      host = packet_device.test[count.index].access_public_ipv4
      user = "root"
      private_key = file(var.private_key_path)
      agent = false
	}

    provisioner "file" {
            source="scripts"
            destination="/provision"
    }

	provisioner "remote-exec" {
		inline = [
            "sudo chmod 755 /provision/*.sh",
			"sudo /provision/install.sh",
            "go get -u github.com/cilium/cilium || true"
		]
	}
}
