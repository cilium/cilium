variable "private_key_path" {
    description = "If sharing a private key for packet access, specify the path"
}

variable "shared_key" {
    description = "If set to true, use a shared key"
    type        = bool
}

variable "packet_token" {
    description = "Packet.net user token for authentication"
}

variable "packet_project_id" {
    description = "Packet.net for identifying the project to deploy nodes"
}

variable "packet_plan" {
    default="t1.small.x86"
}

variable "packet_location" {
    default="sjc1"
}

variable "nodes" {
    default =  1
}

provider "packet" {
    auth_token = "${var.packet_token}"
}

# Create a device and add it to tf_project_1
resource "packet_device" "test" {
    count            = "${var.nodes}"
    hostname         = "test-${count.index}"
    plan             = "${var.packet_plan}"
    facilities       = ["${var.packet_location}"]
    operating_system = "ubuntu_18_04"
    billing_cycle    = "hourly"
    project_id       = "${var.packet_project_id}"

    connection {
        host = self.access_public_ipv4
        type = "ssh"
        user = "root"
        private_key = var.shared_key ? "${file("${var.private_key_path}")}" : ""
        agent = var.shared_key ? false : true
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
