terraform {
  required_providers {
    metal = {
      source = "equinix/metal"
    }
  }
}

variable "public_key_path" {}
variable "private_key_path" {}

variable "metal_token" {}
variable "metal_project_id" {}
variable "metal_plan" {}

variable "metal_location" {
    default="sjc1"
}

variable "nodes" {
    default =  1
}

provider "metal" {
    auth_token = var.metal_token
}

resource "metal_ssh_key" "key1" {
    name       = "key1"
    public_key = file(var.public_key_path)
}

# Create a device and add it to tf_project_1
resource "metal_device" "test" {
    count            = var.nodes
    hostname         = "test-${count.index}"
    plan             = var.metal_plan
    facilities       = [ var.metal_location ]
    operating_system = "ubuntu_20_04"
    billing_cycle    = "hourly"
    project_id       = var.metal_project_id
    depends_on       = [ metal_ssh_key.key1 ]

    connection {
        type = "ssh"
        host = metal_device.test[count.index].access_public_ipv4
        user = "root"
        private_key = file(var.private_key_path)
        agent = false
    }

    provisioner "file" {
        source="scripts"
        destination="/provision"
    }

    provisioner "file" {
            source="../../contrib/scripts/add_vagrant_box.sh"
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
