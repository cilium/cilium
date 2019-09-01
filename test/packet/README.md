# Instructions to run CI tests in your own packet.net instances

1. Download terraform https://www.terraform.io/downloads.html
2. Log into [Packet.net](https://app.packet.net/login) and get your API key by
   clicking in your user profile (top right corner) and pick "API Keys"
   * If this is the first time, create an API Key with read/write permissions
     and give a description, something like "CI private testing"
   * Store the private token as you will need it in the next steps
3. Go to the packet.net and pick or create a project ID
   * Store the project id (from "Project Settings" page)
   * Add your public ssh key to the project
4. Open a terminal at this path in the Cilium repository.
5. `terraform init .`
6. `terraform apply`
   * This step asks for the above token, project id, whether you want to use
     a shared project key, and the path to the shared project key locally
     (optional, not required if you added your public key to the project above).
   * Confirm that you want to create the resources.
   * After a few minutes, terraform may ask for ssh agent authentication to
     provision the CI dependencies into the node.
7. After the VM is up and running you can check its IP with `terraform show`
8. SSH in to the public IP with `ssh -i <ssh-key-path> root@<publicIP>`
9. Checkout to the branch that you want to test `git checkout <my-faulty-branch>`
10. Run `screen` which will create a new terminal, this is helpful as you can leave your terminal while
     tests are running and come back again afterwards.
11. Enter the `test` directory with `cd test`
12. Consider configuring the memory for each VM lower, depending on memory available:
   `export MEMORY=3072`
13. Run the ginkgo command to initialize the tests, for example:
    `K8S_VERSION=1.14 ginkgo --focus="K8s*" -v -- --cilium.showCommands --cilium.holdEnvironment=true`
   * If you customize the `packet_plan` to `t1.small.x86`, you will need to
     specify a smaller amount of memory, eg `MEMORY=3072`.
14. Once tests are running and if you are running `screen`, you can leave the terminal
     by typing `CTRL+a+d`, to resume again type `screen -r`

## Configuring the terraform variables in your `~/.bashrc`

```
export TF_VAR_private_key_path="<SSH KEY PATH>"
export TF_VAR_packet_token="<TOKEN>"
export TF_VAR_packet_project_id="<PROJECT ID>"
# the location for europeans is better to pick Amsterdam (ams1) or Toronto (yyz1)
export TF_VAR_packet_location="ams1"
export TF_VAR_packet_plan="c1.small.x86"
```

## Cleaning up afterwards

```
terraform destroy
```
