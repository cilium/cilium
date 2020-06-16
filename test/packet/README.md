# Instructions to run CI tests in your own packet-net instances

# 1 - download terraform https://www.terraform.io/downloads.html
# 2 - get your API key by clicking in your user profile (top right corner)
#     and pick "API Keys" https://app.packet.net/login
# 3 - Create an API Key with read/write permissions and give a description,
#     something like "CI private testing"
# 4 - store the private token as you will need it in the next steps
# 5 - go to the packet.net and pick or create a project ID
# 6 - terraform init .
# 7 - terraform apply
# 8 - After the VM is up and running you can check its IP with `terraform show`
# 9 - SSH in to the public IP with `ssh -i <ssh-key-path> root@<publicIP>`
# 10 - Checkout to the branch that you want to test `git checkout <my-faulty-branch>`
# 11 - Run `screen` which will create a new terminal, this is helpful as you can leave your terminal while
#      tests are running and come back again afterwards.
# 12 - Enter the `test` directory with `cd test`
# 13 - Run the ginkgo command to initialize the tests, for example:
#     `K8S_VERSION=1.14 ginkgo --focus="K8s" -v -- --cilium.showCommands --cilium.holdEnvironment=true`
# 14 - Once tests are running and if you are running `screen`, you can leave the terminal
#      by typing `CTRL+a+d`, to resume again type `screen -r`
#
export TF_VAR_private_key_path="<SSH KEY PATH>"
export TF_VAR_packet_token="<TOKEN>"
export TF_VAR_packet_project_id="<PROJECT ID>"
# the location for europeans is better to pick Amsterdam (ams1) or Toronto (yyz1)
export TF_VAR_packet_location="ams1"
export TF_VAR_packet_plan="c1.small.x86"
