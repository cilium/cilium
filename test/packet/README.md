# Instructions to run CI tests in your own packet-net instances

1) Download terraform https://www.terraform.io/downloads.html
2) Get your API key by clicking in your user profile (top right corner) and
pick "API Keys" https://app.packet.net/login
3) Create an API Key with read/write permissions and give a description,
something like "CI private testing"
4) Store the private token as you will need it in the next steps
5) Go to the packet.net and pick or create a project ID
6) Generate your own SSH keys via `ssk-keygen`
7) Set the following env vars:
```
export TF_VAR_public_key_path="<SSH PUB KEY PATH>"
export TF_VAR_private_key_path="<SSH PRIV KEY PATH>"
export TF_VAR_metal_token="<TOKEN>"
export TF_VAR_metal_project_id="<PROJECT ID>"
# For europeans it's better to pick Amsterdam (ams1) or Toronto (yyz1)
export TF_VAR_metal_location="ams1"
export TF_VAR_metal_plan="c1.small.x86"
```
8) `terraform init`
9) `terraform apply`
10) After the VM is up and running you can check its IP with `terraform show`
11) SSH in to the public IP with `ssh -i <ssh-key-path> root@<publicIP>`
12) Checkout to the branch that you want to test `git checkout <my-faulty-branch>`
13) Run `screen` which will create a new terminal, this is helpful as you can leave your terminal while tests are running and come back again afterwards.
14) Enter the `test` directory with `cd test`
15) Run the ginkgo command to initialize the tests, for example:
`INTEGRATION_TESTS=true K8S_VERSION=1.14 ginkgo --focus="K8s" -v -- --cilium.showCommands --cilium.holdEnvironment=true`
16) Once tests are running and if you are running `screen`, you can leave the terminal
by typing `CTRL+a+d`, to resume again type `screen -r`
