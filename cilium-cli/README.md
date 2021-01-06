# Next-Gen Cilium CLI (Experimental)

## Installation

cd cmd/cilium
go build

## Capabilities

### Install Cilium

To install Cilium while automatically detected 

        cilium install
        🔮 Auto-detected Kubernetes kind: minikube
        ✨ Running "minikube" validation checks
        ✅ Detected minikube version "1.5.2"
        ℹ️  Cilium version not set, using default version "v1.9.1"
        🔮 Auto-detected cluster name: minikube
        🔮 Auto-detected datapath mode: tunnel
        🔑 Found existing CA in secret cilium-ca
        🔑 Generating certificates for Hubble...
        2021/01/06 14:40:09 [INFO] generate received request
        2021/01/06 14:40:09 [INFO] received CSR
        2021/01/06 14:40:09 [INFO] generating key: rsa-2048
        2021/01/06 14:40:09 [INFO] encoded CSR
        2021/01/06 14:40:09 [INFO] signed certificate with serial number 100064573681617100283382379701098370105206717828
        🚀 Creating service accounts...
        🚀 Creating cluster roles...
        🚀 Creating ConfigMap...
        🚀 Creating agent DaemonSet...
        🚀 Creating operator Deployment...

#### Supported Environments

 - [x] minikube
 - [x] EKS
 - [x] self-managed
 - [ ] GKE
 - [ ] AKS
 - [ ] kind
 - [ ] k3s
 - [ ] Rancher

### Cluster Context Management

        cilium context
        Context: minikube
        Cluster: minikube
        Auth: minikube
        Host: https://192.168.64.25:8443
        TLS server name:
        CA path: /Users/tgraf/.minikube/ca.crt

### Hubble

        ./cilium hubble enable
        🔑 Generating certificates for Relay...
        2021/01/06 14:40:21 [INFO] generate received request
        2021/01/06 14:40:21 [INFO] received CSR
        2021/01/06 14:40:21 [INFO] generating key: rsa-2048
        2021/01/06 14:40:21 [INFO] encoded CSR
        2021/01/06 14:40:21 [INFO] signed certificate with serial number 257161504887184430913779255692233956510035935986
        2021/01/06 14:40:21 [INFO] generate received request
        2021/01/06 14:40:21 [INFO] received CSR
        2021/01/06 14:40:21 [INFO] generating key: rsa-2048
        2021/01/06 14:40:21 [INFO] encoded CSR
        2021/01/06 14:40:21 [INFO] signed certificate with serial number 282554813841417773944504735898535346056548994034
        ✨ Deploying Relay...

### Status

        cilium status
            /¯¯\
         /¯¯\__/¯¯\    Cilium:      OK
         \__/¯¯\__/    Operator:    OK
         /¯¯\__/¯¯\    Hubble:      OK
         \__/¯¯\__/
            \__/
        DaemonSet         cilium             Desired: 1, Ready: 1/1, Available: 1/1
        Deployment        cilium-operator    Desired: 1, Ready: 1/1, Available: 1/1
        Deployment        hubble-relay       Desired: 1, Ready: 1/1, Available: 1/1
        Containers:       cilium             Running: 1
                          cilium-operator    Running: 1
                          hubble-relay       Running: 1
        Image versions    cilium             quay.io/cilium/cilium:v1.9.1: 1
                          cilium-operator    quay.io/cilium/operator-generic:v1.9.1: 1
                          hubble-relay       quay.io/cilium/hubble-relay:v1.9.1: 1

### Connectivity Check

        cilium connectivity test --single-node
        ⌛ Waiting for deployments to become ready
        🔭 Enabling Hubble telescope...
        ⚠️  Unable to contact Hubble Relay: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing dial tcp [::1]:4245: connect: connection refused"
        ⚠️  Did you enable and expose Hubble + Relay?
        ℹ️  You can export Relay with a port-forward: kubectl port-forward -n kube-system deployment/hubble-relay 4245:4245
        ℹ️  Disabling Hubble telescope and flow validation...
        -------------------------------------------------------------------------------------------
        🔌 Validating from pod cilium-test/client-9f579495f-b2pcq to pod cilium-test/echo-same-node-7f877bbf9-p2xg8...
        -------------------------------------------------------------------------------------------
        ✅ client pod client-9f579495f-b2pcq was able to communicate with echo pod echo-same-node-7f877bbf9-p2xg8 (10.0.0.166)
        -------------------------------------------------------------------------------------------
        🔌 Validating from pod cilium-test/client-9f579495f-b2pcq to outside of cluster...
        -------------------------------------------------------------------------------------------
        ✅ client pod client-9f579495f-b2pcq was able to communicate with google.com
        -------------------------------------------------------------------------------------------
        🔌 Validating from pod cilium-test/client-9f579495f-b2pcq to local host...
        -------------------------------------------------------------------------------------------
        ✅ client pod client-9f579495f-b2pcq was able to communicate with local host
        -------------------------------------------------------------------------------------------
        🔌 Validating from pod cilium-test/client-9f579495f-b2pcq to service echo-same-node...
        -------------------------------------------------------------------------------------------
        ✅ client pod client-9f579495f-b2pcq was able to communicate with service echo-same-node

#### With Flow Validation

        kubectl port-forward -n kube-system deployment/hubble-relay 4245:4245&
        cilium connectivity test --single-node
        ⌛ Waiting for deployments to become ready
        🔭 Enabling Hubble telescope...
        Handling connection for 4245
        ℹ️  Hubble is OK, flows: 405/4096
        -------------------------------------------------------------------------------------------
        🔌 Validating from pod cilium-test/client-9f579495f-b2pcq to pod cilium-test/echo-same-node-7f877bbf9-p2xg8...
        -------------------------------------------------------------------------------------------
        📄 Flow logs of pod cilium-test/client-9f579495f-b2pcq:
        Jan  6 13:41:17.739: 10.0.0.11:43876 -> 10.0.0.166:8080 to-endpoint FORWARDED (TCP Flags: SYN)
        Jan  6 13:41:17.739: 10.0.0.166:8080 -> 10.0.0.11:43876 to-endpoint FORWARDED (TCP Flags: SYN, ACK)
        Jan  6 13:41:17.739: 10.0.0.11:43876 -> 10.0.0.166:8080 to-endpoint FORWARDED (TCP Flags: ACK)
        Jan  6 13:41:17.739: 10.0.0.11:43876 -> 10.0.0.166:8080 to-endpoint FORWARDED (TCP Flags: ACK, PSH)
        Jan  6 13:41:17.755: 10.0.0.166:8080 -> 10.0.0.11:43876 to-endpoint FORWARDED (TCP Flags: ACK, PSH)
        Jan  6 13:41:17.756: 10.0.0.11:43876 -> 10.0.0.166:8080 to-endpoint FORWARDED (TCP Flags: ACK, FIN)
        Jan  6 13:41:17.757: 10.0.0.166:8080 -> 10.0.0.11:43876 to-endpoint FORWARDED (TCP Flags: ACK, FIN)
        Jan  6 13:41:17.757: 10.0.0.11:43876 -> 10.0.0.166:8080 to-endpoint FORWARDED (TCP Flags: ACK)
        📄 Flow logs of pod cilium-test/echo-same-node-7f877bbf9-p2xg8:
        Jan  6 13:41:17.739: 10.0.0.11:43876 -> 10.0.0.166:8080 to-endpoint FORWARDED (TCP Flags: SYN)
        Jan  6 13:41:17.739: 10.0.0.166:8080 -> 10.0.0.11:43876 to-endpoint FORWARDED (TCP Flags: SYN, ACK)
        Jan  6 13:41:17.739: 10.0.0.11:43876 -> 10.0.0.166:8080 to-endpoint FORWARDED (TCP Flags: ACK)
        Jan  6 13:41:17.739: 10.0.0.11:43876 -> 10.0.0.166:8080 to-endpoint FORWARDED (TCP Flags: ACK, PSH)
        Jan  6 13:41:17.755: 10.0.0.166:8080 -> 10.0.0.11:43876 to-endpoint FORWARDED (TCP Flags: ACK, PSH)
        Jan  6 13:41:17.756: 10.0.0.11:43876 -> 10.0.0.166:8080 to-endpoint FORWARDED (TCP Flags: ACK, FIN)
        Jan  6 13:41:17.757: 10.0.0.166:8080 -> 10.0.0.11:43876 to-endpoint FORWARDED (TCP Flags: ACK, FIN)
        Jan  6 13:41:17.757: 10.0.0.11:43876 -> 10.0.0.166:8080 to-endpoint FORWARDED (TCP Flags: ACK)
        ✅ client pod client-9f579495f-b2pcq was able to communicate with echo pod echo-same-node-7f877bbf9-p2xg8 (10.0.0.166)
        -------------------------------------------------------------------------------------------
        🔌 Validating from pod cilium-test/client-9f579495f-b2pcq to outside of cluster...
        -------------------------------------------------------------------------------------------
        ❌ Found RST in pod cilium-test/client-9f579495f-b2pcq
        ❌ FIN not found in pod cilium-test/client-9f579495f-b2pcq
        📄 Flow logs of pod cilium-test/client-9f579495f-b2pcq:
        Jan  6 13:41:22.025: 10.0.0.11:55334 -> 10.0.0.243:53 to-endpoint FORWARDED (UDP)
        Jan  6 13:41:22.025: 10.0.0.11:55334 -> 10.0.0.243:53 to-endpoint FORWARDED (UDP)
        Jan  6 13:41:22.027: 10.0.0.243:53 -> 10.0.0.11:55334 to-endpoint FORWARDED (UDP)
        Jan  6 13:41:22.028: 10.0.0.243:53 -> 10.0.0.11:55334 to-endpoint FORWARDED (UDP)
        Jan  6 13:41:22.028: 10.0.0.11:56466 -> 10.0.0.104:53 to-endpoint FORWARDED (UDP)
        Jan  6 13:41:22.028: 10.0.0.11:56466 -> 10.0.0.104:53 to-endpoint FORWARDED (UDP)
        Jan  6 13:41:22.029: 10.0.0.104:53 -> 10.0.0.11:56466 to-endpoint FORWARDED (UDP)
        Jan  6 13:41:22.029: 10.0.0.104:53 -> 10.0.0.11:56466 to-endpoint FORWARDED (UDP)
        Jan  6 13:41:22.030: 10.0.0.11:57691 -> 10.0.0.243:53 to-endpoint FORWARDED (UDP)
        Jan  6 13:41:22.030: 10.0.0.243:53 -> 10.0.0.11:57691 to-endpoint FORWARDED (UDP)
        Jan  6 13:41:22.030: 10.0.0.11:57691 -> 10.0.0.243:53 to-endpoint FORWARDED (UDP)
        Jan  6 13:41:22.031: 10.0.0.243:53 -> 10.0.0.11:57691 to-endpoint FORWARDED (UDP)
        Jan  6 13:41:22.031: 10.0.0.11:52849 -> 10.0.0.104:53 to-endpoint FORWARDED (UDP)
        Jan  6 13:41:22.032: 10.0.0.104:53 -> 10.0.0.11:52849 to-endpoint FORWARDED (UDP)
        Jan  6 13:41:22.033: 10.0.0.11:52849 -> 10.0.0.104:53 to-endpoint FORWARDED (UDP)
        Jan  6 13:41:22.037: 10.0.0.104:53 -> 10.0.0.11:52849 to-endpoint FORWARDED (UDP)
        Jan  6 13:41:22.038: 10.0.0.11:45040 -> 172.217.168.46:443 to-stack FORWARDED (TCP Flags: SYN)
        Jan  6 13:41:22.041: 172.217.168.46:443 -> 10.0.0.11:45040 to-endpoint FORWARDED (TCP Flags: SYN, ACK)
        Jan  6 13:41:22.041: 10.0.0.11:45040 -> 172.217.168.46:443 to-stack FORWARDED (TCP Flags: ACK)
        Jan  6 13:41:22.059: 10.0.0.11:45040 -> 172.217.168.46:443 to-stack FORWARDED (TCP Flags: ACK, PSH)
        Jan  6 13:41:22.073: 172.217.168.46:443 -> 10.0.0.11:45040 to-endpoint FORWARDED (TCP Flags: ACK, PSH)
        Jan  6 13:41:22.096: 10.0.0.11:45040 -> 172.217.168.46:443 to-stack FORWARDED (TCP Flags: ACK, RST)
        Jan  6 13:41:22.097: 172.217.168.46:443 -> 10.0.0.11:45040 to-endpoint FORWARDED (TCP Flags: ACK, FIN)
        Jan  6 13:41:22.097: 10.0.0.11:45040 -> 172.217.168.46:443 to-stack FORWARDED (TCP Flags: RST)
        ✅ client pod client-9f579495f-b2pcq was able to communicate with google.com
        -------------------------------------------------------------------------------------------
        🔌 Validating from pod cilium-test/client-9f579495f-b2pcq to local host...
        -------------------------------------------------------------------------------------------
        📄 Flow logs of pod cilium-test/client-9f579495f-b2pcq:
        Jan  6 13:41:25.305: 10.0.0.11 -> 192.168.64.25 to-stack FORWARDED (ICMPv4 EchoRequest)
        Jan  6 13:41:25.305: 192.168.64.25 -> 10.0.0.11 to-endpoint FORWARDED (ICMPv4 EchoReply)
        ✅ client pod client-9f579495f-b2pcq was able to communicate with local host
        -------------------------------------------------------------------------------------------
        🔌 Validating from pod cilium-test/client-9f579495f-b2pcq to service echo-same-node...
        -------------------------------------------------------------------------------------------
        📄 Flow logs of pod cilium-test/client-9f579495f-b2pcq:
        Jan  6 13:41:30.499: 10.0.0.11:39559 -> 10.0.0.104:53 to-endpoint FORWARDED (UDP)
        Jan  6 13:41:30.499: 10.0.0.11:39559 -> 10.0.0.104:53 to-endpoint FORWARDED (UDP)
        Jan  6 13:41:30.500: 10.0.0.104:53 -> 10.0.0.11:39559 to-endpoint FORWARDED (UDP)
        Jan  6 13:41:30.500: 10.0.0.104:53 -> 10.0.0.11:39559 to-endpoint FORWARDED (UDP)
        Jan  6 13:41:30.503: 10.0.0.11:59414 -> 10.0.0.166:8080 to-endpoint FORWARDED (TCP Flags: SYN)
        Jan  6 13:41:30.503: 10.0.0.166:8080 -> 10.0.0.11:59414 to-endpoint FORWARDED (TCP Flags: SYN, ACK)
        Jan  6 13:41:30.503: 10.0.0.11:59414 -> 10.0.0.166:8080 to-endpoint FORWARDED (TCP Flags: ACK)
        Jan  6 13:41:30.503: 10.0.0.11:59414 -> 10.0.0.166:8080 to-endpoint FORWARDED (TCP Flags: ACK, PSH)
        Jan  6 13:41:30.505: 10.0.0.166:8080 -> 10.0.0.11:59414 to-endpoint FORWARDED (TCP Flags: ACK, PSH)
        Jan  6 13:41:30.509: 10.0.0.11:59414 -> 10.0.0.166:8080 to-endpoint FORWARDED (TCP Flags: ACK, FIN)
        Jan  6 13:41:30.509: 10.0.0.166:8080 -> 10.0.0.11:59414 to-endpoint FORWARDED (TCP Flags: ACK, FIN)
        Jan  6 13:41:30.509: 10.0.0.11:59414 -> 10.0.0.166:8080 to-endpoint FORWARDED (TCP Flags: ACK)
        ✅ client pod client-9f579495f-b2pcq was able to communicate with service echo-same-node

### ClusterMesh
