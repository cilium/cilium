# Cilium CLI

[![Go](https://github.com/cilium/cilium-cli/workflows/Go/badge.svg)](https://github.com/cilium/cilium-cli/actions?query=workflow%3AGo)
[![Kind](https://github.com/cilium/cilium-cli/workflows/Kind/badge.svg)](https://github.com/cilium/cilium-cli/actions?query=workflow%3AKind)
[![EKS (ENI)](https://github.com/cilium/cilium-cli/actions/workflows/eks.yaml/badge.svg)](https://github.com/cilium/cilium-cli/actions/workflows/eks.yaml)
[![EKS (tunnel)](https://github.com/cilium/cilium-cli/actions/workflows/eks-tunnel.yaml/badge.svg)](https://github.com/cilium/cilium-cli/actions/workflows/eks-tunnel.yaml)
[![GKE](https://github.com/cilium/cilium-cli/workflows/GKE/badge.svg)](https://github.com/cilium/cilium-cli/actions?query=workflow%3AGKE)
[![AKS (BYOCNI)](https://github.com/cilium/cilium-cli/actions/workflows/aks-byocni.yaml/badge.svg)](https://github.com/cilium/cilium-cli/actions/workflows/aks-byocni.yaml)
[![Multicluster](https://github.com/cilium/cilium-cli/workflows/Multicluster/badge.svg)](https://github.com/cilium/cilium-cli/actions?query=workflow%3AMulticluster)
[![External Workloads](https://github.com/cilium/cilium-cli/actions/workflows/externalworkloads.yaml/badge.svg)](https://github.com/cilium/cilium-cli/actions/workflows/externalworkloads.yaml)

## Installation

To build and install, use the `install` target:

```console
make install
```

You may set the `BINDIR` environment variable to install the binary in a
specific location instead of `/usr/local/bin`, e.g.

```
BINDIR=~/.local/bin make install
```

Alternatively, to install the latest binary release:

```
CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
GOOS=$(go env GOOS)
GOARCH=$(go env GOARCH)
curl -L --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-${GOOS}-${GOARCH}.tar.gz{,.sha256sum}
sha256sum --check cilium-${GOOS}-${GOARCH}.tar.gz.sha256sum
sudo tar -C /usr/local/bin -xzvf cilium-${GOOS}-${GOARCH}.tar.gz
rm cilium-${GOOS}-${GOARCH}.tar.gz{,.sha256sum}
```

See https://github.com/cilium/cilium-cli/releases for supported `GOOS`/`GOARCH`
binary releases.

## Releases

| Release                                                                | Maintained | Compatible Cilium Versions |
|------------------------------------------------------------------------|------------|----------------------------|
| [v0.15.23](https://github.com/cilium/cilium-cli/releases/tag/v0.15.23) | Yes        | Cilium 1.14 and newer      |
| [v0.14.8](https://github.com/cilium/cilium-cli/releases/tag/v0.14.8)   | Yes        | Cilium 1.13                |

Please see [`helm` installation mode](#helm-installation-mode) section
regarding our plan to migrate to the new `helm` installation mode and deprecate
the current implementation.

## Capabilities

### Install Cilium

To install Cilium while automatically detected:

    cilium install
    🔮 Auto-detected Kubernetes kind: minikube
    ✨ Running "minikube" validation checks
    ✅ Detected minikube version "1.5.2"
    ℹ️  Cilium version not set, using default version "v1.9.1"
    🔮 Auto-detected cluster name: minikube
    🔑 Found existing CA in secret cilium-ca
    🔑 Generating certificates for Hubble...
    🚀 Creating service accounts...
    🚀 Creating cluster roles...
    🚀 Creating ConfigMap...
    🚀 Creating agent DaemonSet...
    🚀 Creating operator Deployment...

#### Supported Environments

 - [x] minikube
 - [x] kind
 - [x] EKS
 - [x] self-managed
 - [x] GKE
 - [x] AKS BYOCNI
 - [x] k3s
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

    cilium hubble enable
    🔑 Generating certificates for Relay...
    ✨ Deploying Relay...

### Status

    cilium status
        /¯¯\
     /¯¯\__/¯¯\    Cilium:             OK
     \__/¯¯\__/    Operator:           OK
     /¯¯\__/¯¯\    Envoy DaemonSet:    OK
     \__/¯¯\__/    Hubble Relay:       OK
        \__/       ClusterMesh:        disabled

    DaemonSet         cilium             Desired: 1, Ready: 1/1, Available: 1/1
    DaemonSet         cilium-envoy       Desired: 1, Ready: 1/1, Available: 1/1
    Deployment        cilium-operator    Desired: 1, Ready: 1/1, Available: 1/1
    Deployment        hubble-relay       Desired: 1, Ready: 1/1, Available: 1/1
    Containers:       cilium             Running: 1
                      cilium-envoy       Running: 1
                      cilium-operator    Running: 1
                      hubble-relay       Running: 1
    Image versions    cilium             quay.io/cilium/cilium:v1.9.1: 1
                      cilium-envoy       quay.io/cilium/cilium-envoy:v1.25.5-37a98693f069413c82bef1724dd75dcf1b564fd9@sha256:d10841c9cc5b0822eeca4e3654929418b6424c978fd818868b429023f6cc215d: 1
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
    ✅ client pod client-9f579495f-b2pcq was able to communicate with cilium.io
    -------------------------------------------------------------------------------------------
    🔌 Validating from pod cilium-test/client-9f579495f-b2pcq to local host...
    -------------------------------------------------------------------------------------------
    ✅ client pod client-9f579495f-b2pcq was able to communicate with local host
    -------------------------------------------------------------------------------------------
    🔌 Validating from pod cilium-test/client-9f579495f-b2pcq to service echo-same-node...
    -------------------------------------------------------------------------------------------
    ✅ client pod client-9f579495f-b2pcq was able to communicate with service echo-same-node

#### With Flow Validation

    cilium hubble port-forward&
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
    ✅ client pod client-9f579495f-b2pcq was able to communicate with cilium.io
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

#### Network Performance test 

    cilium connectivity perf
    🔥 Network Performance Test Summary:
    --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    📋 Scenario        | Node       | Test            | Duration        | Min             | Mean            | Max             | P50             | P90             | P99             | Transaction rate OP/s
    --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    📋 pod-to-pod      | same-node  | TCP_RR          | 1s              | 16µs            | 32.39µs         | 1.567ms         | 20µs            | 52µs            | 97µs            | 30696.13    
    📋 pod-to-pod      | same-node  | UDP_RR          | 1s              | 14µs            | 29.86µs         | 4.41ms          | 17µs            | 47µs            | 97µs            | 33251.51    
    📋 pod-to-pod      | same-node  | TCP_CRR         | 1s              | 290µs           | 512.1µs         | 13.413ms        | 467µs           | 626µs           | 980µs           | 1949.69     
    📋 pod-to-pod      | other-node | TCP_RR          | 1s              | 350µs           | 692.85µs        | 3.543ms         | 631µs           | 1.001ms         | 1.483ms         | 1438.69     
    📋 pod-to-pod      | other-node | UDP_RR          | 1s              | 312µs           | 865.83µs        | 8.731ms         | 605µs           | 1.444ms         | 6ms             | 1150.79     
    📋 pod-to-pod      | other-node | TCP_CRR         | 1s              | 959µs           | 2.15805ms       | 7.677ms         | 1.555ms         | 5.425ms         | 7.133ms         | 461.78      
    --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    -------------------------------------------------------------------------------------
    📋 Scenario        | Node       | Test            | Duration        | Throughput Mb/s
    -------------------------------------------------------------------------------------
    📋 pod-to-pod      | same-node  | TCP_STREAM      | 1s              | 631.58       
    📋 pod-to-pod      | same-node  | UDP_STREAM      | 1s              | 458.66       
    📋 pod-to-pod      | other-node | TCP_STREAM      | 1s              | 411.43       
    📋 pod-to-pod      | other-node | UDP_STREAM      | 1s              | 144.44       
    -------------------------------------------------------------------------------------


### ClusterMesh

Install Cilium & enable ClusterMesh in Cluster 1

    cilium install --set=cluster.id=1
    🔮 Auto-detected Kubernetes kind: GKE
    ℹ️  Cilium version not set, using default version "v1.9.1"
    🔮 Auto-detected cluster name: gke-cilium-dev-us-west2-a-tgraf-cluster1
    ✅ Detected GKE native routing CIDR: 10.52.0.0/14
    🚀 Creating resource quotas...
    🔑 Found existing CA in secret cilium-ca
    🔑 Generating certificates for Hubble...
    🚀 Creating service accounts...
    🚀 Creating cluster roles...
    🚀 Creating ConfigMap...
    🚀 Creating GKE Node Init DaemonSet...
    🚀 Creating agent DaemonSet...
    🚀 Creating operator Deployment...

    cilium clustermesh enable
    ✨ Validating cluster configuration...
    ✅ Valid cluster identification found: name="gke-cilium-dev-us-west2-a-tgraf-cluster1" id="1"
    🔑 Found existing CA in secret cilium-ca
    🔑 Generating certificates for ClusterMesh...
    ✨ Deploying clustermesh-apiserver...
    🔮 Auto-exposing service within GCP VPC (cloud.google.com/load-balancer-type=internal)


Install Cilium in Cluster 2

    cilium install --context gke_cilium-dev_us-west2-a_tgraf-cluster2 --set=cluster.id=2
    🔮 Auto-detected Kubernetes kind: GKE
    ℹ️  Cilium version not set, using default version "v1.9.1"
    🔮 Auto-detected cluster name: gke-cilium-dev-us-west2-a-tgraf-cluster2
    ✅ Detected GKE native routing CIDR: 10.4.0.0/14
    🚀 Creating resource quotas...
    🔑 Found existing CA in secret cilium-ca
    🔑 Generating certificates for Hubble...
    🚀 Creating service accounts...
    🚀 Creating cluster roles...
    🚀 Creating ConfigMap...
    🚀 Creating GKE Node Init DaemonSet...
    🚀 Creating agent DaemonSet...
    🚀 Creating operator Deployment...

    cilium clustermesh enable --context gke_cilium-dev_us-west2-a_tgraf-cluster2
    ✨ Validating cluster configuration...
    ✅ Valid cluster identification found: name="gke-cilium-dev-us-west2-a-tgraf-cluster2" id="2"
    🔑 Found existing CA in secret cilium-ca
    🔑 Generating certificates for ClusterMesh...
    ✨ Deploying clustermesh-apiserver...
    🔮 Auto-exposing service within GCP VPC (cloud.google.com/load-balancer-type=internal)

Connect Clusters

    cilium clustermesh connect --destination-context gke_cilium-dev_us-west2-a_tgraf-cluster2
    ✨ Extracting access information of cluster gke-cilium-dev-us-west2-a-tgraf-cluster2...
    🔑 Extracting secrets from cluster gke-cilium-dev-us-west2-a-tgraf-cluster2...
    ℹ️  Found ClusterMesh service IPs: [10.168.15.209]
    ✨ Extracting access information of cluster gke-cilium-dev-us-west2-a-tgraf-cluster1...
    🔑 Extracting secrets from cluster gke-cilium-dev-us-west2-a-tgraf-cluster1...
    ℹ️  Found ClusterMesh service IPs: [10.168.15.208]
    ✨ Connecting cluster gke_cilium-dev_us-west2-a_tgraf-cluster1 -> gke_cilium-dev_us-west2-a_tgraf-cluster2...
    🔑 Patching existing secret cilium-clustermesh...
    ✨ Patching DaemonSet with IP aliases cilium-clustermesh...
    ✨ Connecting cluster gke_cilium-dev_us-west2-a_tgraf-cluster2 -> gke_cilium-dev_us-west2-a_tgraf-cluster1...
    🔑 Patching existing secret cilium-clustermesh...
    ✨ Patching DaemonSet with IP aliases cilium-clustermesh...

### Encryption

Install a Cilium in a cluster and enable encryption with IPsec

    cilium install --encryption=ipsec
    🔮 Auto-detected Kubernetes kind: kind
    ✨ Running "kind" validation checks
    ✅ Detected kind version "0.9.0"
    ℹ️  Cilium version not set, using default version "v1.9.2"
    🔮 Auto-detected cluster name: kind-chart-testing
    🔮 Auto-detected IPAM mode: kubernetes
    🔑 Found existing CA in secret cilium-ca
    🔑 Generating certificates for Hubble...
    🚀 Creating Service accounts...
    🚀 Creating Cluster roles...
    🔑 Generated encryption secret cilium-ipsec-keys
    🚀 Creating ConfigMap...
    🚀 Creating Agent DaemonSet...
    🚀 Creating Operator Deployment...
    ⌛ Waiting for Cilium to be installed...

## `helm` installation mode

`cilium-cli` v0.14 introduces a new `helm` installation mode. In the current installation mode
(we now call it `classic` mode), `cilium-cli` directly calls Kubernetes APIs to manage resources
related to Cilium. In the new `helm` mode, `cilium-cli` delegates all the installation state
management to Helm. This enables you to use `cilium-cli` and `helm` interchangeably to manage your
Cilium installation, while taking advantage of `cilium-cli`'s advanced features such as Cilium
configuration auto-detection.

In `cilium-cli` v0.15, the `helm` mode is the default installation mode, and the `classic` mode is
deprecated. To use the `classic` mode, set `CILIUM_CLI_MODE` environment variable to `classic`:

    export CILIUM_CLI_MODE=classic

> **Warnings**
> - The `classic` installation mode will be removed after v0.15 release.
> - Cilium CLI does not support converting `classic` mode installations to
>   `helm` mode installations and vice versa.
> - Cilium CLI does not support running commands in `helm` mode against classic
>   mode installations.

### Examples

#### `install` examples

To install the default version of Cilium:

    cilium install

To see the Helm release that got deployed:

    helm list -n kube-system --filter "cilium"

To see non-default Helm values that `cilium-cli` used for this Cilium installation:

    helm get values -n kube-system cilium

To see all the Cilium-related resources without installing them to your cluster:

    cilium install --dry-run

To see all the non-default Helm values without actually performing the installation:

    cilium install --dry-run-helm-values

To install using Cilium's [OCI dev chart repository](https://quay.io/repository/cilium-charts-dev/cilium):

    cilium install --repository oci://quay.io/cilium-charts-dev/cilium --version 1.14.0-dev-dev.4-main-797347707c

#### `upgrade` examples

To upgrade to a specific version of Cilium:

    cilium upgrade --version v1.13.3

To upgrade using a local Helm chart:

    cilium upgrade --chart-directory ./install/kubernetes/cilium

To upgrade using Cilium's [OCI dev chart repository](https://quay.io/repository/cilium-charts-dev/cilium):

    cilium upgrade --repository oci://quay.io/cilium-charts-dev/cilium --version 1.14.0-dev-dev.4-main-797347707c

Note that `upgrade` does not mean you can only upgrade to a newer version than what is
currently installed. Similar to `helm upgrade`, `cilium upgrade` can be used to downgrade
to a previous version. For example:

     cilium install --version 1.13.3
     cilium upgrade --version 1.12.10

Please read [the upgrade guide](https://docs.cilium.io/en/stable/operations/upgrade/)
carefully before upgrading Cilium to understand all the necessary steps. In particular,
please note that `cilium-cli` does not automatically modify non-default Helm values during
upgrade. You can use `--dry-run` and `--dry-run-helm-values` flags to review Kubernetes
resources and non-default Helm values without actually performing an upgrade:

To see the difference between the current Kubernetes resources in a live cluster and what would
be applied:

    cilium upgrade --version v1.13.3 --dry-run | kubectl diff -f -

To see the non-default Helm values that would be used during upgrade:

    cilium upgrade --version v1.13.3 --dry-run-helm-values

> **Note**
> You can use external diff tools such as [dyff](https://github.com/homeport/dyff) to make
> `kubectl diff` output more readable.

It is strongly recommended that you use Cilium's [OCI dev chart repository](https://quay.io/repository/cilium-charts-dev/cilium)
if you need to deploy Cilium with a specific commit SHA. Alternatively, you can use `image.override`
Helm value if you need to override the cilium-agent container image. For example:

    cilium upgrade --set image.override=quay.io/cilium/cilium-ci:103e277f78ce95e922bfac98f1e74138a411778a --reuse-values

Please see Cilium's [Helm Reference](https://docs.cilium.io/en/stable/helm-reference/) for the
complete list of Helm values.
