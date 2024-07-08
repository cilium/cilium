# cilium

![Version: 1.15.7](https://img.shields.io/badge/Version-1.15.7-informational?style=flat-square) ![AppVersion: 1.15.7](https://img.shields.io/badge/AppVersion-1.15.7-informational?style=flat-square)

Cilium is open source software for providing and transparently securing
network connectivity and loadbalancing between application workloads such as
application containers or processes. Cilium operates at Layer 3/4 to provide
traditional networking and security services as well as Layer 7 to protect and
secure use of modern application protocols such as HTTP, gRPC and Kafka.

A new Linux kernel technology called eBPF is at the foundation of Cilium.
It supports dynamic insertion of eBPF bytecode into the Linux kernel at various
integration points such as: network IO, application sockets, and tracepoints
to implement security, networking and visibility logic. eBPF is highly
efficient and flexible.

![Cilium feature overview](https://raw.githubusercontent.com/cilium/cilium/main/Documentation/images/cilium_overview.png)

## Prerequisites

* Kubernetes: `>= 1.16.0-0`
* Helm: `>= 3.0`

## Getting Started

Try Cilium on any Kubernetes distribution in under 15 minutes:

| Minikube | Self-Managed K8s | Amazon EKS | Google GKE | Microsoft AKS |
|:-:|:-:|:-:|:-:|:-:|
| [![Minikube](https://raw.githubusercontent.com/cilium/charts/master/images/minikube.svg)](https://docs.cilium.io/en/stable/gettingstarted/k8s-install-default/) | [![Self-Managed Kubernetes](https://raw.githubusercontent.com/cilium/charts/master/images/k8s.png)](https://docs.cilium.io/en/stable/gettingstarted/k8s-install-default/) | [![Amazon EKS](https://raw.githubusercontent.com/cilium/charts/master/images/aws.svg)](https://docs.cilium.io/en/stable/gettingstarted/k8s-install-default/) | [![Google GKE](https://raw.githubusercontent.com/cilium/charts/master/images/google-cloud.svg)](https://docs.cilium.io/en/stable/gettingstarted/k8s-install-default/) | [![Microsoft AKS](https://raw.githubusercontent.com/cilium/charts/master/images/azure.svg)](https://docs.cilium.io/en/stable/gettingstarted/k8s-install-default/) |

Or, for a quick install with the default configuration:

```
$ helm repo add cilium https://helm.cilium.io/
$ helm install cilium cilium/cilium --namespace=kube-system
```

After Cilium is installed, you can explore the features that Cilium has to
offer from the [Getting Started Guides page](https://docs.cilium.io/en/stable/gettingstarted/).

## Source Code

* <https://github.com/cilium/cilium>

## Getting Help

The best way to get help if you get stuck is to ask a question on the
[Cilium Slack channel](https://cilium.herokuapp.com/). With Cilium
contributors across the globe, there is almost always someone available to help.

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| MTU | int | `0` | Configure the underlying network MTU to overwrite auto-detected MTU. |
| affinity | object | `{"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"k8s-app":"cilium"}},"topologyKey":"kubernetes.io/hostname"}]}}` | Affinity for cilium-agent. |
| agent | bool | `true` | Install the cilium agent resources. |
| agentNotReadyTaintKey | string | `"node.cilium.io/agent-not-ready"` | Configure the key of the taint indicating that Cilium is not ready on the node. When set to a value starting with `ignore-taint.cluster-autoscaler.kubernetes.io/`, the Cluster Autoscaler will ignore the taint on its decisions, allowing the cluster to scale up. |
| aksbyocni.enabled | bool | `false` | Enable AKS BYOCNI integration. Note that this is incompatible with AKS clusters not created in BYOCNI mode: use Azure integration (`azure.enabled`) instead. |
| alibabacloud.enabled | bool | `false` | Enable AlibabaCloud ENI integration |
| annotateK8sNode | bool | `false` | Annotate k8s node upon initialization with Cilium's metadata. |
| annotations | object | `{}` | Annotations to be added to all top-level cilium-agent objects (resources under templates/cilium-agent) |
| apiRateLimit | string | `nil` | The api-rate-limit option can be used to overwrite individual settings of the default configuration for rate limiting calls to the Cilium Agent API |
| authentication.enabled | bool | `true` | Enable authentication processing and garbage collection. Note that if disabled, policy enforcement will still block requests that require authentication. But the resulting authentication requests for these requests will not be processed, therefore the requests not be allowed. |
| authentication.gcInterval | string | `"5m0s"` | Interval for garbage collection of auth map entries. |
| authentication.mutual.connectTimeout | string | `"5s"` | Timeout for connecting to the remote node TCP socket |
| authentication.mutual.port | int | `4250` | Port on the agent where mutual authentication handshakes between agents will be performed |
| authentication.mutual.spire.adminSocketPath | string | `"/run/spire/sockets/admin.sock"` | SPIRE socket path where the SPIRE delegated api agent is listening |
| authentication.mutual.spire.agentSocketPath | string | `"/run/spire/sockets/agent/agent.sock"` | SPIRE socket path where the SPIRE workload agent is listening. Applies to both the Cilium Agent and Operator |
| authentication.mutual.spire.annotations | object | `{}` | Annotations to be added to all top-level spire objects (resources under templates/spire) |
| authentication.mutual.spire.connectionTimeout | string | `"30s"` | SPIRE connection timeout |
| authentication.mutual.spire.enabled | bool | `false` | Enable SPIRE integration (beta) |
| authentication.mutual.spire.install.agent.affinity | object | `{}` | SPIRE agent affinity configuration |
| authentication.mutual.spire.install.agent.annotations | object | `{}` | SPIRE agent annotations |
| authentication.mutual.spire.install.agent.image | object | `{"digest":"sha256:99405637647968245ff9fe215f8bd2bd0ea9807be9725f8bf19fe1b21471e52b","override":null,"pullPolicy":"IfNotPresent","repository":"ghcr.io/spiffe/spire-agent","tag":"1.8.5","useDigest":true}` | SPIRE agent image |
| authentication.mutual.spire.install.agent.labels | object | `{}` | SPIRE agent labels |
| authentication.mutual.spire.install.agent.nodeSelector | object | `{}` | SPIRE agent nodeSelector configuration ref: ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector |
| authentication.mutual.spire.install.agent.podSecurityContext | object | `{}` | Security context to be added to spire agent pods. SecurityContext holds pod-level security attributes and common container settings. ref: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-security-context-for-a-pod |
| authentication.mutual.spire.install.agent.securityContext | object | `{}` | Security context to be added to spire agent containers. SecurityContext holds pod-level security attributes and common container settings. ref: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-security-context-for-a-container |
| authentication.mutual.spire.install.agent.serviceAccount | object | `{"create":true,"name":"spire-agent"}` | SPIRE agent service account |
| authentication.mutual.spire.install.agent.skipKubeletVerification | bool | `true` | SPIRE Workload Attestor kubelet verification. |
| authentication.mutual.spire.install.agent.tolerations | list | `[{"effect":"NoSchedule","key":"node.kubernetes.io/not-ready"},{"effect":"NoSchedule","key":"node-role.kubernetes.io/master"},{"effect":"NoSchedule","key":"node-role.kubernetes.io/control-plane"},{"effect":"NoSchedule","key":"node.cloudprovider.kubernetes.io/uninitialized","value":"true"},{"key":"CriticalAddonsOnly","operator":"Exists"}]` | SPIRE agent tolerations configuration By default it follows the same tolerations as the agent itself to allow the Cilium agent on this node to connect to SPIRE. ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/ |
| authentication.mutual.spire.install.enabled | bool | `true` | Enable SPIRE installation. This will only take effect only if authentication.mutual.spire.enabled is true |
| authentication.mutual.spire.install.existingNamespace | bool | `false` | SPIRE namespace already exists. Set to true if Helm should not create, manage, and import the SPIRE namespace. |
| authentication.mutual.spire.install.initImage | object | `{"digest":"sha256:9ae97d36d26566ff84e8893c64a6dc4fe8ca6d1144bf5b87b2b85a32def253c7","override":null,"pullPolicy":"IfNotPresent","repository":"docker.io/library/busybox","tag":"1.36.1","useDigest":true}` | init container image of SPIRE agent and server |
| authentication.mutual.spire.install.namespace | string | `"cilium-spire"` | SPIRE namespace to install into |
| authentication.mutual.spire.install.server.affinity | object | `{}` | SPIRE server affinity configuration |
| authentication.mutual.spire.install.server.annotations | object | `{}` | SPIRE server annotations |
| authentication.mutual.spire.install.server.ca.keyType | string | `"rsa-4096"` | SPIRE CA key type AWS requires the use of RSA. EC cryptography is not supported |
| authentication.mutual.spire.install.server.ca.subject | object | `{"commonName":"Cilium SPIRE CA","country":"US","organization":"SPIRE"}` | SPIRE CA Subject |
| authentication.mutual.spire.install.server.dataStorage.accessMode | string | `"ReadWriteOnce"` | Access mode of the SPIRE server data storage |
| authentication.mutual.spire.install.server.dataStorage.enabled | bool | `true` | Enable SPIRE server data storage |
| authentication.mutual.spire.install.server.dataStorage.size | string | `"1Gi"` | Size of the SPIRE server data storage |
| authentication.mutual.spire.install.server.dataStorage.storageClass | string | `nil` | StorageClass of the SPIRE server data storage |
| authentication.mutual.spire.install.server.image | object | `{"digest":"sha256:28269265882048dcf0fed32fe47663cd98613727210b8d1a55618826f9bf5428","override":null,"pullPolicy":"IfNotPresent","repository":"ghcr.io/spiffe/spire-server","tag":"1.8.5","useDigest":true}` | SPIRE server image |
| authentication.mutual.spire.install.server.initContainers | list | `[]` | SPIRE server init containers |
| authentication.mutual.spire.install.server.labels | object | `{}` | SPIRE server labels |
| authentication.mutual.spire.install.server.nodeSelector | object | `{}` | SPIRE server nodeSelector configuration ref: ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector |
| authentication.mutual.spire.install.server.podSecurityContext | object | `{}` | Security context to be added to spire server pods. SecurityContext holds pod-level security attributes and common container settings. ref: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-security-context-for-a-pod |
| authentication.mutual.spire.install.server.securityContext | object | `{}` | Security context to be added to spire server containers. SecurityContext holds pod-level security attributes and common container settings. ref: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-security-context-for-a-container |
| authentication.mutual.spire.install.server.service.annotations | object | `{}` | Annotations to be added to the SPIRE server service |
| authentication.mutual.spire.install.server.service.labels | object | `{}` | Labels to be added to the SPIRE server service |
| authentication.mutual.spire.install.server.service.type | string | `"ClusterIP"` | Service type for the SPIRE server service |
| authentication.mutual.spire.install.server.serviceAccount | object | `{"create":true,"name":"spire-server"}` | SPIRE server service account |
| authentication.mutual.spire.install.server.tolerations | list | `[]` | SPIRE server tolerations configuration ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/ |
| authentication.mutual.spire.serverAddress | string | `nil` | SPIRE server address used by Cilium Operator  If k8s Service DNS along with port number is used (e.g. <service-name>.<namespace>.svc(.*):<port-number> format), Cilium Operator will resolve its address by looking up the clusterIP from Service resource.  Example values: 10.0.0.1:8081, spire-server.cilium-spire.svc:8081 |
| authentication.mutual.spire.trustDomain | string | `"spiffe.cilium"` | SPIFFE trust domain to use for fetching certificates |
| authentication.queueSize | int | `1024` | Buffer size of the channel Cilium uses to receive authentication events from the signal map. |
| authentication.rotatedIdentitiesQueueSize | int | `1024` | Buffer size of the channel Cilium uses to receive certificate expiration events from auth handlers. |
| autoDirectNodeRoutes | bool | `false` | Enable installation of PodCIDR routes between worker nodes if worker nodes share a common L2 network segment. |
| azure.enabled | bool | `false` | Enable Azure integration. Note that this is incompatible with AKS clusters created in BYOCNI mode: use AKS BYOCNI integration (`aksbyocni.enabled`) instead. |
| bandwidthManager | object | `{"bbr":false,"enabled":false}` | Enable bandwidth manager to optimize TCP and UDP workloads and allow for rate-limiting traffic from individual Pods with EDT (Earliest Departure Time) through the "kubernetes.io/egress-bandwidth" Pod annotation. |
| bandwidthManager.bbr | bool | `false` | Activate BBR TCP congestion control for Pods |
| bandwidthManager.enabled | bool | `false` | Enable bandwidth manager infrastructure (also prerequirement for BBR) |
| bgp | object | `{"announce":{"loadbalancerIP":false,"podCIDR":false},"enabled":false}` | Configure BGP |
| bgp.announce.loadbalancerIP | bool | `false` | Enable allocation and announcement of service LoadBalancer IPs |
| bgp.announce.podCIDR | bool | `false` | Enable announcement of node pod CIDR |
| bgp.enabled | bool | `false` | Enable BGP support inside Cilium; embeds a new ConfigMap for BGP inside cilium-agent and cilium-operator |
| bgpControlPlane | object | `{"enabled":false,"secretsNamespace":{"create":false,"name":"kube-system"}}` | This feature set enables virtual BGP routers to be created via CiliumBGPPeeringPolicy CRDs. |
| bgpControlPlane.enabled | bool | `false` | Enables the BGP control plane. |
| bgpControlPlane.secretsNamespace | object | `{"create":false,"name":"kube-system"}` | SecretsNamespace is the namespace which BGP support will retrieve secrets from. |
| bgpControlPlane.secretsNamespace.create | bool | `false` | Create secrets namespace for BGP secrets. |
| bgpControlPlane.secretsNamespace.name | string | `"kube-system"` | The name of the secret namespace to which Cilium agents are given read access |
| bpf.authMapMax | int | `524288` | Configure the maximum number of entries in auth map. |
| bpf.autoMount.enabled | bool | `true` | Enable automatic mount of BPF filesystem When `autoMount` is enabled, the BPF filesystem is mounted at `bpf.root` path on the underlying host and inside the cilium agent pod. If users disable `autoMount`, it's expected that users have mounted bpffs filesystem at the specified `bpf.root` volume, and then the volume will be mounted inside the cilium agent pod at the same path. |
| bpf.ctAnyMax | int | `262144` | Configure the maximum number of entries for the non-TCP connection tracking table. |
| bpf.ctTcpMax | int | `524288` | Configure the maximum number of entries in the TCP connection tracking table. |
| bpf.hostLegacyRouting | bool | `false` | Configure whether direct routing mode should route traffic via host stack (true) or directly and more efficiently out of BPF (false) if the kernel supports it. The latter has the implication that it will also bypass netfilter in the host namespace. |
| bpf.lbExternalClusterIP | bool | `false` | Allow cluster external access to ClusterIP services. |
| bpf.lbMapMax | int | `65536` | Configure the maximum number of service entries in the load balancer maps. |
| bpf.mapDynamicSizeRatio | float64 | `0.0025` | Configure auto-sizing for all BPF maps based on available memory. ref: https://docs.cilium.io/en/stable/network/ebpf/maps/ |
| bpf.masquerade | bool | `false` | Enable native IP masquerade support in eBPF |
| bpf.monitorAggregation | string | `"medium"` | Configure the level of aggregation for monitor notifications. Valid options are none, low, medium, maximum. |
| bpf.monitorFlags | string | `"all"` | Configure which TCP flags trigger notifications when seen for the first time in a connection. |
| bpf.monitorInterval | string | `"5s"` | Configure the typical time between monitor notifications for active connections. |
| bpf.natMax | int | `524288` | Configure the maximum number of entries for the NAT table. |
| bpf.neighMax | int | `524288` | Configure the maximum number of entries for the neighbor table. |
| bpf.nodeMapMax | int | `nil` | Configures the maximum number of entries for the node table. |
| bpf.policyMapMax | int | `16384` | Configure the maximum number of entries in endpoint policy map (per endpoint). @schema type: [null, integer] @schema |
| bpf.preallocateMaps | bool | `false` | Enables pre-allocation of eBPF map values. This increases memory usage but can reduce latency. |
| bpf.root | string | `"/sys/fs/bpf"` | Configure the mount point for the BPF filesystem |
| bpf.tproxy | bool | `false` | Configure the eBPF-based TPROXY to reduce reliance on iptables rules for implementing Layer 7 policy. |
| bpf.vlanBypass | list | `[]` | Configure explicitly allowed VLAN id's for bpf logic bypass. [0] will allow all VLAN id's without any filtering. |
| bpfClockProbe | bool | `false` | Enable BPF clock source probing for more efficient tick retrieval. |
| certgen | object | `{"affinity":{},"annotations":{"cronJob":{},"job":{}},"extraVolumeMounts":[],"extraVolumes":[],"image":{"digest":"sha256:01802e6a153a9473b06ebade7ee5730f8f2c6cc8db8768508161da3cdd778641","override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/certgen","tag":"v0.1.13","useDigest":true},"podLabels":{},"tolerations":[],"ttlSecondsAfterFinished":1800}` | Configure certificate generation for Hubble integration. If hubble.tls.auto.method=cronJob, these values are used for the Kubernetes CronJob which will be scheduled regularly to (re)generate any certificates not provided manually. |
| certgen.affinity | object | `{}` | Affinity for certgen |
| certgen.annotations | object | `{"cronJob":{},"job":{}}` | Annotations to be added to the hubble-certgen initial Job and CronJob |
| certgen.extraVolumeMounts | list | `[]` | Additional certgen volumeMounts. |
| certgen.extraVolumes | list | `[]` | Additional certgen volumes. |
| certgen.podLabels | object | `{}` | Labels to be added to hubble-certgen pods |
| certgen.tolerations | list | `[]` | Node tolerations for pod assignment on nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/ |
| certgen.ttlSecondsAfterFinished | int | `1800` | Seconds after which the completed job pod will be deleted |
| cgroup | object | `{"autoMount":{"enabled":true,"resources":{}},"hostRoot":"/run/cilium/cgroupv2"}` | Configure cgroup related configuration |
| cgroup.autoMount.enabled | bool | `true` | Enable auto mount of cgroup2 filesystem. When `autoMount` is enabled, cgroup2 filesystem is mounted at `cgroup.hostRoot` path on the underlying host and inside the cilium agent pod. If users disable `autoMount`, it's expected that users have mounted cgroup2 filesystem at the specified `cgroup.hostRoot` volume, and then the volume will be mounted inside the cilium agent pod at the same path. |
| cgroup.autoMount.resources | object | `{}` | Init Container Cgroup Automount resource limits & requests |
| cgroup.hostRoot | string | `"/run/cilium/cgroupv2"` | Configure cgroup root where cgroup2 filesystem is mounted on the host (see also: `cgroup.autoMount`) |
| cleanBpfState | bool | `false` | Clean all eBPF datapath state from the initContainer of the cilium-agent DaemonSet.  WARNING: Use with care! |
| cleanState | bool | `false` | Clean all local Cilium state from the initContainer of the cilium-agent DaemonSet. Implies cleanBpfState: true.  WARNING: Use with care! |
| cluster.id | int | `0` | Unique ID of the cluster. Must be unique across all connected clusters and in the range of 1 to 255. Only required for Cluster Mesh, may be 0 if Cluster Mesh is not used. |
| cluster.name | string | `"default"` | Name of the cluster. Only required for Cluster Mesh and mutual authentication with SPIRE. |
| clustermesh.annotations | object | `{}` | Annotations to be added to all top-level clustermesh objects (resources under templates/clustermesh-apiserver and templates/clustermesh-config) |
| clustermesh.apiserver.affinity | object | `{"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"k8s-app":"clustermesh-apiserver"}},"topologyKey":"kubernetes.io/hostname"}]}}` | Affinity for clustermesh.apiserver |
| clustermesh.apiserver.etcd.init.extraArgs | list | `[]` | Additional arguments to `clustermesh-apiserver etcdinit`. |
| clustermesh.apiserver.etcd.init.extraEnv | list | `[]` | Additional environment variables to `clustermesh-apiserver etcdinit`. |
| clustermesh.apiserver.etcd.init.resources | object | `{}` | Specifies the resources for etcd init container in the apiserver |
| clustermesh.apiserver.etcd.lifecycle | object | `{}` | lifecycle setting for the etcd container |
| clustermesh.apiserver.etcd.resources | object | `{}` | Specifies the resources for etcd container in the apiserver |
| clustermesh.apiserver.etcd.securityContext | object | `{}` | Security context to be added to clustermesh-apiserver etcd containers |
| clustermesh.apiserver.extraArgs | list | `[]` | Additional clustermesh-apiserver arguments. |
| clustermesh.apiserver.extraEnv | list | `[]` | Additional clustermesh-apiserver environment variables. |
| clustermesh.apiserver.extraVolumeMounts | list | `[]` | Additional clustermesh-apiserver volumeMounts. |
| clustermesh.apiserver.extraVolumes | list | `[]` | Additional clustermesh-apiserver volumes. |
| clustermesh.apiserver.image | object | `{"digest":"sha256:f8fc26060e0f0c131200b762667f91788a4499362fc72209ce30b4032e926c68","override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/clustermesh-apiserver","tag":"v1.15.7","useDigest":true}` | Clustermesh API server image. |
| clustermesh.apiserver.kvstoremesh.enabled | bool | `false` | Enable KVStoreMesh. KVStoreMesh caches the information retrieved from the remote clusters in the local etcd instance. |
| clustermesh.apiserver.kvstoremesh.extraArgs | list | `[]` | Additional KVStoreMesh arguments. |
| clustermesh.apiserver.kvstoremesh.extraEnv | list | `[]` | Additional KVStoreMesh environment variables. |
| clustermesh.apiserver.kvstoremesh.extraVolumeMounts | list | `[]` | Additional KVStoreMesh volumeMounts. |
| clustermesh.apiserver.kvstoremesh.lifecycle | object | `{}` | lifecycle setting for the KVStoreMesh container |
| clustermesh.apiserver.kvstoremesh.resources | object | `{}` | Resource requests and limits for the KVStoreMesh container |
| clustermesh.apiserver.kvstoremesh.securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}` | KVStoreMesh Security context |
| clustermesh.apiserver.lifecycle | object | `{}` | lifecycle setting for the apiserver container |
| clustermesh.apiserver.metrics.enabled | bool | `true` | Enables exporting apiserver metrics in OpenMetrics format. |
| clustermesh.apiserver.metrics.etcd.enabled | bool | `true` | Enables exporting etcd metrics in OpenMetrics format. |
| clustermesh.apiserver.metrics.etcd.mode | string | `"basic"` | Set level of detail for etcd metrics; specify 'extensive' to include server side gRPC histogram metrics. |
| clustermesh.apiserver.metrics.etcd.port | int | `9963` | Configure the port the etcd metric server listens on. |
| clustermesh.apiserver.metrics.kvstoremesh.enabled | bool | `true` | Enables exporting KVStoreMesh metrics in OpenMetrics format. |
| clustermesh.apiserver.metrics.kvstoremesh.port | int | `9964` | Configure the port the KVStoreMesh metric server listens on. |
| clustermesh.apiserver.metrics.port | int | `9962` | Configure the port the apiserver metric server listens on. |
| clustermesh.apiserver.metrics.serviceMonitor.annotations | object | `{}` | Annotations to add to ServiceMonitor clustermesh-apiserver |
| clustermesh.apiserver.metrics.serviceMonitor.enabled | bool | `false` | Enable service monitor. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml) |
| clustermesh.apiserver.metrics.serviceMonitor.etcd.interval | string | `"10s"` | Interval for scrape metrics (etcd metrics) |
| clustermesh.apiserver.metrics.serviceMonitor.etcd.metricRelabelings | string | `nil` | Metrics relabeling configs for the ServiceMonitor clustermesh-apiserver (etcd metrics) |
| clustermesh.apiserver.metrics.serviceMonitor.etcd.relabelings | string | `nil` | Relabeling configs for the ServiceMonitor clustermesh-apiserver (etcd metrics) |
| clustermesh.apiserver.metrics.serviceMonitor.interval | string | `"10s"` | Interval for scrape metrics (apiserver metrics) |
| clustermesh.apiserver.metrics.serviceMonitor.kvstoremesh.interval | string | `"10s"` | Interval for scrape metrics (KVStoreMesh metrics) |
| clustermesh.apiserver.metrics.serviceMonitor.kvstoremesh.metricRelabelings | string | `nil` | Metrics relabeling configs for the ServiceMonitor clustermesh-apiserver (KVStoreMesh metrics) |
| clustermesh.apiserver.metrics.serviceMonitor.kvstoremesh.relabelings | string | `nil` | Relabeling configs for the ServiceMonitor clustermesh-apiserver (KVStoreMesh metrics) |
| clustermesh.apiserver.metrics.serviceMonitor.labels | object | `{}` | Labels to add to ServiceMonitor clustermesh-apiserver |
| clustermesh.apiserver.metrics.serviceMonitor.metricRelabelings | string | `nil` | Metrics relabeling configs for the ServiceMonitor clustermesh-apiserver (apiserver metrics) |
| clustermesh.apiserver.metrics.serviceMonitor.relabelings | string | `nil` | Relabeling configs for the ServiceMonitor clustermesh-apiserver (apiserver metrics) |
| clustermesh.apiserver.nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node labels for pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector |
| clustermesh.apiserver.podAnnotations | object | `{}` | Annotations to be added to clustermesh-apiserver pods |
| clustermesh.apiserver.podDisruptionBudget.enabled | bool | `false` | enable PodDisruptionBudget ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/ |
| clustermesh.apiserver.podDisruptionBudget.maxUnavailable | int | `1` | Maximum number/percentage of pods that may be made unavailable |
| clustermesh.apiserver.podDisruptionBudget.minAvailable | string | `nil` | Minimum number/percentage of pods that should remain scheduled. When it's set, maxUnavailable must be disabled by `maxUnavailable: null` |
| clustermesh.apiserver.podLabels | object | `{}` | Labels to be added to clustermesh-apiserver pods |
| clustermesh.apiserver.podSecurityContext | object | `{}` | Security context to be added to clustermesh-apiserver pods |
| clustermesh.apiserver.priorityClassName | string | `""` | The priority class to use for clustermesh-apiserver |
| clustermesh.apiserver.replicas | int | `1` | Number of replicas run for the clustermesh-apiserver deployment. |
| clustermesh.apiserver.resources | object | `{}` | Resource requests and limits for the clustermesh-apiserver |
| clustermesh.apiserver.securityContext | object | `{}` | Security context to be added to clustermesh-apiserver containers |
| clustermesh.apiserver.service.annotations | object | `{}` | Annotations for the clustermesh-apiserver For GKE LoadBalancer, use annotation cloud.google.com/load-balancer-type: "Internal" For EKS LoadBalancer, use annotation service.beta.kubernetes.io/aws-load-balancer-internal: 0.0.0.0/0 |
| clustermesh.apiserver.service.externalTrafficPolicy | string | `nil` | The externalTrafficPolicy of service used for apiserver access. |
| clustermesh.apiserver.service.internalTrafficPolicy | string | `nil` | The internalTrafficPolicy of service used for apiserver access. |
| clustermesh.apiserver.service.loadBalancerClass | string | `nil` | Configure a loadBalancerClass. Allows to configure the loadBalancerClass on the clustermesh-apiserver LB service in case the Service type is set to LoadBalancer (requires Kubernetes 1.24+). |
| clustermesh.apiserver.service.loadBalancerIP | string | `nil` | Configure a specific loadBalancerIP. Allows to configure a specific loadBalancerIP on the clustermesh-apiserver LB service in case the Service type is set to LoadBalancer. |
| clustermesh.apiserver.service.nodePort | int | `32379` | Optional port to use as the node port for apiserver access.  WARNING: make sure to configure a different NodePort in each cluster if kube-proxy replacement is enabled, as Cilium is currently affected by a known bug (#24692) when NodePorts are handled by the KPR implementation. If a service with the same NodePort exists both in the local and the remote cluster, all traffic originating from inside the cluster and targeting the corresponding NodePort will be redirected to a local backend, regardless of whether the destination node belongs to the local or the remote cluster. |
| clustermesh.apiserver.service.type | string | `"NodePort"` | The type of service used for apiserver access. |
| clustermesh.apiserver.terminationGracePeriodSeconds | int | `30` | terminationGracePeriodSeconds for the clustermesh-apiserver deployment |
| clustermesh.apiserver.tls.admin | object | `{"cert":"","key":""}` | base64 encoded PEM values for the clustermesh-apiserver admin certificate and private key. Used if 'auto' is not enabled. |
| clustermesh.apiserver.tls.authMode | string | `"legacy"` | Configure the clustermesh authentication mode. Supported values: - legacy:     All clusters access remote clustermesh instances with the same               username (i.e., remote). The "remote" certificate must be               generated with CN=remote if provided manually. - migration:  Intermediate mode required to upgrade from legacy to cluster               (and vice versa) with no disruption. Specifically, it enables               the creation of the per-cluster usernames, while still using               the common one for authentication. The "remote" certificate must               be generated with CN=remote if provided manually (same as legacy). - cluster:    Each cluster accesses remote etcd instances with a username               depending on the local cluster name (i.e., remote-<cluster-name>).               The "remote" certificate must be generated with CN=remote-<cluster-name>               if provided manually. Cluster mode is meaningful only when the same               CA is shared across all clusters part of the mesh. |
| clustermesh.apiserver.tls.auto | object | `{"certManagerIssuerRef":{},"certValidityDuration":1095,"enabled":true,"method":"helm"}` | Configure automatic TLS certificates generation. A Kubernetes CronJob is used the generate any certificates not provided by the user at installation time. |
| clustermesh.apiserver.tls.auto.certManagerIssuerRef | object | `{}` | certmanager issuer used when clustermesh.apiserver.tls.auto.method=certmanager. |
| clustermesh.apiserver.tls.auto.certValidityDuration | int | `1095` | Generated certificates validity duration in days. |
| clustermesh.apiserver.tls.auto.enabled | bool | `true` | When set to true, automatically generate a CA and certificates to enable mTLS between clustermesh-apiserver and external workload instances. If set to false, the certs to be provided by setting appropriate values below. |
| clustermesh.apiserver.tls.client | object | `{"cert":"","key":""}` | base64 encoded PEM values for the clustermesh-apiserver client certificate and private key. Used if 'auto' is not enabled. |
| clustermesh.apiserver.tls.remote | object | `{"cert":"","key":""}` | base64 encoded PEM values for the clustermesh-apiserver remote cluster certificate and private key. Used if 'auto' is not enabled. |
| clustermesh.apiserver.tls.server | object | `{"cert":"","extraDnsNames":[],"extraIpAddresses":[],"key":""}` | base64 encoded PEM values for the clustermesh-apiserver server certificate and private key. Used if 'auto' is not enabled. |
| clustermesh.apiserver.tls.server.extraDnsNames | list | `[]` | Extra DNS names added to certificate when it's auto generated |
| clustermesh.apiserver.tls.server.extraIpAddresses | list | `[]` | Extra IP addresses added to certificate when it's auto generated |
| clustermesh.apiserver.tolerations | list | `[]` | Node tolerations for pod assignment on nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/ |
| clustermesh.apiserver.topologySpreadConstraints | list | `[]` | Pod topology spread constraints for clustermesh-apiserver |
| clustermesh.apiserver.updateStrategy | object | `{"rollingUpdate":{"maxUnavailable":1},"type":"RollingUpdate"}` | clustermesh-apiserver update strategy |
| clustermesh.config | object | `{"clusters":[],"domain":"mesh.cilium.io","enabled":false}` | Clustermesh explicit configuration. |
| clustermesh.config.clusters | list | `[]` | List of clusters to be peered in the mesh. |
| clustermesh.config.domain | string | `"mesh.cilium.io"` | Default dns domain for the Clustermesh API servers This is used in the case cluster addresses are not provided and IPs are used. |
| clustermesh.config.enabled | bool | `false` | Enable the Clustermesh explicit configuration. |
| clustermesh.maxConnectedClusters | int | `255` | The maximum number of clusters to support in a ClusterMesh. This value cannot be changed on running clusters, and all clusters in a ClusterMesh must be configured with the same value. Values > 255 will decrease the maximum allocatable cluster-local identities. Supported values are 255 and 511. |
| clustermesh.useAPIServer | bool | `false` | Deploy clustermesh-apiserver for clustermesh |
| cni.binPath | string | `"/opt/cni/bin"` | Configure the path to the CNI binary directory on the host. |
| cni.chainingMode | string | `nil` | Configure chaining on top of other CNI plugins. Possible values:  - none  - aws-cni  - flannel  - generic-veth  - portmap |
| cni.chainingTarget | string | `nil` | A CNI network name in to which the Cilium plugin should be added as a chained plugin. This will cause the agent to watch for a CNI network with this network name. When it is found, this will be used as the basis for Cilium's CNI configuration file. If this is set, it assumes a chaining mode of generic-veth. As a special case, a chaining mode of aws-cni implies a chainingTarget of aws-cni. |
| cni.confFileMountPath | string | `"/tmp/cni-configuration"` | Configure the path to where to mount the ConfigMap inside the agent pod. |
| cni.confPath | string | `"/etc/cni/net.d"` | Configure the path to the CNI configuration directory on the host. |
| cni.configMapKey | string | `"cni-config"` | Configure the key in the CNI ConfigMap to read the contents of the CNI configuration from. |
| cni.customConf | bool | `false` | Skip writing of the CNI configuration. This can be used if writing of the CNI configuration is performed by external automation. |
| cni.exclusive | bool | `true` | Make Cilium take ownership over the `/etc/cni/net.d` directory on the node, renaming all non-Cilium CNI configurations to `*.cilium_bak`. This ensures no Pods can be scheduled using other CNI plugins during Cilium agent downtime. |
| cni.hostConfDirMountPath | string | `"/host/etc/cni/net.d"` | Configure the path to where the CNI configuration directory is mounted inside the agent pod. |
| cni.install | bool | `true` | Install the CNI configuration and binary files into the filesystem. |
| cni.logFile | string | `"/var/run/cilium/cilium-cni.log"` | Configure the log file for CNI logging with retention policy of 7 days. Disable CNI file logging by setting this field to empty explicitly. |
| cni.resources | object | `{"requests":{"cpu":"100m","memory":"10Mi"}}` | Specifies the resources for the cni initContainer |
| cni.uninstall | bool | `false` | Remove the CNI configuration and binary files on agent shutdown. Enable this if you're removing Cilium from the cluster. Disable this to prevent the CNI configuration file from being removed during agent upgrade, which can cause nodes to go unmanageable. |
| conntrackGCInterval | string | `"0s"` | Configure how frequently garbage collection should occur for the datapath connection tracking table. |
| conntrackGCMaxInterval | string | `""` | Configure the maximum frequency for the garbage collection of the connection tracking table. Only affects the automatic computation for the frequency and has no effect when 'conntrackGCInterval' is set. This can be set to more frequently clean up unused identities created from ToFQDN policies. |
| containerRuntime | object | `{"integration":"none"}` | Configure container runtime specific integration. Deprecated in favor of bpf.autoMount.enabled. To be removed in 1.15. |
| containerRuntime.integration | string | `"none"` | Enables specific integrations for container runtimes. Supported values: - crio - none |
| crdWaitTimeout | string | `"5m"` | Configure timeout in which Cilium will exit if CRDs are not available |
| customCalls | object | `{"enabled":false}` | Tail call hooks for custom eBPF programs. |
| customCalls.enabled | bool | `false` | Enable tail call hooks for custom eBPF programs. |
| daemon.allowedConfigOverrides | string | `nil` | allowedConfigOverrides is a list of config-map keys that can be overridden. That is to say, if this value is set, config sources (excepting the first one) can only override keys in this list.  This takes precedence over blockedConfigOverrides.  By default, all keys may be overridden. To disable overrides, set this to "none" or change the configSources variable. |
| daemon.blockedConfigOverrides | string | `nil` | blockedConfigOverrides is a list of config-map keys that may not be overridden. In other words, if any of these keys appear in a configuration source excepting the first one, they will be ignored  This is ignored if allowedConfigOverrides is set.  By default, all keys may be overridden. |
| daemon.configSources | string | `nil` | Configure a custom list of possible configuration override sources The default is "config-map:cilium-config,cilium-node-config". For supported values, see the help text for the build-config subcommand. Note that this value should be a comma-separated string. |
| daemon.runPath | string | `"/var/run/cilium"` | Configure where Cilium runtime state should be stored. |
| dashboards | object | `{"annotations":{},"enabled":false,"label":"grafana_dashboard","labelValue":"1","namespace":null}` | Grafana dashboards for cilium-agent grafana can import dashboards based on the label and value ref: https://github.com/grafana/helm-charts/tree/main/charts/grafana#sidecar-for-dashboards |
| debug.enabled | bool | `false` | Enable debug logging |
| debug.verbose | string | `nil` | Configure verbosity levels for debug logging This option is used to enable debug messages for operations related to such sub-system such as (e.g. kvstore, envoy, datapath or policy), and flow is for enabling debug messages emitted per request, message and connection. Multiple values can be set via a space-separated string (e.g. "datapath envoy").  Applicable values: - flow - kvstore - envoy - datapath - policy |
| disableEndpointCRD | bool | `false` | Disable the usage of CiliumEndpoint CRD. |
| dnsPolicy | string | `""` | DNS policy for Cilium agent pods. Ref: https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pod-s-dns-policy |
| dnsProxy.dnsRejectResponseCode | string | `"refused"` | DNS response code for rejecting DNS requests, available options are '[nameError refused]'. |
| dnsProxy.enableDnsCompression | bool | `true` | Allow the DNS proxy to compress responses to endpoints that are larger than 512 Bytes or the EDNS0 option, if present. |
| dnsProxy.endpointMaxIpPerHostname | int | `50` | Maximum number of IPs to maintain per FQDN name for each endpoint. |
| dnsProxy.idleConnectionGracePeriod | string | `"0s"` | Time during which idle but previously active connections with expired DNS lookups are still considered alive. |
| dnsProxy.maxDeferredConnectionDeletes | int | `10000` | Maximum number of IPs to retain for expired DNS lookups with still-active connections. |
| dnsProxy.minTtl | int | `0` | The minimum time, in seconds, to use DNS data for toFQDNs policies. If the upstream DNS server returns a DNS record with a shorter TTL, Cilium overwrites the TTL with this value. Setting this value to zero means that Cilium will honor the TTLs returned by the upstream DNS server. |
| dnsProxy.preCache | string | `""` | DNS cache data at this path is preloaded on agent startup. |
| dnsProxy.proxyPort | int | `0` | Global port on which the in-agent DNS proxy should listen. Default 0 is a OS-assigned port. |
| dnsProxy.proxyResponseMaxDelay | string | `"100ms"` | The maximum time the DNS proxy holds an allowed DNS response before sending it along. Responses are sent as soon as the datapath is updated with the new IP information. |
| dnsProxy.socketLingerTimeout | int | `10` | Timeout (in seconds) when closing the connection between the DNS proxy and the upstream server. If set to 0, the connection is closed immediately (with TCP RST). If set to -1, the connection is closed asynchronously in the background. |
| egressGateway.enabled | bool | `false` | Enables egress gateway to redirect and SNAT the traffic that leaves the cluster. |
| egressGateway.installRoutes | bool | `false` | Deprecated without a replacement necessary. |
| egressGateway.reconciliationTriggerInterval | string | `"1s"` | Time between triggers of egress gateway state reconciliations |
| enableCiliumEndpointSlice | bool | `false` | Enable CiliumEndpointSlice feature. |
| enableCriticalPriorityClass | bool | `true` | Explicitly enable or disable priority class. .Capabilities.KubeVersion is unsettable in `helm template` calls, it depends on k8s libraries version that Helm was compiled against. This option allows to explicitly disable setting the priority class, which is useful for rendering charts for gke clusters in advance. |
| enableIPv4BIGTCP | bool | `false` | Enables IPv4 BIG TCP support which increases maximum IPv4 GSO/GRO limits for nodes and pods |
| enableIPv4Masquerade | bool | `true` | Enables masquerading of IPv4 traffic leaving the node from endpoints. |
| enableIPv6BIGTCP | bool | `false` | Enables IPv6 BIG TCP support which increases maximum IPv6 GSO/GRO limits for nodes and pods |
| enableIPv6Masquerade | bool | `true` | Enables masquerading of IPv6 traffic leaving the node from endpoints. |
| enableK8sTerminatingEndpoint | bool | `true` | Configure whether to enable auto detect of terminating state for endpoints in order to support graceful termination. |
| enableMasqueradeRouteSource | bool | `false` | Enables masquerading to the source of the route for traffic leaving the node from endpoints. |
| enableRuntimeDeviceDetection | bool | `false` | Enables experimental support for the detection of new and removed datapath devices. When devices change the eBPF datapath is reloaded and services updated. If "devices" is set then only those devices, or devices matching a wildcard will be considered. |
| enableXTSocketFallback | bool | `true` | Enables the fallback compatibility solution for when the xt_socket kernel module is missing and it is needed for the datapath L7 redirection to work properly. See documentation for details on when this can be disabled: https://docs.cilium.io/en/stable/operations/system_requirements/#linux-kernel. |
| encryption.enabled | bool | `false` | Enable transparent network encryption. |
| encryption.interface | string | `""` | Deprecated in favor of encryption.ipsec.interface. To be removed in 1.15. The interface to use for encrypted traffic. This option is only effective when encryption.type is set to ipsec. |
| encryption.ipsec.interface | string | `""` | The interface to use for encrypted traffic. |
| encryption.ipsec.keyFile | string | `""` | Name of the key file inside the Kubernetes secret configured via secretName. |
| encryption.ipsec.keyRotationDuration | string | `"5m"` | Maximum duration of the IPsec key rotation. The previous key will be removed after that delay. |
| encryption.ipsec.keyWatcher | bool | `true` | Enable the key watcher. If disabled, a restart of the agent will be necessary on key rotations. |
| encryption.ipsec.mountPath | string | `""` | Path to mount the secret inside the Cilium pod. |
| encryption.ipsec.secretName | string | `""` | Name of the Kubernetes secret containing the encryption keys. |
| encryption.keyFile | string | `"keys"` | Deprecated in favor of encryption.ipsec.keyFile. To be removed in 1.15. Name of the key file inside the Kubernetes secret configured via secretName. This option is only effective when encryption.type is set to ipsec. |
| encryption.mountPath | string | `"/etc/ipsec"` | Deprecated in favor of encryption.ipsec.mountPath. To be removed in 1.15. Path to mount the secret inside the Cilium pod. This option is only effective when encryption.type is set to ipsec. |
| encryption.nodeEncryption | bool | `false` | Enable encryption for pure node to node traffic. This option is only effective when encryption.type is set to "wireguard". |
| encryption.secretName | string | `"cilium-ipsec-keys"` | Deprecated in favor of encryption.ipsec.secretName. To be removed in 1.15. Name of the Kubernetes secret containing the encryption keys. This option is only effective when encryption.type is set to ipsec. |
| encryption.strictMode | object | `{"allowRemoteNodeIdentities":false,"cidr":"","enabled":false}` | Configure the WireGuard Pod2Pod strict mode. |
| encryption.strictMode.allowRemoteNodeIdentities | bool | `false` | Allow dynamic lookup of remote node identities. This is required when tunneling is used or direct routing is used and the node CIDR and pod CIDR overlap. |
| encryption.strictMode.cidr | string | `""` | CIDR for the WireGuard Pod2Pod strict mode. |
| encryption.strictMode.enabled | bool | `false` | Enable WireGuard Pod2Pod strict mode. |
| encryption.type | string | `"ipsec"` | Encryption method. Can be either ipsec or wireguard. |
| encryption.wireguard.persistentKeepalive | string | `"0s"` | Controls Wireguard PersistentKeepalive option. Set 0s to disable. |
| encryption.wireguard.userspaceFallback | bool | `false` | Enables the fallback to the user-space implementation. |
| endpointHealthChecking.enabled | bool | `true` | Enable connectivity health checking between virtual endpoints. |
| endpointRoutes.enabled | bool | `false` | Enable use of per endpoint routes instead of routing via the cilium_host interface. |
| endpointStatus | object | `{"enabled":false,"status":""}` | Enable endpoint status. Status can be: policy, health, controllers, log and / or state. For 2 or more options use a space. |
| eni.awsEnablePrefixDelegation | bool | `false` | Enable ENI prefix delegation |
| eni.awsReleaseExcessIPs | bool | `false` | Release IPs not used from the ENI |
| eni.ec2APIEndpoint | string | `""` | EC2 API endpoint to use |
| eni.enabled | bool | `false` | Enable Elastic Network Interface (ENI) integration. |
| eni.eniTags | object | `{}` | Tags to apply to the newly created ENIs |
| eni.gcInterval | string | `"5m"` | Interval for garbage collection of unattached ENIs. Set to "0s" to disable. |
| eni.gcTags | object | `{"io.cilium/cilium-managed":"true,"io.cilium/cluster-name":"<auto-detected>"}` | Additional tags attached to ENIs created by Cilium. Dangling ENIs with this tag will be garbage collected |
| eni.iamRole | string | `""` | If using IAM role for Service Accounts will not try to inject identity values from cilium-aws kubernetes secret. Adds annotation to service account if managed by Helm. See https://github.com/aws/amazon-eks-pod-identity-webhook |
| eni.instanceTagsFilter | list | `[]` | Filter via AWS EC2 Instance tags (k=v) which will dictate which AWS EC2 Instances are going to be used to create new ENIs |
| eni.subnetIDsFilter | list | `[]` | Filter via subnet IDs which will dictate which subnets are going to be used to create new ENIs Important note: This requires that each instance has an ENI with a matching subnet attached when Cilium is deployed. If you only want to control subnets for ENIs attached by Cilium, use the CNI configuration file settings (cni.customConf) instead. |
| eni.subnetTagsFilter | list | `[]` | Filter via tags (k=v) which will dictate which subnets are going to be used to create new ENIs Important note: This requires that each instance has an ENI with a matching subnet attached when Cilium is deployed. If you only want to control subnets for ENIs attached by Cilium, use the CNI configuration file settings (cni.customConf) instead. |
| eni.updateEC2AdapterLimitViaAPI | bool | `true` | Update ENI Adapter limits from the EC2 API |
| envoy.affinity | object | `{"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"cilium.io/no-schedule","operator":"NotIn","values":["true"]}]}]}},"podAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"k8s-app":"cilium"}},"topologyKey":"kubernetes.io/hostname"}]},"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"k8s-app":"cilium-envoy"}},"topologyKey":"kubernetes.io/hostname"}]}}` | Affinity for cilium-envoy. |
| envoy.annotations | object | `{}` | Annotations to be added to all top-level cilium-envoy objects (resources under templates/cilium-envoy) |
| envoy.connectTimeoutSeconds | int | `2` | Time in seconds after which a TCP connection attempt times out |
| envoy.dnsPolicy | string | `nil` | DNS policy for Cilium envoy pods. Ref: https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pod-s-dns-policy |
| envoy.enabled | bool | `false` | Enable Envoy Proxy in standalone DaemonSet. |
| envoy.extraArgs | list | `[]` | Additional envoy container arguments. |
| envoy.extraContainers | list | `[]` | Additional containers added to the cilium Envoy DaemonSet. |
| envoy.extraEnv | list | `[]` | Additional envoy container environment variables. |
| envoy.extraHostPathMounts | list | `[]` | Additional envoy hostPath mounts. |
| envoy.extraVolumeMounts | list | `[]` | Additional envoy volumeMounts. |
| envoy.extraVolumes | list | `[]` | Additional envoy volumes. |
| envoy.healthPort | int | `9878` | TCP port for the health API. |
| envoy.idleTimeoutDurationSeconds | int | `60` | Set Envoy upstream HTTP idle connection timeout seconds. Does not apply to connections with pending requests. Default 60s |
| envoy.image | object | `{"digest":"sha256:bd5ff8c66716080028f414ec1cb4f7dc66f40d2fb5a009fff187f4a9b90b566b","override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/cilium-envoy","tag":"v1.29.7-39a2a56bbd5b3a591f69dbca51d3e30ef97e0e51","useDigest":true}` | Envoy container image. |
| envoy.livenessProbe.failureThreshold | int | `10` | failure threshold of liveness probe |
| envoy.livenessProbe.periodSeconds | int | `30` | interval between checks of the liveness probe |
| envoy.log.format | string | `"[%Y-%m-%d %T.%e][%t][%l][%n] [%g:%#] %v"` | The format string to use for laying out the log message metadata of Envoy. |
| envoy.log.path | string | `""` | Path to a separate Envoy log file, if any. Defaults to /dev/stdout. |
| envoy.maxConnectionDurationSeconds | int | `0` | Set Envoy HTTP option max_connection_duration seconds. Default 0 (disable) |
| envoy.maxRequestsPerConnection | int | `0` | ProxyMaxRequestsPerConnection specifies the max_requests_per_connection setting for Envoy |
| envoy.nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node selector for cilium-envoy. |
| envoy.podAnnotations | object | `{}` | Annotations to be added to envoy pods |
| envoy.podLabels | object | `{}` | Labels to be added to envoy pods |
| envoy.podSecurityContext | object | `{"appArmorProfile":{"type":"Unconfined"}}` | Security Context for cilium-envoy pods. |
| envoy.podSecurityContext.appArmorProfile | object | `{"type":"Unconfined"}` | AppArmorProfile options for the `cilium-agent` and init containers |
| envoy.priorityClassName | string | `nil` | The priority class to use for cilium-envoy. |
| envoy.prometheus | object | `{"enabled":true,"port":"9964","serviceMonitor":{"annotations":{},"enabled":false,"interval":"10s","labels":{},"metricRelabelings":null,"relabelings":[{"replacement":"${1}","sourceLabels":["__meta_kubernetes_pod_node_name"],"targetLabel":"node"}]}}` | Configure Cilium Envoy Prometheus options. Note that some of these apply to either cilium-agent or cilium-envoy. |
| envoy.prometheus.enabled | bool | `true` | Enable prometheus metrics for cilium-envoy |
| envoy.prometheus.port | string | `"9964"` | Serve prometheus metrics for cilium-envoy on the configured port |
| envoy.prometheus.serviceMonitor.annotations | object | `{}` | Annotations to add to ServiceMonitor cilium-envoy |
| envoy.prometheus.serviceMonitor.enabled | bool | `false` | Enable service monitors. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml) Note that this setting applies to both cilium-envoy _and_ cilium-agent with Envoy enabled. |
| envoy.prometheus.serviceMonitor.interval | string | `"10s"` | Interval for scrape metrics. |
| envoy.prometheus.serviceMonitor.labels | object | `{}` | Labels to add to ServiceMonitor cilium-envoy |
| envoy.prometheus.serviceMonitor.metricRelabelings | string | `nil` | Metrics relabeling configs for the ServiceMonitor cilium-envoy or for cilium-agent with Envoy configured. |
| envoy.prometheus.serviceMonitor.relabelings | list | `[{"replacement":"${1}","sourceLabels":["__meta_kubernetes_pod_node_name"],"targetLabel":"node"}]` | Relabeling configs for the ServiceMonitor cilium-envoy or for cilium-agent with Envoy configured. |
| envoy.readinessProbe.failureThreshold | int | `3` | failure threshold of readiness probe |
| envoy.readinessProbe.periodSeconds | int | `30` | interval between checks of the readiness probe |
| envoy.resources | object | `{}` | Envoy resource limits & requests ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/ |
| envoy.rollOutPods | bool | `false` | Roll out cilium envoy pods automatically when configmap is updated. |
| envoy.securityContext.capabilities.envoy | list | `["NET_ADMIN","SYS_ADMIN"]` | Capabilities for the `cilium-envoy` container |
| envoy.securityContext.privileged | bool | `false` | Run the pod with elevated privileges |
| envoy.securityContext.seLinuxOptions | object | `{"level":"s0","type":"spc_t"}` | SELinux options for the `cilium-envoy` container |
| envoy.startupProbe.failureThreshold | int | `105` | failure threshold of startup probe. 105 x 2s translates to the old behaviour of the readiness probe (120s delay + 30 x 3s) |
| envoy.startupProbe.periodSeconds | int | `2` | interval between checks of the startup probe |
| envoy.terminationGracePeriodSeconds | int | `1` | Configure termination grace period for cilium-envoy DaemonSet. |
| envoy.tolerations | list | `[{"operator":"Exists"}]` | Node tolerations for envoy scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/ |
| envoy.updateStrategy | object | `{"rollingUpdate":{"maxUnavailable":2},"type":"RollingUpdate"}` | cilium-envoy update strategy ref: https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/#updating-a-daemonset |
| envoy.xffNumTrustedHopsL7PolicyEgress | int | `0` | Number of trusted hops regarding the x-forwarded-for and related HTTP headers for the egress L7 policy enforcement Envoy listeners. |
| envoy.xffNumTrustedHopsL7PolicyIngress | int | `0` | Number of trusted hops regarding the x-forwarded-for and related HTTP headers for the ingress L7 policy enforcement Envoy listeners. |
| envoyConfig.enabled | bool | `false` | Enable CiliumEnvoyConfig CRD CiliumEnvoyConfig CRD can also be implicitly enabled by other options. |
| envoyConfig.secretsNamespace | object | `{"create":true,"name":"cilium-secrets"}` | SecretsNamespace is the namespace in which envoy SDS will retrieve secrets from. |
| envoyConfig.secretsNamespace.create | bool | `true` | Create secrets namespace for CiliumEnvoyConfig CRDs. |
| envoyConfig.secretsNamespace.name | string | `"cilium-secrets"` | The name of the secret namespace to which Cilium agents are given read access. |
| etcd.annotations | object | `{}` | Annotations to be added to all top-level etcd-operator objects (resources under templates/etcd-operator) |
| etcd.clusterDomain | string | `"cluster.local"` | Cluster domain for cilium-etcd-operator. |
| etcd.enabled | bool | `false` | Enable etcd mode for the agent. |
| etcd.endpoints | list | `["https://CHANGE-ME:2379"]` | List of etcd endpoints (not needed when using managed=true). |
| etcd.extraArgs | list | `[]` | Additional cilium-etcd-operator container arguments. |
| etcd.extraVolumeMounts | list | `[]` | Additional cilium-etcd-operator volumeMounts. |
| etcd.extraVolumes | list | `[]` | Additional cilium-etcd-operator volumes. |
| etcd.image | object | `{"digest":"sha256:04b8327f7f992693c2cb483b999041ed8f92efc8e14f2a5f3ab95574a65ea2dc","override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/cilium-etcd-operator","tag":"v2.0.7","useDigest":true}` | cilium-etcd-operator image. |
| etcd.k8sService | bool | `false` | If etcd is behind a k8s service set this option to true so that Cilium does the service translation automatically without requiring a DNS to be running. |
| etcd.nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node labels for cilium-etcd-operator pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector |
| etcd.podAnnotations | object | `{}` | Annotations to be added to cilium-etcd-operator pods |
| etcd.podDisruptionBudget.enabled | bool | `false` | enable PodDisruptionBudget ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/ |
| etcd.podDisruptionBudget.maxUnavailable | int | `1` | Maximum number/percentage of pods that may be made unavailable |
| etcd.podDisruptionBudget.minAvailable | string | `nil` | Minimum number/percentage of pods that should remain scheduled. When it's set, maxUnavailable must be disabled by `maxUnavailable: null` |
| etcd.podLabels | object | `{}` | Labels to be added to cilium-etcd-operator pods |
| etcd.podSecurityContext | object | `{}` | Security context to be added to cilium-etcd-operator pods |
| etcd.priorityClassName | string | `""` | The priority class to use for cilium-etcd-operator |
| etcd.resources | object | `{}` | cilium-etcd-operator resource limits & requests ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/ |
| etcd.securityContext | object | `{}` | Security context to be added to cilium-etcd-operator pods |
| etcd.ssl | bool | `false` | Enable use of TLS/SSL for connectivity to etcd. (auto-enabled if managed=true) |
| etcd.tolerations | list | `[{"operator":"Exists"}]` | Node tolerations for cilium-etcd-operator scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/ |
| etcd.topologySpreadConstraints | list | `[]` | Pod topology spread constraints for cilium-etcd-operator |
| etcd.updateStrategy | object | `{"rollingUpdate":{"maxSurge":1,"maxUnavailable":1},"type":"RollingUpdate"}` | cilium-etcd-operator update strategy |
| externalIPs.enabled | bool | `false` | Enable ExternalIPs service support. |
| externalWorkloads | object | `{"enabled":false}` | Configure external workloads support |
| externalWorkloads.enabled | bool | `false` | Enable support for external workloads, such as VMs (false by default). |
| extraArgs | list | `[]` | Additional agent container arguments. |
| extraConfig | object | `{}` | extraConfig allows you to specify additional configuration parameters to be included in the cilium-config configmap. |
| extraContainers | list | `[]` | Additional containers added to the cilium DaemonSet. |
| extraEnv | list | `[]` | Additional agent container environment variables. |
| extraHostPathMounts | list | `[]` | Additional agent hostPath mounts. |
| extraVolumeMounts | list | `[]` | Additional agent volumeMounts. |
| extraVolumes | list | `[]` | Additional agent volumes. |
| gatewayAPI.enabled | bool | `false` | Enable support for Gateway API in cilium This will automatically set enable-envoy-config as well. |
| gatewayAPI.secretsNamespace | object | `{"create":true,"name":"cilium-secrets","sync":true}` | SecretsNamespace is the namespace in which envoy SDS will retrieve TLS secrets from. |
| gatewayAPI.secretsNamespace.create | bool | `true` | Create secrets namespace for Gateway API. |
| gatewayAPI.secretsNamespace.name | string | `"cilium-secrets"` | Name of Gateway API secret namespace. |
| gatewayAPI.secretsNamespace.sync | bool | `true` | Enable secret sync, which will make sure all TLS secrets used by Ingress are synced to secretsNamespace.name. If disabled, TLS secrets must be maintained externally. |
| gke.enabled | bool | `false` | Enable Google Kubernetes Engine integration |
| healthChecking | bool | `true` | Enable connectivity health checking. |
| healthPort | int | `9879` | TCP port for the agent health API. This is not the port for cilium-health. |
| highScaleIPcache | object | `{"enabled":false}` | EnableHighScaleIPcache enables the special ipcache mode for high scale clusters. The ipcache content will be reduced to the strict minimum and traffic will be encapsulated to carry security identities. |
| highScaleIPcache.enabled | bool | `false` | Enable the high scale mode for the ipcache. |
| hostFirewall | object | `{"enabled":false}` | Configure the host firewall. |
| hostFirewall.enabled | bool | `false` | Enables the enforcement of host policies in the eBPF datapath. |
| hostPort.enabled | bool | `false` | Enable hostPort service support. |
| hubble.annotations | object | `{}` | Annotations to be added to all top-level hubble objects (resources under templates/hubble) |
| hubble.enabled | bool | `true` | Enable Hubble (true by default). |
| hubble.export | object | `{"dynamic":{"config":{"configMapName":"cilium-flowlog-config","content":[{"excludeFilters":[],"fieldMask":[],"filePath":"/var/run/cilium/hubble/events.log","includeFilters":[],"name":"all"}],"createConfigMap":true},"enabled":false},"fileMaxBackups":5,"fileMaxSizeMb":10,"static":{"allowList":[],"denyList":[],"enabled":false,"fieldMask":[],"filePath":"/var/run/cilium/hubble/events.log"}}` | Hubble flows export. |
| hubble.export.dynamic | object | `{"config":{"configMapName":"cilium-flowlog-config","content":[{"excludeFilters":[],"fieldMask":[],"filePath":"/var/run/cilium/hubble/events.log","includeFilters":[],"name":"all"}],"createConfigMap":true},"enabled":false}` | - Dynamic exporters configuration. Dynamic exporters may be reconfigured without a need of agent restarts. |
| hubble.export.dynamic.config.configMapName | string | `"cilium-flowlog-config"` | -- Name of configmap with configuration that may be altered to reconfigure exporters within a running agents. |
| hubble.export.dynamic.config.content | list | `[{"excludeFilters":[],"fieldMask":[],"filePath":"/var/run/cilium/hubble/events.log","includeFilters":[],"name":"all"}]` | -- Exporters configuration in YAML format. |
| hubble.export.dynamic.config.createConfigMap | bool | `true` | -- True if helm installer should create config map. Switch to false if you want to self maintain the file content. |
| hubble.export.fileMaxBackups | int | `5` | - Defines max number of backup/rotated files. |
| hubble.export.fileMaxSizeMb | int | `10` | - Defines max file size of output file before it gets rotated. |
| hubble.export.static | object | `{"allowList":[],"denyList":[],"enabled":false,"fieldMask":[],"filePath":"/var/run/cilium/hubble/events.log"}` | - Static exporter configuration. Static exporter is bound to agent lifecycle. |
| hubble.listenAddress | string | `":4244"` | An additional address for Hubble to listen to. Set this field ":4244" if you are enabling Hubble Relay, as it assumes that Hubble is listening on port 4244. |
| hubble.metrics | object | `{"dashboards":{"annotations":{},"enabled":false,"label":"grafana_dashboard","labelValue":"1","namespace":null},"enableOpenMetrics":false,"enabled":null,"port":9965,"serviceAnnotations":{},"serviceMonitor":{"annotations":{},"enabled":false,"interval":"10s","jobLabel":"","labels":{},"metricRelabelings":null,"relabelings":[{"replacement":"${1}","sourceLabels":["__meta_kubernetes_pod_node_name"],"targetLabel":"node"}]}}` | Hubble metrics configuration. See https://docs.cilium.io/en/stable/observability/metrics/#hubble-metrics for more comprehensive documentation about Hubble metrics. |
| hubble.metrics.dashboards | object | `{"annotations":{},"enabled":false,"label":"grafana_dashboard","labelValue":"1","namespace":null}` | Grafana dashboards for hubble grafana can import dashboards based on the label and value ref: https://github.com/grafana/helm-charts/tree/main/charts/grafana#sidecar-for-dashboards |
| hubble.metrics.enableOpenMetrics | bool | `false` | Enables exporting hubble metrics in OpenMetrics format. |
| hubble.metrics.enabled | string | `nil` | Configures the list of metrics to collect. If empty or null, metrics are disabled. Example:    enabled:   - dns:query;ignoreAAAA   - drop   - tcp   - flow   - icmp   - http  You can specify the list of metrics from the helm CLI:    --set hubble.metrics.enabled="{dns:query;ignoreAAAA,drop,tcp,flow,icmp,http}"  |
| hubble.metrics.port | int | `9965` | Configure the port the hubble metric server listens on. |
| hubble.metrics.serviceAnnotations | object | `{}` | Annotations to be added to hubble-metrics service. |
| hubble.metrics.serviceMonitor.annotations | object | `{}` | Annotations to add to ServiceMonitor hubble |
| hubble.metrics.serviceMonitor.enabled | bool | `false` | Create ServiceMonitor resources for Prometheus Operator. This requires the prometheus CRDs to be available. ref: https://github.com/prometheus-operator/prometheus-operator/blob/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml) |
| hubble.metrics.serviceMonitor.interval | string | `"10s"` | Interval for scrape metrics. |
| hubble.metrics.serviceMonitor.jobLabel | string | `""` | jobLabel to add for ServiceMonitor hubble |
| hubble.metrics.serviceMonitor.labels | object | `{}` | Labels to add to ServiceMonitor hubble |
| hubble.metrics.serviceMonitor.metricRelabelings | string | `nil` | Metrics relabeling configs for the ServiceMonitor hubble |
| hubble.metrics.serviceMonitor.relabelings | list | `[{"replacement":"${1}","sourceLabels":["__meta_kubernetes_pod_node_name"],"targetLabel":"node"}]` | Relabeling configs for the ServiceMonitor hubble |
| hubble.peerService.clusterDomain | string | `"cluster.local"` | The cluster domain to use to query the Hubble Peer service. It should be the local cluster. |
| hubble.peerService.targetPort | int | `4244` | Target Port for the Peer service, must match the hubble.listenAddress' port. |
| hubble.preferIpv6 | bool | `false` | Whether Hubble should prefer to announce IPv6 or IPv4 addresses if both are available. |
| hubble.redact | object | `{"enabled":false,"http":{"headers":{"allow":[],"deny":[]},"urlQuery":false,"userInfo":true},"kafka":{"apiKey":false}}` | Enables redacting sensitive information present in Layer 7 flows. |
| hubble.redact.http.headers.allow | list | `[]` | List of HTTP headers to allow: headers not matching will be redacted. Note: `allow` and `deny` lists cannot be used both at the same time, only one can be present. Example:   redact:     enabled: true     http:       headers:         allow:           - traceparent           - tracestate           - Cache-Control  You can specify the options from the helm CLI:   --set hubble.redact.enabled="true"   --set hubble.redact.http.headers.allow="traceparent,tracestate,Cache-Control" |
| hubble.redact.http.headers.deny | list | `[]` | List of HTTP headers to deny: matching headers will be redacted. Note: `allow` and `deny` lists cannot be used both at the same time, only one can be present. Example:   redact:     enabled: true     http:       headers:         deny:           - Authorization           - Proxy-Authorization  You can specify the options from the helm CLI:   --set hubble.redact.enabled="true"   --set hubble.redact.http.headers.deny="Authorization,Proxy-Authorization" |
| hubble.redact.http.urlQuery | bool | `false` | Enables redacting URL query (GET) parameters. Example:    redact:     enabled: true     http:       urlQuery: true  You can specify the options from the helm CLI:    --set hubble.redact.enabled="true"   --set hubble.redact.http.urlQuery="true" |
| hubble.redact.http.userInfo | bool | `true` | Enables redacting user info, e.g., password when basic auth is used. Example:    redact:     enabled: true     http:       userInfo: true  You can specify the options from the helm CLI:    --set hubble.redact.enabled="true"   --set hubble.redact.http.userInfo="true" |
| hubble.redact.kafka.apiKey | bool | `false` | Enables redacting Kafka's API key. Example:    redact:     enabled: true     kafka:       apiKey: true  You can specify the options from the helm CLI:    --set hubble.redact.enabled="true"   --set hubble.redact.kafka.apiKey="true" |
| hubble.relay.affinity | object | `{"podAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"k8s-app":"cilium"}},"topologyKey":"kubernetes.io/hostname"}]}}` | Affinity for hubble-replay |
| hubble.relay.annotations | object | `{}` | Annotations to be added to all top-level hubble-relay objects (resources under templates/hubble-relay) |
| hubble.relay.dialTimeout | string | `nil` | Dial timeout to connect to the local hubble instance to receive peer information (e.g. "30s"). |
| hubble.relay.enabled | bool | `false` | Enable Hubble Relay (requires hubble.enabled=true) |
| hubble.relay.extraEnv | list | `[]` | Additional hubble-relay environment variables. |
| hubble.relay.extraVolumeMounts | list | `[]` | Additional hubble-relay volumeMounts. |
| hubble.relay.extraVolumes | list | `[]` | Additional hubble-relay volumes. |
| hubble.relay.gops.enabled | bool | `true` | Enable gops for hubble-relay |
| hubble.relay.gops.port | int | `9893` | Configure gops listen port for hubble-relay |
| hubble.relay.image | object | `{"digest":"sha256:12870e87ec6c105ca86885c4ee7c184ece6b706cc0f22f63d2a62a9a818fd68f","override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/hubble-relay","tag":"v1.15.7","useDigest":true}` | Hubble-relay container image. |
| hubble.relay.listenHost | string | `""` | Host to listen to. Specify an empty string to bind to all the interfaces. |
| hubble.relay.listenPort | string | `"4245"` | Port to listen to. |
| hubble.relay.nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node labels for pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector |
| hubble.relay.podAnnotations | object | `{}` | Annotations to be added to hubble-relay pods |
| hubble.relay.podDisruptionBudget.enabled | bool | `false` | enable PodDisruptionBudget ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/ |
| hubble.relay.podDisruptionBudget.maxUnavailable | int | `1` | Maximum number/percentage of pods that may be made unavailable |
| hubble.relay.podDisruptionBudget.minAvailable | string | `nil` | Minimum number/percentage of pods that should remain scheduled. When it's set, maxUnavailable must be disabled by `maxUnavailable: null` |
| hubble.relay.podLabels | object | `{}` | Labels to be added to hubble-relay pods |
| hubble.relay.podSecurityContext | object | `{"fsGroup":65532}` | hubble-relay pod security context |
| hubble.relay.pprof.address | string | `"localhost"` | Configure pprof listen address for hubble-relay |
| hubble.relay.pprof.enabled | bool | `false` | Enable pprof for hubble-relay |
| hubble.relay.pprof.port | int | `6062` | Configure pprof listen port for hubble-relay |
| hubble.relay.priorityClassName | string | `""` | The priority class to use for hubble-relay |
| hubble.relay.prometheus | object | `{"enabled":false,"port":9966,"serviceMonitor":{"annotations":{},"enabled":false,"interval":"10s","labels":{},"metricRelabelings":null,"relabelings":null}}` | Enable prometheus metrics for hubble-relay on the configured port at /metrics |
| hubble.relay.prometheus.serviceMonitor.annotations | object | `{}` | Annotations to add to ServiceMonitor hubble-relay |
| hubble.relay.prometheus.serviceMonitor.enabled | bool | `false` | Enable service monitors. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml) |
| hubble.relay.prometheus.serviceMonitor.interval | string | `"10s"` | Interval for scrape metrics. |
| hubble.relay.prometheus.serviceMonitor.labels | object | `{}` | Labels to add to ServiceMonitor hubble-relay |
| hubble.relay.prometheus.serviceMonitor.metricRelabelings | string | `nil` | Metrics relabeling configs for the ServiceMonitor hubble-relay |
| hubble.relay.prometheus.serviceMonitor.relabelings | string | `nil` | Relabeling configs for the ServiceMonitor hubble-relay |
| hubble.relay.replicas | int | `1` | Number of replicas run for the hubble-relay deployment. |
| hubble.relay.resources | object | `{}` | Specifies the resources for the hubble-relay pods |
| hubble.relay.retryTimeout | string | `nil` | Backoff duration to retry connecting to the local hubble instance in case of failure (e.g. "30s"). |
| hubble.relay.rollOutPods | bool | `false` | Roll out Hubble Relay pods automatically when configmap is updated. |
| hubble.relay.securityContext | object | `{"capabilities":{"drop":["ALL"]},"runAsGroup":65532,"runAsNonRoot":true,"runAsUser":65532}` | hubble-relay container security context |
| hubble.relay.service | object | `{"nodePort":31234,"type":"ClusterIP"}` | hubble-relay service configuration. |
| hubble.relay.service.nodePort | int | `31234` | - The port to use when the service type is set to NodePort. |
| hubble.relay.service.type | string | `"ClusterIP"` | - The type of service used for Hubble Relay access, either ClusterIP or NodePort. |
| hubble.relay.sortBufferDrainTimeout | string | `nil` | When the per-request flows sort buffer is not full, a flow is drained every time this timeout is reached (only affects requests in follow-mode) (e.g. "1s"). |
| hubble.relay.sortBufferLenMax | string | `nil` | Max number of flows that can be buffered for sorting before being sent to the client (per request) (e.g. 100). |
| hubble.relay.terminationGracePeriodSeconds | int | `1` | Configure termination grace period for hubble relay Deployment. |
| hubble.relay.tls | object | `{"client":{"cert":"","key":""},"server":{"cert":"","enabled":false,"extraDnsNames":[],"extraIpAddresses":[],"key":"","mtls":false,"relayName":"ui.hubble-relay.cilium.io"}}` | TLS configuration for Hubble Relay |
| hubble.relay.tls.client | object | `{"cert":"","key":""}` | base64 encoded PEM values for the hubble-relay client certificate and private key This keypair is presented to Hubble server instances for mTLS authentication and is required when hubble.tls.enabled is true. These values need to be set manually if hubble.tls.auto.enabled is false. |
| hubble.relay.tls.server | object | `{"cert":"","enabled":false,"extraDnsNames":[],"extraIpAddresses":[],"key":"","mtls":false,"relayName":"ui.hubble-relay.cilium.io"}` | base64 encoded PEM values for the hubble-relay server certificate and private key |
| hubble.relay.tls.server.extraDnsNames | list | `[]` | extra DNS names added to certificate when its auto gen |
| hubble.relay.tls.server.extraIpAddresses | list | `[]` | extra IP addresses added to certificate when its auto gen |
| hubble.relay.tolerations | list | `[]` | Node tolerations for pod assignment on nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/ |
| hubble.relay.topologySpreadConstraints | list | `[]` | Pod topology spread constraints for hubble-relay |
| hubble.relay.updateStrategy | object | `{"rollingUpdate":{"maxUnavailable":1},"type":"RollingUpdate"}` | hubble-relay update strategy |
| hubble.skipUnknownCGroupIDs | bool | `true` | Skip Hubble events with unknown cgroup ids |
| hubble.socketPath | string | `"/var/run/cilium/hubble.sock"` | Unix domain socket path to listen to when Hubble is enabled. |
| hubble.tls | object | `{"auto":{"certManagerIssuerRef":{},"certValidityDuration":1095,"enabled":true,"method":"helm","schedule":"0 0 1 */4 *"},"enabled":true,"server":{"cert":"","extraDnsNames":[],"extraIpAddresses":[],"key":""}}` | TLS configuration for Hubble |
| hubble.tls.auto | object | `{"certManagerIssuerRef":{},"certValidityDuration":1095,"enabled":true,"method":"helm","schedule":"0 0 1 */4 *"}` | Configure automatic TLS certificates generation. |
| hubble.tls.auto.certManagerIssuerRef | object | `{}` | certmanager issuer used when hubble.tls.auto.method=certmanager. |
| hubble.tls.auto.certValidityDuration | int | `1095` | Generated certificates validity duration in days. |
| hubble.tls.auto.enabled | bool | `true` | Auto-generate certificates. When set to true, automatically generate a CA and certificates to enable mTLS between Hubble server and Hubble Relay instances. If set to false, the certs for Hubble server need to be provided by setting appropriate values below. |
| hubble.tls.auto.method | string | `"helm"` | Set the method to auto-generate certificates. Supported values: - helm:         This method uses Helm to generate all certificates. - cronJob:      This method uses a Kubernetes CronJob the generate any                 certificates not provided by the user at installation                 time. - certmanager:  This method use cert-manager to generate & rotate certificates. |
| hubble.tls.auto.schedule | string | `"0 0 1 */4 *"` | Schedule for certificates regeneration (regardless of their expiration date). Only used if method is "cronJob". If nil, then no recurring job will be created. Instead, only the one-shot job is deployed to generate the certificates at installation time.  Defaults to midnight of the first day of every fourth month. For syntax, see https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/#schedule-syntax |
| hubble.tls.enabled | bool | `true` | Enable mutual TLS for listenAddress. Setting this value to false is highly discouraged as the Hubble API provides access to potentially sensitive network flow metadata and is exposed on the host network. |
| hubble.tls.server | object | `{"cert":"","extraDnsNames":[],"extraIpAddresses":[],"key":""}` | base64 encoded PEM values for the Hubble server certificate and private key |
| hubble.tls.server.extraDnsNames | list | `[]` | Extra DNS names added to certificate when it's auto generated |
| hubble.tls.server.extraIpAddresses | list | `[]` | Extra IP addresses added to certificate when it's auto generated |
| hubble.ui.affinity | object | `{}` | Affinity for hubble-ui |
| hubble.ui.annotations | object | `{}` | Annotations to be added to all top-level hubble-ui objects (resources under templates/hubble-ui) |
| hubble.ui.backend.extraEnv | list | `[]` | Additional hubble-ui backend environment variables. |
| hubble.ui.backend.extraVolumeMounts | list | `[]` | Additional hubble-ui backend volumeMounts. |
| hubble.ui.backend.extraVolumes | list | `[]` | Additional hubble-ui backend volumes. |
| hubble.ui.backend.image | object | `{"digest":"sha256:0e0eed917653441fded4e7cdb096b7be6a3bddded5a2dd10812a27b1fc6ed95b","override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/hubble-ui-backend","tag":"v0.13.1","useDigest":true}` | Hubble-ui backend image. |
| hubble.ui.backend.livenessProbe.enabled | bool | `false` | Enable liveness probe for Hubble-ui backend (requires Hubble-ui 0.12+) |
| hubble.ui.backend.readinessProbe.enabled | bool | `false` | Enable readiness probe for Hubble-ui backend (requires Hubble-ui 0.12+) |
| hubble.ui.backend.resources | object | `{}` | Resource requests and limits for the 'backend' container of the 'hubble-ui' deployment. |
| hubble.ui.backend.securityContext | object | `{}` | Hubble-ui backend security context. |
| hubble.ui.baseUrl | string | `"/"` | Defines base url prefix for all hubble-ui http requests. It needs to be changed in case if ingress for hubble-ui is configured under some sub-path. Trailing `/` is required for custom path, ex. `/service-map/` |
| hubble.ui.enabled | bool | `false` | Whether to enable the Hubble UI. |
| hubble.ui.frontend.extraEnv | list | `[]` | Additional hubble-ui frontend environment variables. |
| hubble.ui.frontend.extraVolumeMounts | list | `[]` | Additional hubble-ui frontend volumeMounts. |
| hubble.ui.frontend.extraVolumes | list | `[]` | Additional hubble-ui frontend volumes. |
| hubble.ui.frontend.image | object | `{"digest":"sha256:e2e9313eb7caf64b0061d9da0efbdad59c6c461f6ca1752768942bfeda0796c6","override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/hubble-ui","tag":"v0.13.1","useDigest":true}` | Hubble-ui frontend image. |
| hubble.ui.frontend.resources | object | `{}` | Resource requests and limits for the 'frontend' container of the 'hubble-ui' deployment. |
| hubble.ui.frontend.securityContext | object | `{}` | Hubble-ui frontend security context. |
| hubble.ui.frontend.server.ipv6 | object | `{"enabled":true}` | Controls server listener for ipv6 |
| hubble.ui.ingress | object | `{"annotations":{},"className":"","enabled":false,"hosts":["chart-example.local"],"labels":{},"tls":[]}` | hubble-ui ingress configuration. |
| hubble.ui.nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node labels for pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector |
| hubble.ui.podAnnotations | object | `{}` | Annotations to be added to hubble-ui pods |
| hubble.ui.podDisruptionBudget.enabled | bool | `false` | enable PodDisruptionBudget ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/ |
| hubble.ui.podDisruptionBudget.maxUnavailable | int | `1` | Maximum number/percentage of pods that may be made unavailable |
| hubble.ui.podDisruptionBudget.minAvailable | string | `nil` | Minimum number/percentage of pods that should remain scheduled. When it's set, maxUnavailable must be disabled by `maxUnavailable: null` |
| hubble.ui.podLabels | object | `{}` | Labels to be added to hubble-ui pods |
| hubble.ui.priorityClassName | string | `""` | The priority class to use for hubble-ui |
| hubble.ui.replicas | int | `1` | The number of replicas of Hubble UI to deploy. |
| hubble.ui.rollOutPods | bool | `false` | Roll out Hubble-ui pods automatically when configmap is updated. |
| hubble.ui.securityContext | object | `{"fsGroup":1001,"runAsGroup":1001,"runAsUser":1001}` | Security context to be added to Hubble UI pods |
| hubble.ui.service | object | `{"annotations":{},"nodePort":31235,"type":"ClusterIP"}` | hubble-ui service configuration. |
| hubble.ui.service.annotations | object | `{}` | Annotations to be added for the Hubble UI service |
| hubble.ui.service.nodePort | int | `31235` | - The port to use when the service type is set to NodePort. |
| hubble.ui.service.type | string | `"ClusterIP"` | - The type of service used for Hubble UI access, either ClusterIP or NodePort. |
| hubble.ui.standalone.enabled | bool | `false` | When true, it will allow installing the Hubble UI only, without checking dependencies. It is useful if a cluster already has cilium and Hubble relay installed and you just want Hubble UI to be deployed. When installed via helm, installing UI should be done via `helm upgrade` and when installed via the cilium cli, then `cilium hubble enable --ui` |
| hubble.ui.standalone.tls.certsVolume | object | `{}` | When deploying Hubble UI in standalone, with tls enabled for Hubble relay, it is required to provide a volume for mounting the client certificates. |
| hubble.ui.tls.client | object | `{"cert":"","key":""}` | base64 encoded PEM values used to connect to hubble-relay This keypair is presented to Hubble Relay instances for mTLS authentication and is required when hubble.relay.tls.server.enabled is true. These values need to be set manually if hubble.tls.auto.enabled is false. |
| hubble.ui.tolerations | list | `[]` | Node tolerations for pod assignment on nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/ |
| hubble.ui.topologySpreadConstraints | list | `[]` | Pod topology spread constraints for hubble-ui |
| hubble.ui.updateStrategy | object | `{"rollingUpdate":{"maxUnavailable":1},"type":"RollingUpdate"}` | hubble-ui update strategy. |
| identityAllocationMode | string | `"crd"` | Method to use for identity allocation (`crd` or `kvstore`). |
| identityChangeGracePeriod | string | `"5s"` | Time to wait before using new identity on endpoint identity change. |
| image | object | `{"digest":"sha256:2e432bf6879feb8b891c497d6fd784b13e53456017d2b8e4ea734145f0282ef0","override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/cilium","tag":"v1.15.7","useDigest":true}` | Agent container image. |
| imagePullSecrets | string | `nil` | Configure image pull secrets for pulling container images |
| ingressController.default | bool | `false` | Set cilium ingress controller to be the default ingress controller This will let cilium ingress controller route entries without ingress class set |
| ingressController.defaultSecretName | string | `nil` | Default secret name for ingresses without .spec.tls[].secretName set. |
| ingressController.defaultSecretNamespace | string | `nil` | Default secret namespace for ingresses without .spec.tls[].secretName set. |
| ingressController.enableProxyProtocol | bool | `false` | Enable proxy protocol for all Ingress listeners. Note that _only_ Proxy protocol traffic will be accepted once this is enabled. |
| ingressController.enabled | bool | `false` | Enable cilium ingress controller This will automatically set enable-envoy-config as well. |
| ingressController.enforceHttps | bool | `true` | Enforce https for host having matching TLS host in Ingress. Incoming traffic to http listener will return 308 http error code with respective location in header. |
| ingressController.ingressLBAnnotationPrefixes | list | `["service.beta.kubernetes.io","service.kubernetes.io","cloud.google.com"]` | IngressLBAnnotations are the annotation and label prefixes, which are used to filter annotations and/or labels to propagate from Ingress to the Load Balancer service |
| ingressController.loadbalancerMode | string | `"dedicated"` | Default ingress load balancer mode Supported values: shared, dedicated For granular control, use the following annotations on the ingress resource ingress.cilium.io/loadbalancer-mode: shared|dedicated, |
| ingressController.secretsNamespace | object | `{"create":true,"name":"cilium-secrets","sync":true}` | SecretsNamespace is the namespace in which envoy SDS will retrieve TLS secrets from. |
| ingressController.secretsNamespace.create | bool | `true` | Create secrets namespace for Ingress. |
| ingressController.secretsNamespace.name | string | `"cilium-secrets"` | Name of Ingress secret namespace. |
| ingressController.secretsNamespace.sync | bool | `true` | Enable secret sync, which will make sure all TLS secrets used by Ingress are synced to secretsNamespace.name. If disabled, TLS secrets must be maintained externally. |
| ingressController.service | object | `{"allocateLoadBalancerNodePorts":null,"annotations":{},"insecureNodePort":null,"labels":{},"loadBalancerClass":null,"loadBalancerIP":null,"name":"cilium-ingress","secureNodePort":null,"type":"LoadBalancer"}` | Load-balancer service in shared mode. This is a single load-balancer service for all Ingress resources. |
| ingressController.service.allocateLoadBalancerNodePorts | string | `nil` | Configure if node port allocation is required for LB service ref: https://kubernetes.io/docs/concepts/services-networking/service/#load-balancer-nodeport-allocation |
| ingressController.service.annotations | object | `{}` | Annotations to be added for the shared LB service |
| ingressController.service.insecureNodePort | string | `nil` | Configure a specific nodePort for insecure HTTP traffic on the shared LB service |
| ingressController.service.labels | object | `{}` | Labels to be added for the shared LB service |
| ingressController.service.loadBalancerClass | string | `nil` | Configure a specific loadBalancerClass on the shared LB service (requires Kubernetes 1.24+) |
| ingressController.service.loadBalancerIP | string | `nil` | Configure a specific loadBalancerIP on the shared LB service |
| ingressController.service.name | string | `"cilium-ingress"` | Service name |
| ingressController.service.secureNodePort | string | `nil` | Configure a specific nodePort for secure HTTPS traffic on the shared LB service |
| ingressController.service.type | string | `"LoadBalancer"` | Service type for the shared LB service |
| initResources | object | `{}` | resources & limits for the agent init containers |
| installNoConntrackIptablesRules | bool | `false` | Install Iptables rules to skip netfilter connection tracking on all pod traffic. This option is only effective when Cilium is running in direct routing and full KPR mode. Moreover, this option cannot be enabled when Cilium is running in a managed Kubernetes environment or in a chained CNI setup. |
| ipMasqAgent | object | `{"enabled":false}` | Configure the eBPF-based ip-masq-agent |
| ipam.ciliumNodeUpdateRate | string | `"15s"` | Maximum rate at which the CiliumNode custom resource is updated. |
| ipam.mode | string | `"cluster-pool"` | Configure IP Address Management mode. ref: https://docs.cilium.io/en/stable/network/concepts/ipam/ |
| ipam.operator.autoCreateCiliumPodIPPools | object | `{}` | IP pools to auto-create in multi-pool IPAM mode. |
| ipam.operator.clusterPoolIPv4MaskSize | int | `24` | IPv4 CIDR mask size to delegate to individual nodes for IPAM. |
| ipam.operator.clusterPoolIPv4PodCIDRList | list | `["10.0.0.0/8"]` | IPv4 CIDR list range to delegate to individual nodes for IPAM. |
| ipam.operator.clusterPoolIPv6MaskSize | int | `120` | IPv6 CIDR mask size to delegate to individual nodes for IPAM. |
| ipam.operator.clusterPoolIPv6PodCIDRList | list | `["fd00::/104"]` | IPv6 CIDR list range to delegate to individual nodes for IPAM. |
| ipam.operator.externalAPILimitBurstSize | string | `20` | The maximum burst size when rate limiting access to external APIs. Also known as the token bucket capacity. |
| ipam.operator.externalAPILimitQPS | string | `4.0` | The maximum queries per second when rate limiting access to external APIs. Also known as the bucket refill rate, which is used to refill the bucket up to the burst size capacity. |
| ipv4.enabled | bool | `true` | Enable IPv4 support. |
| ipv4NativeRoutingCIDR | string | `""` | Allows to explicitly specify the IPv4 CIDR for native routing. When specified, Cilium assumes networking for this CIDR is preconfigured and hands traffic destined for that range to the Linux network stack without applying any SNAT. Generally speaking, specifying a native routing CIDR implies that Cilium can depend on the underlying networking stack to route packets to their destination. To offer a concrete example, if Cilium is configured to use direct routing and the Kubernetes CIDR is included in the native routing CIDR, the user must configure the routes to reach pods, either manually or by setting the auto-direct-node-routes flag. |
| ipv6.enabled | bool | `false` | Enable IPv6 support. |
| ipv6NativeRoutingCIDR | string | `""` | Allows to explicitly specify the IPv6 CIDR for native routing. When specified, Cilium assumes networking for this CIDR is preconfigured and hands traffic destined for that range to the Linux network stack without applying any SNAT. Generally speaking, specifying a native routing CIDR implies that Cilium can depend on the underlying networking stack to route packets to their destination. To offer a concrete example, if Cilium is configured to use direct routing and the Kubernetes CIDR is included in the native routing CIDR, the user must configure the routes to reach pods, either manually or by setting the auto-direct-node-routes flag. |
| k8s | object | `{}` | Configure Kubernetes specific configuration |
| k8sClientRateLimit | object | `{"burst":null,"qps":null}` | Configure the client side rate limit for the agent and operator  If the amount of requests to the Kubernetes API server exceeds the configured rate limit, the agent and operator will start to throttle requests by delaying them until there is budget or the request times out. |
| k8sClientRateLimit.burst | int | 10 for k8s up to 1.26. 20 for k8s version 1.27+ | The burst request rate in requests per second. The rate limiter will allow short bursts with a higher rate. |
| k8sClientRateLimit.qps | int | 5 for k8s up to 1.26. 10 for k8s version 1.27+ | The sustained request rate in requests per second. |
| k8sNetworkPolicy.enabled | bool | `true` | Enable support for K8s NetworkPolicy |
| k8sServiceHost | string | `""` | Kubernetes service host |
| k8sServicePort | string | `""` | Kubernetes service port |
| keepDeprecatedLabels | bool | `false` | Keep the deprecated selector labels when deploying Cilium DaemonSet. |
| keepDeprecatedProbes | bool | `false` | Keep the deprecated probes when deploying Cilium DaemonSet |
| kubeConfigPath | string | `"~/.kube/config"` | Kubernetes config path |
| kubeProxyReplacementHealthzBindAddr | string | `""` | healthz server bind address for the kube-proxy replacement. To enable set the value to '0.0.0.0:10256' for all ipv4 addresses and this '[::]:10256' for all ipv6 addresses. By default it is disabled. |
| l2NeighDiscovery.enabled | bool | `true` | Enable L2 neighbor discovery in the agent |
| l2NeighDiscovery.refreshPeriod | string | `"30s"` | Override the agent's default neighbor resolution refresh period. |
| l2announcements | object | `{"enabled":false}` | Configure L2 announcements |
| l2announcements.enabled | bool | `false` | Enable L2 announcements |
| l2podAnnouncements | object | `{"enabled":false,"interface":"eth0"}` | Configure L2 pod announcements |
| l2podAnnouncements.enabled | bool | `false` | Enable L2 pod announcements |
| l2podAnnouncements.interface | string | `"eth0"` | Interface used for sending Gratuitous ARP pod announcements |
| l7Proxy | bool | `true` | Enable Layer 7 network policy. |
| livenessProbe.failureThreshold | int | `10` | failure threshold of liveness probe |
| livenessProbe.periodSeconds | int | `30` | interval between checks of the liveness probe |
| loadBalancer | object | `{"acceleration":"disabled","l7":{"algorithm":"round_robin","backend":"disabled","ports":[]}}` | Configure service load balancing |
| loadBalancer.acceleration | string | `"disabled"` | acceleration is the option to accelerate service handling via XDP Applicable values can be: disabled (do not use XDP), native (XDP BPF program is run directly out of the networking driver's early receive path), or best-effort (use native mode XDP acceleration on devices that support it). |
| loadBalancer.l7 | object | `{"algorithm":"round_robin","backend":"disabled","ports":[]}` | L7 LoadBalancer |
| loadBalancer.l7.algorithm | string | `"round_robin"` | Default LB algorithm The default LB algorithm to be used for services, which can be overridden by the service annotation (e.g. service.cilium.io/lb-l7-algorithm) Applicable values: round_robin, least_request, random |
| loadBalancer.l7.backend | string | `"disabled"` | Enable L7 service load balancing via envoy proxy. The request to a k8s service, which has specific annotation e.g. service.cilium.io/lb-l7, will be forwarded to the local backend proxy to be load balanced to the service endpoints. Please refer to docs for supported annotations for more configuration.  Applicable values:   - envoy: Enable L7 load balancing via envoy proxy. This will automatically set enable-envoy-config as well.   - disabled: Disable L7 load balancing by way of service annotation. |
| loadBalancer.l7.ports | list | `[]` | List of ports from service to be automatically redirected to above backend. Any service exposing one of these ports will be automatically redirected. Fine-grained control can be achieved by using the service annotation. |
| localRedirectPolicy | bool | `false` | Enable Local Redirect Policy. |
| logSystemLoad | bool | `false` | Enables periodic logging of system load |
| maglev | object | `{}` | Configure maglev consistent hashing |
| monitor | object | `{"enabled":false}` | cilium-monitor sidecar. |
| monitor.enabled | bool | `false` | Enable the cilium-monitor sidecar. |
| name | string | `"cilium"` | Agent container name. |
| nat46x64Gateway | object | `{"enabled":false}` | Configure standalone NAT46/NAT64 gateway |
| nat46x64Gateway.enabled | bool | `false` | Enable RFC8215-prefixed translation |
| nodePort | object | `{"autoProtectPortRange":true,"bindProtection":true,"enableHealthCheck":true,"enableHealthCheckLoadBalancerIP":false,"enabled":false}` | Configure N-S k8s service loadbalancing |
| nodePort.autoProtectPortRange | bool | `true` | Append NodePort range to ip_local_reserved_ports if clash with ephemeral ports is detected. |
| nodePort.bindProtection | bool | `true` | Set to true to prevent applications binding to service ports. |
| nodePort.enableHealthCheck | bool | `true` | Enable healthcheck nodePort server for NodePort services |
| nodePort.enableHealthCheckLoadBalancerIP | bool | `false` | Enable access of the healthcheck nodePort on the LoadBalancerIP. Needs EnableHealthCheck to be enabled |
| nodePort.enabled | bool | `false` | Enable the Cilium NodePort service implementation. |
| nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node selector for cilium-agent. |
| nodeinit.affinity | object | `{}` | Affinity for cilium-nodeinit |
| nodeinit.annotations | object | `{}` | Annotations to be added to all top-level nodeinit objects (resources under templates/cilium-nodeinit) |
| nodeinit.bootstrapFile | string | `"/tmp/cilium-bootstrap.d/cilium-bootstrap-time"` | bootstrapFile is the location of the file where the bootstrap timestamp is written by the node-init DaemonSet |
| nodeinit.enabled | bool | `false` | Enable the node initialization DaemonSet |
| nodeinit.extraEnv | list | `[]` | Additional nodeinit environment variables. |
| nodeinit.extraVolumeMounts | list | `[]` | Additional nodeinit volumeMounts. |
| nodeinit.extraVolumes | list | `[]` | Additional nodeinit volumes. |
| nodeinit.image | object | `{"digest":"sha256:8d7b41c4ca45860254b3c19e20210462ef89479bb6331d6760c4e609d651b29c","override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/startup-script","tag":"c54c7edeab7fde4da68e59acd319ab24af242c3f","useDigest":true}` | node-init image. |
| nodeinit.nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node labels for nodeinit pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector |
| nodeinit.podAnnotations | object | `{}` | Annotations to be added to node-init pods. |
| nodeinit.podLabels | object | `{}` | Labels to be added to node-init pods. |
| nodeinit.podSecurityContext | object | `{"appArmorProfile":{"type":"Unconfined"}}` | Security Context for cilium-node-init pods. |
| nodeinit.podSecurityContext.appArmorProfile | object | `{"type":"Unconfined"}` | AppArmorProfile options for the `cilium-node-init` and init containers |
| nodeinit.prestop | object | `{"postScript":"","preScript":""}` | prestop offers way to customize prestop nodeinit script (pre and post position) |
| nodeinit.priorityClassName | string | `""` | The priority class to use for the nodeinit pod. |
| nodeinit.resources | object | `{"requests":{"cpu":"100m","memory":"100Mi"}}` | nodeinit resource limits & requests ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/ |
| nodeinit.securityContext | object | `{"capabilities":{"add":["SYS_MODULE","NET_ADMIN","SYS_ADMIN","SYS_CHROOT","SYS_PTRACE"]},"privileged":false,"seLinuxOptions":{"level":"s0","type":"spc_t"}}` | Security context to be added to nodeinit pods. |
| nodeinit.startup | object | `{"postScript":"","preScript":""}` | startup offers way to customize startup nodeinit script (pre and post position) |
| nodeinit.tolerations | list | `[{"operator":"Exists"}]` | Node tolerations for nodeinit scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/ |
| nodeinit.updateStrategy | object | `{"type":"RollingUpdate"}` | node-init update strategy |
| operator.affinity | object | `{"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"io.cilium/app":"operator"}},"topologyKey":"kubernetes.io/hostname"}]}}` | Affinity for cilium-operator |
| operator.annotations | object | `{}` | Annotations to be added to all top-level cilium-operator objects (resources under templates/cilium-operator) |
| operator.dashboards | object | `{"annotations":{},"enabled":false,"label":"grafana_dashboard","labelValue":"1","namespace":null}` | Grafana dashboards for cilium-operator grafana can import dashboards based on the label and value ref: https://github.com/grafana/helm-charts/tree/main/charts/grafana#sidecar-for-dashboards |
| operator.dnsPolicy | string | `""` | DNS policy for Cilium operator pods. Ref: https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pod-s-dns-policy |
| operator.enabled | bool | `true` | Enable the cilium-operator component (required). |
| operator.endpointGCInterval | string | `"5m0s"` | Interval for endpoint garbage collection. |
| operator.extraArgs | list | `[]` | Additional cilium-operator container arguments. |
| operator.extraEnv | list | `[]` | Additional cilium-operator environment variables. |
| operator.extraHostPathMounts | list | `[]` | Additional cilium-operator hostPath mounts. |
| operator.extraVolumeMounts | list | `[]` | Additional cilium-operator volumeMounts. |
| operator.extraVolumes | list | `[]` | Additional cilium-operator volumes. |
| operator.identityGCInterval | string | `"15m0s"` | Interval for identity garbage collection. |
| operator.identityHeartbeatTimeout | string | `"30m0s"` | Timeout for identity heartbeats. |
| operator.image | object | `{"alibabacloudDigest":"sha256:2dcd7e3305cb47e4b5fbbb9bc2451d6aacb18788a87cab95cf86aec65ec19329","awsDigest":"sha256:bb4085da666a5c7a7c6f8135f0de10f0b6895dbf561e9fccda0e272b51bb936e","azureDigest":"sha256:8e189549bc3c31a44a1171cc970b8e502ae8bf55cd07035735c4b3a24a16f80b","genericDigest":"sha256:6840a6dde703b3e73dd31e03390327a9184fcb888efbad9d9d098d65b9035b54","override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/operator","suffix":"","tag":"v1.15.7","useDigest":true}` | cilium-operator image. |
| operator.nodeGCInterval | string | `"5m0s"` | Interval for cilium node garbage collection. |
| operator.nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node labels for cilium-operator pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector |
| operator.podAnnotations | object | `{}` | Annotations to be added to cilium-operator pods |
| operator.podDisruptionBudget.enabled | bool | `false` | enable PodDisruptionBudget ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/ |
| operator.podDisruptionBudget.maxUnavailable | int | `1` | Maximum number/percentage of pods that may be made unavailable |
| operator.podDisruptionBudget.minAvailable | string | `nil` | Minimum number/percentage of pods that should remain scheduled. When it's set, maxUnavailable must be disabled by `maxUnavailable: null` |
| operator.podLabels | object | `{}` | Labels to be added to cilium-operator pods |
| operator.podSecurityContext | object | `{}` | Security context to be added to cilium-operator pods |
| operator.pprof.address | string | `"localhost"` | Configure pprof listen address for cilium-operator |
| operator.pprof.enabled | bool | `false` | Enable pprof for cilium-operator |
| operator.pprof.port | int | `6061` | Configure pprof listen port for cilium-operator |
| operator.priorityClassName | string | `""` | The priority class to use for cilium-operator |
| operator.prometheus | object | `{"enabled":true,"port":9963,"serviceMonitor":{"annotations":{},"enabled":false,"interval":"10s","jobLabel":"","labels":{},"metricRelabelings":null,"relabelings":null}}` | Enable prometheus metrics for cilium-operator on the configured port at /metrics |
| operator.prometheus.serviceMonitor.annotations | object | `{}` | Annotations to add to ServiceMonitor cilium-operator |
| operator.prometheus.serviceMonitor.enabled | bool | `false` | Enable service monitors. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml) |
| operator.prometheus.serviceMonitor.interval | string | `"10s"` | Interval for scrape metrics. |
| operator.prometheus.serviceMonitor.jobLabel | string | `""` | jobLabel to add for ServiceMonitor cilium-operator |
| operator.prometheus.serviceMonitor.labels | object | `{}` | Labels to add to ServiceMonitor cilium-operator |
| operator.prometheus.serviceMonitor.metricRelabelings | string | `nil` | Metrics relabeling configs for the ServiceMonitor cilium-operator |
| operator.prometheus.serviceMonitor.relabelings | string | `nil` | Relabeling configs for the ServiceMonitor cilium-operator |
| operator.removeNodeTaints | bool | `true` | Remove Cilium node taint from Kubernetes nodes that have a healthy Cilium pod running. |
| operator.replicas | int | `2` | Number of replicas to run for the cilium-operator deployment |
| operator.resources | object | `{}` | cilium-operator resource limits & requests ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/ |
| operator.rollOutPods | bool | `false` | Roll out cilium-operator pods automatically when configmap is updated. |
| operator.securityContext | object | `{}` | Security context to be added to cilium-operator pods |
| operator.setNodeNetworkStatus | bool | `true` | Set Node condition NetworkUnavailable to 'false' with the reason 'CiliumIsUp' for nodes that have a healthy Cilium pod. |
| operator.setNodeTaints | string | same as removeNodeTaints | Taint nodes where Cilium is scheduled but not running. This prevents pods from being scheduled to nodes where Cilium is not the default CNI provider. |
| operator.skipCNPStatusStartupClean | bool | `false` | Skip CNP node status clean up at operator startup. |
| operator.skipCRDCreation | bool | `false` | Skip CRDs creation for cilium-operator |
| operator.tolerations | list | `[{"operator":"Exists"}]` | Node tolerations for cilium-operator scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/ |
| operator.topologySpreadConstraints | list | `[]` | Pod topology spread constraints for cilium-operator |
| operator.unmanagedPodWatcher.intervalSeconds | int | `15` | Interval, in seconds, to check if there are any pods that are not managed by Cilium. |
| operator.unmanagedPodWatcher.restart | bool | `true` | Restart any pod that are not managed by Cilium. |
| operator.updateStrategy | object | `{"rollingUpdate":{"maxSurge":"25%","maxUnavailable":"50%"},"type":"RollingUpdate"}` | cilium-operator update strategy |
| pmtuDiscovery.enabled | bool | `false` | Enable path MTU discovery to send ICMP fragmentation-needed replies to the client. |
| podAnnotations | object | `{}` | Annotations to be added to agent pods |
| podLabels | object | `{}` | Labels to be added to agent pods |
| podSecurityContext | object | `{"appArmorProfile":{"type":"Unconfined"}}` | Security Context for cilium-agent pods. |
| podSecurityContext.appArmorProfile | object | `{"type":"Unconfined"}` | AppArmorProfile options for the `cilium-agent` and init containers |
| policyCIDRMatchMode | string | `nil` | policyCIDRMatchMode is a list of entities that may be selected by CIDR selector. The possible value is "nodes". |
| policyEnforcementMode | string | `"default"` | The agent can be put into one of the three policy enforcement modes: default, always and never. ref: https://docs.cilium.io/en/stable/security/policy/intro/#policy-enforcement-modes |
| pprof.address | string | `"localhost"` | Configure pprof listen address for cilium-agent |
| pprof.enabled | bool | `false` | Enable pprof for cilium-agent |
| pprof.port | int | `6060` | Configure pprof listen port for cilium-agent |
| preflight.affinity | object | `{"podAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"k8s-app":"cilium"}},"topologyKey":"kubernetes.io/hostname"}]}}` | Affinity for cilium-preflight |
| preflight.annotations | object | `{}` | Annotations to be added to all top-level preflight objects (resources under templates/cilium-preflight) |
| preflight.enabled | bool | `false` | Enable Cilium pre-flight resources (required for upgrade) |
| preflight.extraEnv | list | `[]` | Additional preflight environment variables. |
| preflight.extraVolumeMounts | list | `[]` | Additional preflight volumeMounts. |
| preflight.extraVolumes | list | `[]` | Additional preflight volumes. |
| preflight.image | object | `{"digest":"sha256:2e432bf6879feb8b891c497d6fd784b13e53456017d2b8e4ea734145f0282ef0","override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/cilium","tag":"v1.15.7","useDigest":true}` | Cilium pre-flight image. |
| preflight.nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node labels for preflight pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector |
| preflight.podAnnotations | object | `{}` | Annotations to be added to preflight pods |
| preflight.podDisruptionBudget.enabled | bool | `false` | enable PodDisruptionBudget ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/ |
| preflight.podDisruptionBudget.maxUnavailable | int | `1` | Maximum number/percentage of pods that may be made unavailable |
| preflight.podDisruptionBudget.minAvailable | string | `nil` | Minimum number/percentage of pods that should remain scheduled. When it's set, maxUnavailable must be disabled by `maxUnavailable: null` |
| preflight.podLabels | object | `{}` | Labels to be added to the preflight pod. |
| preflight.podSecurityContext | object | `{}` | Security context to be added to preflight pods. |
| preflight.priorityClassName | string | `""` | The priority class to use for the preflight pod. |
| preflight.resources | object | `{}` | preflight resource limits & requests ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/ |
| preflight.securityContext | object | `{}` | Security context to be added to preflight pods |
| preflight.terminationGracePeriodSeconds | int | `1` | Configure termination grace period for preflight Deployment and DaemonSet. |
| preflight.tofqdnsPreCache | string | `""` | Path to write the `--tofqdns-pre-cache` file to. |
| preflight.tolerations | list | `[{"effect":"NoSchedule","key":"node.kubernetes.io/not-ready"},{"effect":"NoSchedule","key":"node-role.kubernetes.io/master"},{"effect":"NoSchedule","key":"node-role.kubernetes.io/control-plane"},{"effect":"NoSchedule","key":"node.cloudprovider.kubernetes.io/uninitialized","value":"true"},{"key":"CriticalAddonsOnly","operator":"Exists"}]` | Node tolerations for preflight scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/ |
| preflight.updateStrategy | object | `{"type":"RollingUpdate"}` | preflight update strategy |
| preflight.validateCNPs | bool | `true` | By default we should always validate the installed CNPs before upgrading Cilium. This will make sure the user will have the policies deployed in the cluster with the right schema. |
| priorityClassName | string | `""` | The priority class to use for cilium-agent. |
| prometheus | object | `{"controllerGroupMetrics":["write-cni-file","sync-host-ips","sync-lb-maps-with-k8s-services"],"enabled":false,"metrics":null,"port":9962,"serviceMonitor":{"annotations":{},"enabled":false,"interval":"10s","jobLabel":"","labels":{},"metricRelabelings":null,"relabelings":[{"replacement":"${1}","sourceLabels":["__meta_kubernetes_pod_node_name"],"targetLabel":"node"}],"trustCRDsExist":false}}` | Configure prometheus metrics on the configured port at /metrics |
| prometheus.controllerGroupMetrics | list | `["write-cni-file","sync-host-ips","sync-lb-maps-with-k8s-services"]` | - Enable controller group metrics for monitoring specific Cilium subsystems. The list is a list of controller group names. The special values of "all" and "none" are supported. The set of controller group names is not guaranteed to be stable between Cilium versions. |
| prometheus.metrics | string | `nil` | Metrics that should be enabled or disabled from the default metric list. The list is expected to be separated by a space. (+metric_foo to enable metric_foo , -metric_bar to disable metric_bar). ref: https://docs.cilium.io/en/stable/observability/metrics/ |
| prometheus.serviceMonitor.annotations | object | `{}` | Annotations to add to ServiceMonitor cilium-agent |
| prometheus.serviceMonitor.enabled | bool | `false` | Enable service monitors. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml) |
| prometheus.serviceMonitor.interval | string | `"10s"` | Interval for scrape metrics. |
| prometheus.serviceMonitor.jobLabel | string | `""` | jobLabel to add for ServiceMonitor cilium-agent |
| prometheus.serviceMonitor.labels | object | `{}` | Labels to add to ServiceMonitor cilium-agent |
| prometheus.serviceMonitor.metricRelabelings | string | `nil` | Metrics relabeling configs for the ServiceMonitor cilium-agent |
| prometheus.serviceMonitor.relabelings | list | `[{"replacement":"${1}","sourceLabels":["__meta_kubernetes_pod_node_name"],"targetLabel":"node"}]` | Relabeling configs for the ServiceMonitor cilium-agent |
| prometheus.serviceMonitor.trustCRDsExist | bool | `false` | Set to `true` and helm will not check for monitoring.coreos.com/v1 CRDs before deploying |
| proxy | object | `{"prometheus":{"enabled":true,"port":null},"sidecarImageRegex":"cilium/istio_proxy"}` | Configure Istio proxy options. |
| proxy.prometheus.enabled | bool | `true` | Deprecated in favor of envoy.prometheus.enabled |
| proxy.prometheus.port | string | `nil` | Deprecated in favor of envoy.prometheus.port |
| proxy.sidecarImageRegex | string | `"cilium/istio_proxy"` | Regular expression matching compatible Istio sidecar istio-proxy container image names |
| rbac.create | bool | `true` | Enable creation of Resource-Based Access Control configuration. |
| readinessProbe.failureThreshold | int | `3` | failure threshold of readiness probe |
| readinessProbe.periodSeconds | int | `30` | interval between checks of the readiness probe |
| remoteNodeIdentity | bool | `true` | Enable use of the remote node identity. ref: https://docs.cilium.io/en/v1.7/install/upgrade/#configmap-remote-node-identity Deprecated without replacement in 1.15. To be removed in 1.16. |
| resourceQuotas | object | `{"cilium":{"hard":{"pods":"10k"}},"enabled":false,"operator":{"hard":{"pods":"15"}}}` | Enable resource quotas for priority classes used in the cluster. |
| resources | object | `{}` | Agent resource limits & requests ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/ |
| rollOutCiliumPods | bool | `false` | Roll out cilium agent pods automatically when configmap is updated. |
| routingMode | string | `"tunnel"` | Enable native-routing mode or tunneling mode. Possible values:   - ""   - native   - tunnel |
| sctp | object | `{"enabled":false}` | SCTP Configuration Values |
| sctp.enabled | bool | `false` | Enable SCTP support. NOTE: Currently, SCTP support does not support rewriting ports or multihoming. |
| securityContext.capabilities.applySysctlOverwrites | list | `["SYS_ADMIN","SYS_CHROOT","SYS_PTRACE"]` | capabilities for the `apply-sysctl-overwrites` init container |
| securityContext.capabilities.ciliumAgent | list | `["CHOWN","KILL","NET_ADMIN","NET_RAW","IPC_LOCK","SYS_MODULE","SYS_ADMIN","SYS_RESOURCE","DAC_OVERRIDE","FOWNER","SETGID","SETUID"]` | Capabilities for the `cilium-agent` container |
| securityContext.capabilities.cleanCiliumState | list | `["NET_ADMIN","SYS_MODULE","SYS_ADMIN","SYS_RESOURCE"]` | Capabilities for the `clean-cilium-state` init container |
| securityContext.capabilities.mountCgroup | list | `["SYS_ADMIN","SYS_CHROOT","SYS_PTRACE"]` | Capabilities for the `mount-cgroup` init container |
| securityContext.privileged | bool | `false` | Run the pod with elevated privileges |
| securityContext.seLinuxOptions | object | `{"level":"s0","type":"spc_t"}` | SELinux options for the `cilium-agent` and init containers |
| serviceAccounts | object | Component's fully qualified name. | Define serviceAccount names for components. |
| serviceAccounts.clustermeshcertgen | object | `{"annotations":{},"automount":true,"create":true,"name":"clustermesh-apiserver-generate-certs"}` | Clustermeshcertgen is used if clustermesh.apiserver.tls.auto.method=cronJob |
| serviceAccounts.hubblecertgen | object | `{"annotations":{},"automount":true,"create":true,"name":"hubble-generate-certs"}` | Hubblecertgen is used if hubble.tls.auto.method=cronJob |
| serviceAccounts.nodeinit.enabled | bool | `false` | Enabled is temporary until https://github.com/cilium/cilium-cli/issues/1396 is implemented. Cilium CLI doesn't create the SAs for node-init, thus the workaround. Helm is not affected by this issue. Name and automount can be configured, if enabled is set to true. Otherwise, they are ignored. Enabled can be removed once the issue is fixed. Cilium-nodeinit DS must also be fixed. |
| serviceNoBackendResponse | string | `"reject"` | Configure what the response should be to traffic for a service without backends. "reject" only works on kernels >= 5.10, on lower kernels we fallback to "drop". Possible values:  - reject (default)  - drop |
| sleepAfterInit | bool | `false` | Do not run Cilium agent when running with clean mode. Useful to completely uninstall Cilium as it will stop Cilium from starting and create artifacts in the node. |
| socketLB | object | `{"enabled":false}` | Configure socket LB |
| socketLB.enabled | bool | `false` | Enable socket LB |
| startupProbe.failureThreshold | int | `105` | failure threshold of startup probe. 105 x 2s translates to the old behaviour of the readiness probe (120s delay + 30 x 3s) |
| startupProbe.periodSeconds | int | `2` | interval between checks of the startup probe |
| svcSourceRangeCheck | bool | `true` | Enable check of service source ranges (currently, only for LoadBalancer). |
| synchronizeK8sNodes | bool | `true` | Synchronize Kubernetes nodes to kvstore and perform CNP GC. |
| sysctlfix | object | `{"enabled":true}` | Configure sysctl override described in #20072. |
| sysctlfix.enabled | bool | `true` | Enable the sysctl override. When enabled, the init container will mount the /proc of the host so that the `sysctlfix` utility can execute. |
| terminationGracePeriodSeconds | int | `1` | Configure termination grace period for cilium-agent DaemonSet. |
| tls | object | `{"ca":{"cert":"","certValidityDuration":1095,"key":""},"caBundle":{"enabled":false,"key":"ca.crt","name":"cilium-root-ca.crt","useSecret":false},"secretsBackend":"local"}` | Configure TLS configuration in the agent. |
| tls.ca | object | `{"cert":"","certValidityDuration":1095,"key":""}` | Base64 encoded PEM values for the CA certificate and private key. This can be used as common CA to generate certificates used by hubble and clustermesh components. It is neither required nor used when cert-manager is used to generate the certificates. |
| tls.ca.cert | string | `""` | Optional CA cert. If it is provided, it will be used by cilium to generate all other certificates. Otherwise, an ephemeral CA is generated. |
| tls.ca.certValidityDuration | int | `1095` | Generated certificates validity duration in days. This will be used for auto generated CA. |
| tls.ca.key | string | `""` | Optional CA private key. If it is provided, it will be used by cilium to generate all other certificates. Otherwise, an ephemeral CA is generated. |
| tls.caBundle | object | `{"enabled":false,"key":"ca.crt","name":"cilium-root-ca.crt","useSecret":false}` | Configure the CA trust bundle used for the validation of the certificates leveraged by hubble and clustermesh. When enabled, it overrides the content of the 'ca.crt' field of the respective certificates, allowing for CA rotation with no down-time. |
| tls.caBundle.enabled | bool | `false` | Enable the use of the CA trust bundle. |
| tls.caBundle.key | string | `"ca.crt"` | Entry of the ConfigMap containing the CA trust bundle. |
| tls.caBundle.name | string | `"cilium-root-ca.crt"` | Name of the ConfigMap containing the CA trust bundle. |
| tls.caBundle.useSecret | bool | `false` | Use a Secret instead of a ConfigMap. |
| tls.secretsBackend | string | `"local"` | This configures how the Cilium agent loads the secrets used TLS-aware CiliumNetworkPolicies (namely the secrets referenced by terminatingTLS and originatingTLS). Possible values:   - local   - k8s |
| tolerations | list | `[{"operator":"Exists"}]` | Node tolerations for agent scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/ |
| tunnelPort | int | Port 8472 for VXLAN, Port 6081 for Geneve | Configure VXLAN and Geneve tunnel port. |
| tunnelProtocol | string | `"vxlan"` | Tunneling protocol to use in tunneling mode and for ad-hoc tunnels. Possible values:   - ""   - vxlan   - geneve |
| updateStrategy | object | `{"rollingUpdate":{"maxUnavailable":2},"type":"RollingUpdate"}` | Cilium agent update strategy |
| vtep.cidr | string | `""` | A space separated list of VTEP device CIDRs, for example "1.1.1.0/24 1.1.2.0/24" |
| vtep.enabled | bool | `false` | Enables VXLAN Tunnel Endpoint (VTEP) Integration (beta) to allow Cilium-managed pods to talk to third party VTEP devices over Cilium tunnel. |
| vtep.endpoint | string | `""` | A space separated list of VTEP device endpoint IPs, for example "1.1.1.1  1.1.2.1" |
| vtep.mac | string | `""` | A space separated list of VTEP device MAC addresses (VTEP MAC), for example "x:x:x:x:x:x  y:y:y:y:y:y:y" |
| vtep.mask | string | `""` | VTEP CIDRs Mask that applies to all VTEP CIDRs, for example "255.255.255.0" |
| waitForKubeProxy | bool | `false` | Wait for KUBE-PROXY-CANARY iptables rule to appear in "wait-for-kube-proxy" init container before launching cilium-agent. More context can be found in the commit message of below PR https://github.com/cilium/cilium/pull/20123 |
| wellKnownIdentities.enabled | bool | `false` | Enable the use of well-known identities. |
