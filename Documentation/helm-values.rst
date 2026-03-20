..
  AUTO-GENERATED. Please DO NOT edit manually.

|||||
|||||
| Key | Description | Type | Default |
|-----|-------------|------|---------|
| MTU | Configure the underlying network MTU to overwrite auto-detected MTU. This value doesn't change the host network interface MTU i.e. eth0 or ens0. It changes the MTU for cilium_net@cilium_host, cilium_host@cilium_net, cilium_vxlan and lxc_health interfaces. | int | `0` |
| affinity | Affinity for cilium-agent. | object | `{"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"k8s-app":"cilium"}},"topologyKey":"kubernetes.io/hostname"}]}}` |
| agent | Install the cilium agent resources. | bool | `true` |
| agentNotReadyTaintKey | Configure the key of the taint indicating that Cilium is not ready on the node. When set to a value starting with `ignore-taint.cluster-autoscaler.kubernetes.io/`, the Cluster Autoscaler will ignore the taint on its decisions, allowing the cluster to scale up. | string | `"node.cilium.io/agent-not-ready"` |
| aksbyocni.enabled | Enable AKS BYOCNI integration. Note that this is incompatible with AKS clusters not created in BYOCNI mode: use Azure integration (`azure.enabled`) instead. | bool | `false` |
| alibabacloud.enabled | Enable AlibabaCloud ENI integration | bool | `false` |
| alibabacloud.nodeSpec.securityGroupTags |  | list | `[]` |
| alibabacloud.nodeSpec.securityGroups |  | list | `[]` |
| alibabacloud.nodeSpec.vSwitchTags |  | list | `[]` |
| alibabacloud.nodeSpec.vSwitches |  | list | `[]` |
| annotateK8sNode | Annotate k8s node upon initialization with Cilium's metadata. | bool | `false` |
| annotations | Annotations to be added to all top-level cilium-agent objects (resources under templates/cilium-agent) | object | `{}` |
| apiRateLimit | The api-rate-limit option can be used to overwrite individual settings of the default configuration for rate limiting calls to the Cilium Agent API | string | `nil` |
| authentication.enabled | Enable authentication processing and garbage collection. Note that if disabled, policy enforcement will still block requests that require authentication. But the resulting authentication requests for these requests will not be processed, therefore the requests not be allowed. | bool | `false` |
| authentication.gcInterval | Interval for garbage collection of auth map entries. | string | `"5m0s"` |
| authentication.mutual.connectTimeout | Timeout for connecting to the remote node TCP socket | string | `"5s"` |
| authentication.mutual.port | Port on the agent where mutual authentication handshakes between agents will be performed | int | `4250` |
| authentication.mutual.spire.adminSocketPath | SPIRE socket path where the SPIRE delegated api agent is listening | string | `"/run/spire/sockets/admin.sock"` |
| authentication.mutual.spire.agentSocketPath | SPIRE socket path where the SPIRE workload agent is listening. Applies to both the Cilium Agent and Operator | string | `"/run/spire/sockets/agent/agent.sock"` |
| authentication.mutual.spire.annotations | Annotations to be added to all top-level spire objects (resources under templates/spire) | object | `{}` |
| authentication.mutual.spire.connectionTimeout | SPIRE connection timeout | string | `"30s"` |
| authentication.mutual.spire.enabled | Enable SPIRE integration (beta) | bool | `false` |
| authentication.mutual.spire.install.agent.affinity | SPIRE agent affinity configuration | object | `{}` |
| authentication.mutual.spire.install.agent.annotations | SPIRE agent annotations | object | `{}` |
| authentication.mutual.spire.install.agent.image | SPIRE agent image | object | `{"digest":"sha256:f8c40f435d42bd8b5420768b95f6b41acc695fb13cd9f9728d27c8e21e07d803","override":null,"pullPolicy":"Always","repository":"ghcr.io/spiffe/spire-agent","tag":"1.14.2","useDigest":true}` |
| authentication.mutual.spire.install.agent.labels | SPIRE agent labels | object | `{}` |
| authentication.mutual.spire.install.agent.nodeSelector | SPIRE agent nodeSelector configuration ref: ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector | object | `{}` |
| authentication.mutual.spire.install.agent.podSecurityContext | Security context to be added to spire agent pods. SecurityContext holds pod-level security attributes and common container settings. ref: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-security-context-for-a-pod | object | `{}` |
| authentication.mutual.spire.install.agent.priorityClassName | The priority class to use for the spire agent | string | `""` |
| authentication.mutual.spire.install.agent.resources | container resource limits & requests | object | `{}` |
| authentication.mutual.spire.install.agent.securityContext | Security context to be added to spire agent containers. SecurityContext holds pod-level security attributes and common container settings. ref: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-security-context-for-a-container | object | `{}` |
| authentication.mutual.spire.install.agent.serviceAccount | SPIRE agent service account | object | `{"create":true,"name":"spire-agent"}` |
| authentication.mutual.spire.install.agent.skipKubeletVerification | SPIRE Workload Attestor kubelet verification. | bool | `true` |
| authentication.mutual.spire.install.agent.tolerations | SPIRE agent tolerations configuration By default it follows the same tolerations as the agent itself to allow the Cilium agent on this node to connect to SPIRE. ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/ | list | `[{"effect":"NoSchedule","key":"node.kubernetes.io/not-ready"},{"effect":"NoSchedule","key":"node-role.kubernetes.io/master"},{"effect":"NoSchedule","key":"node-role.kubernetes.io/control-plane"},{"effect":"NoSchedule","key":"node.cloudprovider.kubernetes.io/uninitialized","value":"true"},{"key":"CriticalAddonsOnly","operator":"Exists"}]` |
| authentication.mutual.spire.install.enabled | Enable SPIRE installation. This will only take effect only if authentication.mutual.spire.enabled is true | bool | `true` |
| authentication.mutual.spire.install.existingNamespace | SPIRE namespace already exists. Set to true if Helm should not create, manage, and import the SPIRE namespace. | bool | `false` |
| authentication.mutual.spire.install.initImage | init container image of SPIRE agent and server | object | `{"digest":"sha256:b3255e7dfbcd10cb367af0d409747d511aeb66dfac98cf30e97e87e4207dd76f","override":null,"pullPolicy":"Always","repository":"docker.io/library/busybox","tag":"1.37.0","useDigest":true}` |
| authentication.mutual.spire.install.namespace | SPIRE namespace to install into | string | `"cilium-spire"` |
| authentication.mutual.spire.install.server.affinity | SPIRE server affinity configuration | object | `{}` |
| authentication.mutual.spire.install.server.annotations | SPIRE server annotations | object | `{}` |
| authentication.mutual.spire.install.server.ca.keyType | SPIRE CA key type AWS requires the use of RSA. EC cryptography is not supported | string | `"rsa-4096"` |
| authentication.mutual.spire.install.server.ca.subject | SPIRE CA Subject | object | `{"commonName":"Cilium SPIRE CA","country":"US","organization":"SPIRE"}` |
| authentication.mutual.spire.install.server.dataStorage.accessMode | Access mode of the SPIRE server data storage | string | `"ReadWriteOnce"` |
| authentication.mutual.spire.install.server.dataStorage.enabled | Enable SPIRE server data storage | bool | `true` |
| authentication.mutual.spire.install.server.dataStorage.size | Size of the SPIRE server data storage | string | `"1Gi"` |
| authentication.mutual.spire.install.server.dataStorage.storageClass | StorageClass of the SPIRE server data storage | string | `nil` |
| authentication.mutual.spire.install.server.image | SPIRE server image | object | `{"digest":"sha256:12f30ce1b6e298cf0dc7bedd5a67b174f03a4c5130ab825fba0ec3dcf407d0b2","override":null,"pullPolicy":"Always","repository":"ghcr.io/spiffe/spire-server","tag":"1.14.2","useDigest":true}` |
| authentication.mutual.spire.install.server.initContainers | SPIRE server init containers | list | `[]` |
| authentication.mutual.spire.install.server.labels | SPIRE server labels | object | `{}` |
| authentication.mutual.spire.install.server.nodeSelector | SPIRE server nodeSelector configuration ref: ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector | object | `{}` |
| authentication.mutual.spire.install.server.podSecurityContext | Security context to be added to spire server pods. SecurityContext holds pod-level security attributes and common container settings. ref: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-security-context-for-a-pod | object | `{}` |
| authentication.mutual.spire.install.server.priorityClassName | The priority class to use for the spire server | string | `""` |
| authentication.mutual.spire.install.server.resources | container resource limits & requests | object | `{}` |
| authentication.mutual.spire.install.server.securityContext | Security context to be added to spire server containers. SecurityContext holds pod-level security attributes and common container settings. ref: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-security-context-for-a-container | object | `{}` |
| authentication.mutual.spire.install.server.service.annotations | Annotations to be added to the SPIRE server service | object | `{}` |
| authentication.mutual.spire.install.server.service.labels | Labels to be added to the SPIRE server service | object | `{}` |
| authentication.mutual.spire.install.server.service.type | Service type for the SPIRE server service | string | `"ClusterIP"` |
| authentication.mutual.spire.install.server.serviceAccount | SPIRE server service account | object | `{"create":true,"name":"spire-server"}` |
| authentication.mutual.spire.install.server.tolerations | SPIRE server tolerations configuration ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/ | list | `[]` |
| authentication.mutual.spire.serverAddress | SPIRE server address used by Cilium Operator  If k8s Service DNS along with port number is used (e.g. <service-name>.<namespace>.svc(.*):<port-number> format), Cilium Operator will resolve its address by looking up the clusterIP from Service resource.  Example values: 10.0.0.1:8081, spire-server.cilium-spire.svc:8081 | string | `nil` |
| authentication.mutual.spire.trustDomain | SPIFFE trust domain to use for fetching certificates | string | `"spiffe.cilium"` |
| authentication.queueSize | Buffer size of the channel Cilium uses to receive authentication events from the signal map. | int | `1024` |
| authentication.rotatedIdentitiesQueueSize | Buffer size of the channel Cilium uses to receive certificate expiration events from auth handlers. | int | `1024` |
| autoDirectNodeRoutes | Enable installation of PodCIDR routes between worker nodes if worker nodes share a common L2 network segment. | bool | `false` |
| azure.enabled | Enable Azure integration. Note that this is incompatible with AKS clusters created in BYOCNI mode: use AKS BYOCNI integration (`aksbyocni.enabled`) instead. | bool | `false` |
| azure.nodeSpec.azureInterfaceName |  | string | `""` |
| bandwidthManager | Enable bandwidth manager to optimize TCP and UDP workloads and allow for rate-limiting traffic from individual Pods with EDT (Earliest Departure Time) through the "kubernetes.io/egress-bandwidth" Pod annotation. | object | `{"bbr":false,"bbrHostNamespaceOnly":false,"enabled":false}` |
| bandwidthManager.bbr | Activate BBR TCP congestion control for Pods | bool | `false` |
| bandwidthManager.bbrHostNamespaceOnly | Activate BBR TCP congestion control for Pods in the host namespace only. | bool | `false` |
| bandwidthManager.enabled | Enable bandwidth manager infrastructure (also prerequirement for BBR) | bool | `false` |
| bgpControlPlane | This feature set enables virtual BGP routers to be created via BGP CRDs. | object | `{"enabled":false,"legacyOriginAttribute":{"enabled":false},"routerIDAllocation":{"ipPool":"","mode":"default"},"secretsNamespace":{"create":false,"name":"kube-system"},"statusReport":{"enabled":true}}` |
| bgpControlPlane.enabled | Enables the BGP control plane. | bool | `false` |
| bgpControlPlane.legacyOriginAttribute | Legacy BGP ORIGIN attribute settings | object | `{"enabled":false}` |
| bgpControlPlane.legacyOriginAttribute.enabled | Enable/Disable advertising LoadBalancerIP routes with the legacy BGP ORIGIN attribute value INCOMPLETE (2) instead of the default IGP (0). Enable for compatibility with the legacy behavior of MetalLB integration. | bool | `false` |
| bgpControlPlane.routerIDAllocation | BGP router-id allocation mode | object | `{"ipPool":"","mode":"default"}` |
| bgpControlPlane.routerIDAllocation.ipPool | IP pool to allocate the BGP router-id from when the mode is ip-pool. | string | `""` |
| bgpControlPlane.routerIDAllocation.mode | BGP router-id allocation mode. In default mode, the router-id is derived from the IPv4 address if it is available, or else it is determined by the lower 32 bits of the MAC address. | string | `"default"` |
| bgpControlPlane.secretsNamespace | SecretsNamespace is the namespace which BGP support will retrieve secrets from. | object | `{"create":false,"name":"kube-system"}` |
| bgpControlPlane.secretsNamespace.create | Create secrets namespace for BGP secrets. | bool | `false` |
| bgpControlPlane.secretsNamespace.name | The name of the secret namespace to which Cilium agents are given read access | string | `"kube-system"` |
| bgpControlPlane.statusReport | Status reporting settings | object | `{"enabled":true}` |
| bgpControlPlane.statusReport.enabled | Enable/Disable BGP status reporting It is recommended to enable status reporting in general, but if you have any issue such as high API server load, you can disable it by setting this to false. | bool | `true` |
| bpf.authMapMax | Configure the maximum number of entries in auth map. | int | `524288` |
| bpf.autoMount.enabled | Enable automatic mount of BPF filesystem When `autoMount` is enabled, the BPF filesystem is mounted at `bpf.root` path on the underlying host and inside the cilium agent pod. If users disable `autoMount`, it's expected that users have mounted bpffs filesystem at the specified `bpf.root` volume, and then the volume will be mounted inside the cilium agent pod at the same path. | bool | `true` |
| bpf.ctAccounting | Enable CT accounting for packets and bytes | bool | `false` |
| bpf.ctAnyMax | Configure the maximum number of entries for the non-TCP connection tracking table. | int | `262144` |
| bpf.ctTcpMax | Configure the maximum number of entries in the TCP connection tracking table. | int | `524288` |
| bpf.datapathMode | Mode for Pod devices for the core datapath (auto, veth, netkit, netkit-l2). Note netkit is incompatible with TPROXY (`bpf.tproxy`). | string | `veth` |
| bpf.disableExternalIPMitigation | Disable ExternalIP mitigation (CVE-2020-8554) | bool | `false` |
| bpf.distributedLRU | Control to use a distributed per-CPU backend memory for the core BPF LRU maps which Cilium uses. This improves performance significantly, but it is also recommended to increase BPF map sizing along with that. | object | `{"enabled":false}` |
| bpf.distributedLRU.enabled | Enable distributed LRU backend memory. For compatibility with existing installations it is off by default. | bool | `false` |
| bpf.enableTCX | Attach endpoint programs using tcx instead of legacy tc hooks on supported kernels. | bool | `true` |
| bpf.events | Control events generated by the Cilium datapath exposed to Cilium monitor and Hubble. Helm configuration for BPF events map rate limiting is experimental and might change in upcoming releases. | object | `{"default":{"burstLimit":null,"rateLimit":null},"drop":{"enabled":true},"policyVerdict":{"enabled":true},"trace":{"enabled":true}}` |
| bpf.events.default | Default settings for all types of events except dbg. | object | `{"burstLimit":null,"rateLimit":null}` |
| bpf.events.default.burstLimit | Configure the maximum number of messages that can be written to BPF events map in 1 second. If burstLimit is greater than 0, non-zero value for rateLimit must also be provided lest the configuration is considered invalid. Setting both burstLimit and rateLimit to 0 disables BPF events rate limiting. | int | `0` |
| bpf.events.default.rateLimit | Configure the limit of messages per second that can be written to BPF events map. The number of messages is averaged, meaning that if no messages were written to the map over 5 seconds, it's possible to write more events in the 6th second. If rateLimit is greater than 0, non-zero value for burstLimit must also be provided lest the configuration is considered invalid. Setting both burstLimit and rateLimit to 0 disables BPF events rate limiting. | int | `0` |
| bpf.events.drop.enabled | Enable drop events. | bool | `true` |
| bpf.events.policyVerdict.enabled | Enable policy verdict events. | bool | `true` |
| bpf.events.trace.enabled | Enable trace events. | bool | `true` |
| bpf.hostLegacyRouting | Configure whether direct routing mode should route traffic via host stack (true) or directly and more efficiently out of BPF (false) if the kernel supports it. The latter has the implication that it will also bypass netfilter in the host namespace. | bool | `false` |
| bpf.lbAlgorithmAnnotation | Enable the option to define the load balancing algorithm on a per-service basis through service.cilium.io/lb-algorithm annotation. | bool | `false` |
| bpf.lbExternalClusterIP | Allow cluster external access to ClusterIP services. | bool | `false` |
| bpf.lbMapMax | Configure the maximum number of service entries in the load balancer maps. | int | `65536` |
| bpf.lbModeAnnotation | Enable the option to define the load balancing mode (SNAT or DSR) on a per-service basis through service.cilium.io/forwarding-mode annotation. | bool | `false` |
| bpf.lbSourceRangeAllTypes | Enable loadBalancerSourceRanges CIDR filtering for all service types, not just LoadBalancer services. The corresponding NodePort and ClusterIP (if enabled for cluster-external traffic) will also apply the CIDR filter. | bool | `false` |
| bpf.mapDynamicSizeRatio | Configure auto-sizing for all BPF maps based on available memory. ref: https://docs.cilium.io/en/stable/network/ebpf/maps/ | float64 | `0.0025` |
| bpf.masquerade | Enable native IP masquerade support in eBPF | bool | `false` |
| bpf.monitorAggregation | Configure the level of aggregation for monitor notifications. Valid options are none, low, medium, maximum. | string | `"medium"` |
| bpf.monitorFlags | Configure which TCP flags trigger notifications when seen for the first time in a connection. | string | `"all"` |
| bpf.monitorInterval | Configure the typical time between monitor notifications for active connections. | string | `"5s"` |
| bpf.monitorTraceIPOption | Configure the IP tracing option type. This option is used to specify the IP option type to use for tracing. The value must be an integer between 0 and 255. @schema type: [null, integer] minimum: 0 maximum: 255 @schema | int | `0` |
| bpf.natMax | Configure the maximum number of entries for the NAT table. | int | `524288` |
| bpf.neighMax | Configure the maximum number of entries for the neighbor table. | int | `524288` |
| bpf.nodeMapMax | Configures the maximum number of entries for the node table. | int | `nil` |
| bpf.policyMapMax | Configure the maximum number of entries in endpoint policy map (per endpoint). @schema type: [null, integer] @schema | int | `16384` |
| bpf.policyMapPressureMetricsThreshold | Configure threshold for emitting pressure metrics of policy maps. @schema type: [null, number] @schema | float64 | `0.1` |
| bpf.policyStatsMapMax | Configure the maximum number of entries in global policy stats map. @schema type: [null, integer] @schema | int | `65536` |
| bpf.preallocateMaps | Enables pre-allocation of eBPF map values. This increases memory usage but can reduce latency. | bool | `false` |
| bpf.root | Configure the mount point for the BPF filesystem | string | `"/sys/fs/bpf"` |
| bpf.tproxy | Configure the eBPF-based TPROXY (beta) to reduce reliance on iptables rules for implementing Layer 7 policy. Note this is incompatible with netkit (`bpf.datapathMode=netkit`, `bpf.datapathMode=netkit-l2`). | bool | `false` |
| bpf.vlanBypass | Configure explicitly allowed VLAN id's for bpf logic bypass. [0] will allow all VLAN id's without any filtering. | list | `[]` |
| bpfClockProbe | Enable BPF clock source probing for more efficient tick retrieval. | bool | `false` |
| certgen | Configure certificate generation for Hubble integration. If hubble.tls.auto.method=cronJob, these values are used for the Kubernetes CronJob which will be scheduled regularly to (re)generate any certificates not provided manually. | object | `{"affinity":{},"annotations":{"cronJob":{},"job":{}},"cronJob":{"failedJobsHistoryLimit":1,"successfulJobsHistoryLimit":3},"extraVolumeMounts":[],"extraVolumes":[],"generateCA":true,"image":{"digest":"sha256:f0c656830e856d26b24b0e144df1f8b327d3b46748d76a630514111fc365b697","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/certgen","tag":"v0.4.1","useDigest":true},"nodeSelector":{},"podLabels":{},"priorityClassName":"","resources":{},"tolerations":[],"ttlSecondsAfterFinished":null}` |
| certgen.affinity | Affinity for certgen | object | `{}` |
| certgen.annotations | Annotations to be added to the hubble-certgen initial Job and CronJob | object | `{"cronJob":{},"job":{}}` |
| certgen.cronJob.failedJobsHistoryLimit | The number of failed finished jobs to keep | int | `1` |
| certgen.cronJob.successfulJobsHistoryLimit | The number of successful finished jobs to keep | int | `3` |
| certgen.extraVolumeMounts | Additional certgen volumeMounts. | list | `[]` |
| certgen.extraVolumes | Additional certgen volumes. | list | `[]` |
| certgen.generateCA | When set to true the certificate authority secret is created. | bool | `true` |
| certgen.nodeSelector | Node selector for certgen ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector | object | `{}` |
| certgen.podLabels | Labels to be added to hubble-certgen pods | object | `{}` |
| certgen.priorityClassName | Priority class for certgen ref: https://kubernetes.io/docs/concepts/scheduling-eviction/pod-priority-preemption/#priorityclass | string | `""` |
| certgen.resources | Resource limits for certgen ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers | object | `{}` |
| certgen.tolerations | Node tolerations for pod assignment on nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/ | list | `[]` |
| certgen.ttlSecondsAfterFinished | Seconds after which the completed job pod will be deleted | string | `nil` |
| cgroup | Configure cgroup related configuration | object | `{"autoMount":{"enabled":true,"resources":{}},"hostRoot":"/run/cilium/cgroupv2"}` |
| cgroup.autoMount.enabled | Enable auto mount of cgroup2 filesystem. When `autoMount` is enabled, cgroup2 filesystem is mounted at `cgroup.hostRoot` path on the underlying host and inside the cilium agent pod. If users disable `autoMount`, it's expected that users have mounted cgroup2 filesystem at the specified `cgroup.hostRoot` volume, and then the volume will be mounted inside the cilium agent pod at the same path. | bool | `true` |
| cgroup.autoMount.resources | Init Container Cgroup Automount resource limits & requests | object | `{}` |
| cgroup.hostRoot | Configure cgroup root where cgroup2 filesystem is mounted on the host (see also: `cgroup.autoMount`) | string | `"/run/cilium/cgroupv2"` |
| ciliumEndpointSlice | CiliumEndpointSlice configuration options. | object | `{"enabled":false,"rateLimits":[{"burst":20,"limit":10,"nodes":0},{"burst":100,"limit":50,"nodes":100}]}` |
| ciliumEndpointSlice.enabled | Enable Cilium EndpointSlice feature. | bool | `false` |
| ciliumEndpointSlice.rateLimits | List of rate limit options to be used for the CiliumEndpointSlice controller. Each object in the list must have the following fields: nodes: Count of nodes at which to apply the rate limit. limit: The sustained request rate in requests per second. The maximum rate that can be configured is 50. burst: The burst request rate in requests per second. The maximum burst that can be configured is 100. | list | `[{"burst":20,"limit":10,"nodes":0},{"burst":100,"limit":50,"nodes":100}]` |
| cleanBpfState | Clean all eBPF datapath state from the initContainer of the cilium-agent DaemonSet.  WARNING: Use with care! | bool | `false` |
| cleanState | Clean all local Cilium state from the initContainer of the cilium-agent DaemonSet. Implies cleanBpfState: true.  WARNING: Use with care! | bool | `false` |
| cluster.id | Unique ID of the cluster. Must be unique across all connected clusters and in the range of 1 to 255. Only required for Cluster Mesh, may be 0 if Cluster Mesh is not used. | int | `0` |
| cluster.name | Name of the cluster. Only required for Cluster Mesh and mutual authentication with SPIRE. It must respect the following constraints: * It must contain at most 32 characters; * It must begin and end with a lower case alphanumeric character; * It may contain lower case alphanumeric characters and dashes between. The "default" name cannot be used if the Cluster ID is different from 0. | string | `"default"` |
| clustermesh.annotations | Annotations to be added to all top-level clustermesh objects (resources under templates/clustermesh-apiserver and templates/clustermesh-config) | object | `{}` |
| clustermesh.apiserver.affinity | Affinity for clustermesh.apiserver | object | `{"podAntiAffinity":{"preferredDuringSchedulingIgnoredDuringExecution":[{"podAffinityTerm":{"labelSelector":{"matchLabels":{"k8s-app":"clustermesh-apiserver"}},"topologyKey":"kubernetes.io/hostname"},"weight":100}]}}` |
| clustermesh.apiserver.etcd.init.extraArgs | Additional arguments to `clustermesh-apiserver etcdinit`. | list | `[]` |
| clustermesh.apiserver.etcd.init.extraEnv | Additional environment variables to `clustermesh-apiserver etcdinit`. | list | `[]` |
| clustermesh.apiserver.etcd.init.resources | Specifies the resources for etcd init container in the apiserver | object | `{}` |
| clustermesh.apiserver.etcd.lifecycle | lifecycle setting for the etcd container | object | `{}` |
| clustermesh.apiserver.etcd.resources | Specifies the resources for etcd container in the apiserver | object | `{}` |
| clustermesh.apiserver.etcd.securityContext | Security context to be added to clustermesh-apiserver etcd containers | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}` |
| clustermesh.apiserver.etcd.storageMedium | Specifies whether etcd data is stored in a temporary volume backed by the node's default medium, such as disk, SSD or network storage (Disk), or RAM (Memory). The Memory option enables improved etcd read and write performance at the cost of additional memory usage, which counts against the memory limits of the container. | string | `"Disk"` |
| clustermesh.apiserver.extraArgs | Additional clustermesh-apiserver arguments. | list | `[]` |
| clustermesh.apiserver.extraEnv | Additional clustermesh-apiserver environment variables. | list | `[]` |
| clustermesh.apiserver.extraVolumeMounts | Additional clustermesh-apiserver volumeMounts. | list | `[]` |
| clustermesh.apiserver.extraVolumes | Additional clustermesh-apiserver volumes. | list | `[]` |
| clustermesh.apiserver.healthPort | TCP port for the clustermesh-apiserver health API. | int | `9880` |
| clustermesh.apiserver.image | Clustermesh API server image. | object | `{"digest":"","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/clustermesh-apiserver-ci","tag":"latest","useDigest":false}` |
| clustermesh.apiserver.kvstoremesh.enabled | Enable KVStoreMesh. KVStoreMesh caches the information retrieved from the remote clusters in the local etcd instance (deprecated - KVStoreMesh will always be enabled once the option is removed). | bool | `true` |
| clustermesh.apiserver.kvstoremesh.extraArgs | Additional KVStoreMesh arguments. | list | `[]` |
| clustermesh.apiserver.kvstoremesh.extraEnv | Additional KVStoreMesh environment variables. | list | `[]` |
| clustermesh.apiserver.kvstoremesh.extraVolumeMounts | Additional KVStoreMesh volumeMounts. | list | `[]` |
| clustermesh.apiserver.kvstoremesh.healthPort | TCP port for the KVStoreMesh health API. | int | `9881` |
| clustermesh.apiserver.kvstoremesh.kvstoreMode | Specify the KVStore mode when running KVStoreMesh Supported values: - "internal": remote cluster identities are cached in etcd that runs as a sidecar within ``clustermesh-apiserver`` pod. - "external": ``clustermesh-apiserver`` will sync remote cluster information to the etcd used as kvstore. This can't be enabled with crd identity allocation mode. | string | `"internal"` |
| clustermesh.apiserver.kvstoremesh.lifecycle | lifecycle setting for the KVStoreMesh container | object | `{}` |
| clustermesh.apiserver.kvstoremesh.readinessProbe | Configuration for the KVStoreMesh readiness probe. | object | `{}` |
| clustermesh.apiserver.kvstoremesh.resources | Resource requests and limits for the KVStoreMesh container | object | `{}` |
| clustermesh.apiserver.kvstoremesh.securityContext | KVStoreMesh Security context | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}` |
| clustermesh.apiserver.lifecycle | lifecycle setting for the apiserver container | object | `{}` |
| clustermesh.apiserver.metrics.enabled | Enables exporting apiserver metrics in OpenMetrics format. | bool | `true` |
| clustermesh.apiserver.metrics.etcd.enabled | Enables exporting etcd metrics in OpenMetrics format. | bool | `true` |
| clustermesh.apiserver.metrics.etcd.mode | Set level of detail for etcd metrics; specify 'extensive' to include server side gRPC histogram metrics. | string | `"basic"` |
| clustermesh.apiserver.metrics.etcd.port | Configure the port the etcd metric server listens on. | int | `9963` |
| clustermesh.apiserver.metrics.kvstoremesh.enabled | Enables exporting KVStoreMesh metrics in OpenMetrics format. | bool | `true` |
| clustermesh.apiserver.metrics.kvstoremesh.port | Configure the port the KVStoreMesh metric server listens on. | int | `9964` |
| clustermesh.apiserver.metrics.port | Configure the port the apiserver metric server listens on. | int | `9962` |
| clustermesh.apiserver.metrics.serviceMonitor.annotations | Annotations to add to ServiceMonitor clustermesh-apiserver | object | `{}` |
| clustermesh.apiserver.metrics.serviceMonitor.enabled | Enable service monitor. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml) | bool | `false` |
| clustermesh.apiserver.metrics.serviceMonitor.etcd.interval | Interval for scrape metrics (etcd metrics) | string | `"10s"` |
| clustermesh.apiserver.metrics.serviceMonitor.etcd.metricRelabelings | Metrics relabeling configs for the ServiceMonitor clustermesh-apiserver (etcd metrics) | string | `nil` |
| clustermesh.apiserver.metrics.serviceMonitor.etcd.relabelings | Relabeling configs for the ServiceMonitor clustermesh-apiserver (etcd metrics) | string | `nil` |
| clustermesh.apiserver.metrics.serviceMonitor.etcd.scrapeTimeout | Timeout after which scrape is considered to be failed. | string | `nil` |
| clustermesh.apiserver.metrics.serviceMonitor.interval | Interval for scrape metrics (apiserver metrics) | string | `"10s"` |
| clustermesh.apiserver.metrics.serviceMonitor.kvstoremesh.interval | Interval for scrape metrics (KVStoreMesh metrics) | string | `"10s"` |
| clustermesh.apiserver.metrics.serviceMonitor.kvstoremesh.metricRelabelings | Metrics relabeling configs for the ServiceMonitor clustermesh-apiserver (KVStoreMesh metrics) | string | `nil` |
| clustermesh.apiserver.metrics.serviceMonitor.kvstoremesh.relabelings | Relabeling configs for the ServiceMonitor clustermesh-apiserver (KVStoreMesh metrics) | string | `nil` |
| clustermesh.apiserver.metrics.serviceMonitor.kvstoremesh.scrapeTimeout | Timeout after which scrape is considered to be failed. | string | `nil` |
| clustermesh.apiserver.metrics.serviceMonitor.labels | Labels to add to ServiceMonitor clustermesh-apiserver | object | `{}` |
| clustermesh.apiserver.metrics.serviceMonitor.metricRelabelings | Metrics relabeling configs for the ServiceMonitor clustermesh-apiserver (apiserver metrics) | string | `nil` |
| clustermesh.apiserver.metrics.serviceMonitor.relabelings | Relabeling configs for the ServiceMonitor clustermesh-apiserver (apiserver metrics) | string | `nil` |
| clustermesh.apiserver.metrics.serviceMonitor.scrapeTimeout | Timeout after which scrape is considered to be failed. | string | `nil` |
| clustermesh.apiserver.nodeSelector | Node labels for pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector | object | `{"kubernetes.io/os":"linux"}` |
| clustermesh.apiserver.podAnnotations | Annotations to be added to clustermesh-apiserver pods | object | `{}` |
| clustermesh.apiserver.podDisruptionBudget.enabled | enable PodDisruptionBudget ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/ | bool | `false` |
| clustermesh.apiserver.podDisruptionBudget.maxUnavailable | Maximum number/percentage of pods that may be made unavailable | int | `1` |
| clustermesh.apiserver.podDisruptionBudget.minAvailable | Minimum number/percentage of pods that should remain scheduled. When it's set, maxUnavailable must be disabled by `maxUnavailable: null` | string | `nil` |
| clustermesh.apiserver.podDisruptionBudget.unhealthyPodEvictionPolicy | How are unhealthy, but running, pods counted for eviction | string | `nil` |
| clustermesh.apiserver.podLabels | Labels to be added to clustermesh-apiserver pods | object | `{}` |
| clustermesh.apiserver.podSecurityContext | Security context to be added to clustermesh-apiserver pods | object | `{"fsGroup":65532,"runAsGroup":65532,"runAsNonRoot":true,"runAsUser":65532}` |
| clustermesh.apiserver.priorityClassName | The priority class to use for clustermesh-apiserver | string | `""` |
| clustermesh.apiserver.readinessProbe | Configuration for the clustermesh-apiserver readiness probe. | object | `{}` |
| clustermesh.apiserver.replicas | Number of replicas run for the clustermesh-apiserver deployment. | int | `1` |
| clustermesh.apiserver.resources | Resource requests and limits for the clustermesh-apiserver | object | `{}` |
| clustermesh.apiserver.securityContext | Security context to be added to clustermesh-apiserver containers | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}` |
| clustermesh.apiserver.service.annotations | Annotations for the clustermesh-apiserver service. Example annotations to configure an internal load balancer on different cloud providers: * AKS: service.beta.kubernetes.io/azure-load-balancer-internal: "true" * EKS: service.beta.kubernetes.io/aws-load-balancer-scheme: "internal" * GKE: networking.gke.io/load-balancer-type: "Internal" | object | `{}` |
| clustermesh.apiserver.service.enableSessionAffinity | Defines when to enable session affinity. Each replica in a clustermesh-apiserver deployment runs its own discrete etcd cluster. Remote clients connect to one of the replicas through a shared Kubernetes Service. A client reconnecting to a different backend will require a full resync to ensure data integrity. Session affinity can reduce the likelihood of this happening, but may not be supported by all cloud providers. Possible values:  - "HAOnly" (default) Only enable session affinity for deployments with more than 1 replica.  - "Always" Always enable session affinity.  - "Never" Never enable session affinity. Useful in environments where            session affinity is not supported, but may lead to slightly            degraded performance due to more frequent reconnections. | string | `"HAOnly"` |
| clustermesh.apiserver.service.externalTrafficPolicy | The externalTrafficPolicy of service used for apiserver access. | string | `"Cluster"` |
| clustermesh.apiserver.service.externallyCreated | Set externallyCreated to true to create the clustermesh-apiserver service outside this helm chart. For example after external load balancer controllers are created. | bool | `false` |
| clustermesh.apiserver.service.internalTrafficPolicy | The internalTrafficPolicy of service used for apiserver access. | string | `"Cluster"` |
| clustermesh.apiserver.service.labels | Labels for the clustermesh-apiserver service. | object | `{}` |
| clustermesh.apiserver.service.loadBalancerClass | Configure a loadBalancerClass. Allows to configure the loadBalancerClass on the clustermesh-apiserver LB service in case the Service type is set to LoadBalancer (requires Kubernetes 1.24+). | string | `nil` |
| clustermesh.apiserver.service.loadBalancerIP | Configure a specific loadBalancerIP. Allows to configure a specific loadBalancerIP on the clustermesh-apiserver LB service in case the Service type is set to LoadBalancer. | string | `nil` |
| clustermesh.apiserver.service.loadBalancerSourceRanges | Configure loadBalancerSourceRanges. Allows to configure the source IP ranges allowed to access the clustermesh-apiserver LB service in case the Service type is set to LoadBalancer. | list | `[]` |
| clustermesh.apiserver.service.nodePort | Optional port to use as the node port for apiserver access. | int | `32379` |
| clustermesh.apiserver.service.type | The type of service used for apiserver access. | string | `"NodePort"` |
| clustermesh.apiserver.terminationGracePeriodSeconds | terminationGracePeriodSeconds for the clustermesh-apiserver deployment | int | `30` |
| clustermesh.apiserver.tls.admin | base64 encoded PEM values for the clustermesh-apiserver admin certificate and private key. Used if 'auto' is not enabled. | object | `{"cert":"","key":""}` |
| clustermesh.apiserver.tls.admin.cert | Deprecated, as secrets will always need to be created externally if `auto` is disabled. | string | `""` |
| clustermesh.apiserver.tls.admin.key | Deprecated, as secrets will always need to be created externally if `auto` is disabled. | string | `""` |
| clustermesh.apiserver.tls.authMode | Configure the clustermesh authentication mode. Supported values: - legacy:     All clusters access remote clustermesh instances with the same               username (i.e., remote). The "remote" certificate must be               generated with CN=remote if provided manually. - migration:  Intermediate mode required to upgrade from legacy to cluster               (and vice versa) with no disruption. Specifically, it enables               the creation of the per-cluster usernames, while still using               the common one for authentication. The "remote" certificate must               be generated with CN=remote if provided manually (same as legacy). - cluster:    Each cluster accesses remote etcd instances with a username               depending on the local cluster name (i.e., remote-<cluster-name>).               The "remote" certificate must be generated with CN=remote-<cluster-name>               if provided manually. Cluster mode is meaningful only when the same               CA is shared across all clusters part of the mesh. | string | `"migration"` |
| clustermesh.apiserver.tls.auto | Configure automatic TLS certificates generation. A Kubernetes CronJob is used the generate any certificates not provided by the user at installation time. | object | `{"certManagerIssuerRef":{},"certValidityDuration":1095,"enabled":true,"method":"helm"}` |
| clustermesh.apiserver.tls.auto.certManagerIssuerRef | certmanager issuer used when clustermesh.apiserver.tls.auto.method=certmanager. | object | `{}` |
| clustermesh.apiserver.tls.auto.certValidityDuration | Generated certificates validity duration in days. | int | `1095` |
| clustermesh.apiserver.tls.auto.enabled | When set to true, automatically generate a CA and certificates to enable mTLS between clustermesh-apiserver and external workload instances.  When set to false you need to pre-create the following secrets: - clustermesh-apiserver-server-cert - clustermesh-apiserver-admin-cert - clustermesh-apiserver-remote-cert - clustermesh-apiserver-local-cert The above secret should at least contains the keys `tls.crt` and `tls.key` and optionally `ca.crt` if a CA bundle is not configured. | bool | `true` |
| clustermesh.apiserver.tls.enableSecrets | Allow users to provide their own certificates Users may need to provide their certificates using a mechanism that requires they provide their own secrets. This setting does not apply to any of the auto-generated mechanisms below, it only restricts the creation of secrets via the `tls-provided` templates. This option is deprecated as secrets are expected to be created externally when 'auto' is not enabled. | deprecated | `true` |
| clustermesh.apiserver.tls.remote | base64 encoded PEM values for the clustermesh-apiserver remote cluster certificate and private key. Used if 'auto' is not enabled. | object | `{"cert":"","key":""}` |
| clustermesh.apiserver.tls.remote.cert | Deprecated, as secrets will always need to be created externally if `auto` is disabled. | string | `""` |
| clustermesh.apiserver.tls.remote.key | Deprecated, as secrets will always need to be created externally if `auto` is disabled. | string | `""` |
| clustermesh.apiserver.tls.server | base64 encoded PEM values for the clustermesh-apiserver server certificate and private key. Used if 'auto' is not enabled. | object | `{"cert":"","extraDnsNames":[],"extraIpAddresses":[],"key":""}` |
| clustermesh.apiserver.tls.server.cert | Deprecated, as secrets will always need to be created externally if `auto` is disabled. | string | `""` |
| clustermesh.apiserver.tls.server.extraDnsNames | Extra DNS names added to certificate when it's auto generated | list | `[]` |
| clustermesh.apiserver.tls.server.extraIpAddresses | Extra IP addresses added to certificate when it's auto generated | list | `[]` |
| clustermesh.apiserver.tls.server.key | Deprecated, as secrets will always need to be created externally if `auto` is disabled. | string | `""` |
| clustermesh.apiserver.tolerations | Node tolerations for pod assignment on nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/ | list | `[]` |
| clustermesh.apiserver.topologySpreadConstraints | Pod topology spread constraints for clustermesh-apiserver | list | `[]` |
| clustermesh.apiserver.updateStrategy | clustermesh-apiserver update strategy | object | `{"rollingUpdate":{"maxSurge":1,"maxUnavailable":0},"type":"RollingUpdate"}` |
| clustermesh.cacheTTL | The time to live for the cache of a remote cluster after connectivity is lost. If the connection is not re-established within this duration, the cached data is revoked to prevent stale state. If not specified or set to 0s, the cache is never revoked (default). | string | `"0s"` |
| clustermesh.config | Clustermesh explicit configuration. | object | `{"clusters":[],"domain":"mesh.cilium.io","enabled":false}` |
| clustermesh.config.clusters | Clusters to be peered in the mesh. @schema type: [object, array] @schema | list | `[]` |
| clustermesh.config.domain | Default dns domain for the Clustermesh API servers This is used in the case cluster addresses are not provided and IPs are used. | string | `"mesh.cilium.io"` |
| clustermesh.config.enabled | Enable the Clustermesh explicit configuration. If set to false, you need to provide the following resources yourself: - (Secret) cilium-clustermesh (used by cilium-agent/cilium-operator to connect to   the local etcd instance if KVStoreMesh is enabled or the remote clusters   if KVStoreMesh is disabled) - (Secret) cilium-kvstoremesh (used by KVStoreMesh to connect to the remote clusters) - (ConfigMap) clustermesh-remote-users (used to create one etcd user per remote cluster   if clustermesh-apiserver is used and `clustermesh.apiserver.tls.authMode` is not   set to `legacy`) | bool | `false` |
| clustermesh.defaultGlobalNamespace | Default behavior of namespaces in Clustermesh.  A "global" namespace means its resources (CiliumEndpoints, CiliumIdentities, and Services) are exported and shared across all connected clusters in the mesh. This enables: - Cross-cluster pod-to-pod connectivity - Cross-cluster network policy enforcement (policies can match labels on pods in remote clusters) - Global services and Multi-Cluster Services (MCS-API)  A "local" namespace means its resources stay within the cluster and are NOT exported to other clusters. Cross-cluster communication and network policies will not work for pods in local namespaces.  If set to true, all namespaces are considered global by default unless explicitly annotated with clustermesh.cilium.io/global=false. If set to false, all namespaces are considered local by default unless explicitly annotated with clustermesh.cilium.io/global=true.  Note: For cross-cluster communication to work, BOTH the source and destination namespaces must be global. Additionally, for a service to be a Global Service, it must both reside in a global namespace AND be annotated with service.cilium.io/global=true. This setting improves scalability by limiting the amount of state synchronized across clusters.  Defaults to true (preserves existing behavior where all namespaces are global). | bool | `true` |
| clustermesh.enableEndpointSliceSynchronization | Enable the synchronization of Kubernetes EndpointSlices corresponding to the remote endpoints of appropriately-annotated global services through ClusterMesh | bool | `false` |
| clustermesh.maxConnectedClusters | The maximum number of clusters to support in a ClusterMesh. This value cannot be changed on running clusters, and all clusters in a ClusterMesh must be configured with the same value. Values > 255 will decrease the maximum allocatable cluster-local identities. Supported values are 255 and 511. | int | `255` |
| clustermesh.mcsapi.corednsAutoConfigure.affinity | Affinity for coredns-mcsapi-autoconfig | object | `{}` |
| clustermesh.mcsapi.corednsAutoConfigure.annotations | Annotations to be added to the coredns-mcsapi-autoconfig Job | object | `{}` |
| clustermesh.mcsapi.corednsAutoConfigure.coredns.clusterDomain | The cluster domain for the cluster CoreDNS service | string | `"cluster.local"` |
| clustermesh.mcsapi.corednsAutoConfigure.coredns.clustersetDomain | The clusterset domain for the cluster CoreDNS service | string | `"clusterset.local"` |
| clustermesh.mcsapi.corednsAutoConfigure.coredns.configMapName | The ConfigMap name for the cluster CoreDNS service | string | `"coredns"` |
| clustermesh.mcsapi.corednsAutoConfigure.coredns.deploymentName | The Deployment for the cluster CoreDNS service | string | `"coredns"` |
| clustermesh.mcsapi.corednsAutoConfigure.coredns.namespace | The namespace for the cluster CoreDNS service | string | `"kube-system"` |
| clustermesh.mcsapi.corednsAutoConfigure.coredns.serviceAccountName | The Service Account name for the cluster CoreDNS service | string | `"coredns"` |
| clustermesh.mcsapi.corednsAutoConfigure.enabled | Enable auto-configuration of CoreDNS for Multi-Cluster Services API.    CoreDNS MUST be at least in version v1.12.2 to run this. | bool | `false` |
| clustermesh.mcsapi.corednsAutoConfigure.extraArgs | Additional arguments to `clustermesh-apiserver coredns-mcsapi-auto-configure`. | list | `[]` |
| clustermesh.mcsapi.corednsAutoConfigure.extraVolumeMounts | Additional coredns-mcsapi-autoconfig volumeMounts. | list | `[]` |
| clustermesh.mcsapi.corednsAutoConfigure.extraVolumes | Additional coredns-mcsapi-autoconfig volumes. | list | `[]` |
| clustermesh.mcsapi.corednsAutoConfigure.nodeSelector | Node selector for coredns-mcsapi-autoconfig ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector | object | `{}` |
| clustermesh.mcsapi.corednsAutoConfigure.podLabels | Labels to be added to coredns-mcsapi-autoconfig pods | object | `{}` |
| clustermesh.mcsapi.corednsAutoConfigure.priorityClassName | Priority class for coredns-mcsapi-autoconfig ref: https://kubernetes.io/docs/concepts/scheduling-eviction/pod-priority-preemption/#priorityclass | string | `""` |
| clustermesh.mcsapi.corednsAutoConfigure.resources | Resource limits for coredns-mcsapi-autoconfig ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers | object | `{}` |
| clustermesh.mcsapi.corednsAutoConfigure.tolerations | Node tolerations for pod assignment on nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/ | list | `[]` |
| clustermesh.mcsapi.corednsAutoConfigure.ttlSecondsAfterFinished | Seconds after which the completed job pod will be deleted | int | `1800` |
| clustermesh.mcsapi.enabled | Enable Multi-Cluster Services API support | bool | `false` |
| clustermesh.mcsapi.installCRDs | Enabled MCS-API CRDs auto-installation | bool | `true` |
| clustermesh.policyDefaultLocalCluster | Control whether policy rules assume by default the local cluster if not explicitly selected | bool | `true` |
| clustermesh.useAPIServer | Deploy clustermesh-apiserver for clustermesh. This option is typically used with ``clustermesh.config.enabled=true``. Refer to the ``clustermesh.config.enabled=true``documentation for more information. | bool | `false` |
| cni.binPath | Configure the path to the CNI binary directory on the host. | string | `"/opt/cni/bin"` |
| cni.chainingMode | Configure chaining on top of other CNI plugins. Possible values:  - none  - aws-cni  - flannel  - generic-veth  - portmap | string | `nil` |
| cni.chainingTarget | A CNI network name in to which the Cilium plugin should be added as a chained plugin. This will cause the agent to watch for a CNI network with this network name. When it is found, this will be used as the basis for Cilium's CNI configuration file. If this is set, it assumes a chaining mode of generic-veth. As a special case, a chaining mode of aws-cni implies a chainingTarget of aws-cni. | string | `nil` |
| cni.confFileMountPath | Configure the path to where to mount the ConfigMap inside the agent pod. | string | `"/tmp/cni-configuration"` |
| cni.confPath | Configure the path to the CNI configuration directory on the host. | string | `"/etc/cni/net.d"` |
| cni.configMap | When defined, configMap will mount the provided value as ConfigMap and interpret the 'cni.configMapKey' value as CNI configuration file and write it when the agent starts up. | string | `""` |
| cni.configMapKey | Configure the key in the CNI ConfigMap to read the contents of the CNI configuration from. For this to be effective, the 'cni.configMap' parameter must be specified too. Note that the 'cni.configMap' parameter is the name of the ConfigMap, while 'cni.configMapKey' is the name of the key in the ConfigMap data containing the actual configuration. | string | `"cni-config"` |
| cni.customConf | Skip writing of the CNI configuration. This can be used if writing of the CNI configuration is performed by external automation. | bool | `false` |
| cni.enableRouteMTUForCNIChaining | Enable route MTU for pod netns when CNI chaining is used | bool | `false` |
| cni.exclusive | Make Cilium take ownership over the `/etc/cni/net.d` directory on the node, renaming all non-Cilium CNI configurations to `*.cilium_bak`. This ensures no Pods can be scheduled using other CNI plugins during Cilium agent downtime. | bool | `true` |
| cni.hostConfDirMountPath | Configure the path to where the CNI configuration directory is mounted inside the agent pod. | string | `"/host/etc/cni/net.d"` |
| cni.install | Install the CNI configuration and binary files into the filesystem. | bool | `true` |
| cni.iptablesRemoveAWSRules | Enable the removal of iptables rules created by the AWS CNI VPC plugin. | bool | `true` |
| cni.logFile | Configure the log file for CNI logging with retention policy of 7 days. Disable CNI file logging by setting this field to empty explicitly. | string | `"/var/run/cilium/cilium-cni.log"` |
| cni.resources | Specifies the resources for the cni initContainer | object | `{"limits":{"cpu":1,"memory":"1Gi"},"requests":{"cpu":"100m","memory":"10Mi"}}` |
| cni.uninstall | Remove the CNI configuration and binary files on agent shutdown. Enable this if you're removing Cilium from the cluster. Disable this to prevent the CNI configuration file from being removed during agent upgrade, which can cause nodes to go unmanageable. | bool | `false` |
| commonLabels | commonLabels allows users to add common labels for all Cilium resources. | object | `{}` |
| configDriftDetection | Configuration for the ConfigMap drift detection feature. When enabled, the agent continuously watches the cilium-config ConfigMap and exposes a cilium_drift_checker_config_delta Prometheus metric reporting the number of keys that differ between the ConfigMap and the agent's active settings. A non-zero value indicates that the agent has not yet applied all current ConfigMap changes and needs to be restarted. | object | `{"driftChecker":true,"enabled":true,"ignoredKeys":[]}` |
| configDriftDetection.driftChecker | Enable the drift checker which compares the DynamicConfig table against the agent's active settings and publishes the cilium_drift_checker_config_delta metric. | bool | `true` |
| configDriftDetection.enabled | Enable watching of the cilium-config ConfigMap and reflecting its contents into the agent's internal DynamicConfig table. | bool | `true` |
| configDriftDetection.ignoredKeys | List of config-map keys to ignore when computing the drift delta. | list | `[]` |
| connectivityProbeFrequencyRatio | Ratio of the connectivity probe frequency vs resource usage, a float in [0, 1]. 0 will give more frequent probing, 1 will give less frequent probing. Probing frequency is dynamically adjusted based on the cluster size. | float64 | `0.5` |
| conntrackGCInterval | Configure how frequently garbage collection should occur for the datapath connection tracking table. | string | `"0s"` |
| conntrackGCMaxInterval | Configure the maximum frequency for the garbage collection of the connection tracking table. Only affects the automatic computation for the frequency and has no effect when 'conntrackGCInterval' is set. This can be set to more frequently clean up unused identities created from ToFQDN policies. | string | `""` |
| crdWaitTimeout | Configure timeout in which Cilium will exit if CRDs are not available | string | `"5m"` |
| daemon.allowedConfigOverrides | allowedConfigOverrides is a list of config-map keys that can be overridden. That is to say, if this value is set, config sources (excepting the first one) can only override keys in this list.  This takes precedence over blockedConfigOverrides.  By default, all keys may be overridden. To disable overrides, set this to "none" or change the configSources variable. | string | `nil` |
| daemon.blockedConfigOverrides | blockedConfigOverrides is a list of config-map keys that may not be overridden. In other words, if any of these keys appear in a configuration source excepting the first one, they will be ignored  This is ignored if allowedConfigOverrides is set.  By default, all keys may be overridden. | string | `nil` |
| daemon.configSources | Configure a custom list of possible configuration override sources The default is "config-map:cilium-config,cilium-node-config". For supported values, see the help text for the build-config subcommand. Note that this value should be a comma-separated string. | string | `nil` |
| daemon.enableSourceIPVerification | enableSourceIPVerification is a boolean flag to enable or disable the Source IP verification of endpoints. This flag is useful when Cilium is chained with other CNIs.  By default, this functionality is enabled | bool | `true` |
| daemon.runPath | Configure where Cilium runtime state should be stored. | string | `"/var/run/cilium"` |
| dashboards | Grafana dashboards for cilium-agent grafana can import dashboards based on the label and value ref: https://github.com/grafana/helm-charts/tree/main/charts/grafana#sidecar-for-dashboards | object | `{"annotations":{},"enabled":false,"label":"grafana_dashboard","labelValue":"1","namespace":null}` |
| debug.enabled | Enable debug logging | bool | `false` |
| debug.metricsSamplingInterval | Set the agent-internal metrics sampling frequency. This sets the frequency of the internal sampling of the agent metrics. These are available via the "cilium-dbg shell -- metrics -s" command and are part of the metrics HTML page included in the sysdump. @schema type: [null, string] @schema | string | `"5m"` |
| debug.verbose | Configure verbosity levels for debug logging This option is used to enable debug messages for operations related to such sub-system such as (e.g. kvstore, envoy, datapath, policy, or tagged), and flow is for enabling debug messages emitted per request, message and connection. Multiple values can be set via a space-separated string (e.g. "datapath envoy").  Applicable values: - flow - kvstore - envoy - datapath - policy - tagged | string | `nil` |
| defaultLBServiceIPAM | defaultLBServiceIPAM indicates the default LoadBalancer Service IPAM when no LoadBalancer class is set. Applicable values: lbipam, nodeipam, none | string | `"lbipam"` |
| directRoutingSkipUnreachable | Enable skipping of PodCIDR routes between worker nodes if the worker nodes are in a different L2 network segment. | bool | `false` |
| disableEndpointCRD | Disable the usage of CiliumEndpoint CRD. | bool | `false` |
| dnsPolicy | DNS policy for Cilium agent pods. Ref: https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pod-s-dns-policy | string | `""` |
| dnsProxy.dnsRejectResponseCode | DNS response code for rejecting DNS requests, available options are '[nameError refused]'. | string | `"refused"` |
| dnsProxy.enableDnsCompression | Allow the DNS proxy to compress responses to endpoints that are larger than 512 Bytes or the EDNS0 option, if present. | bool | `true` |
| dnsProxy.endpointMaxIpPerHostname | Maximum number of IPs to maintain per FQDN name for each endpoint. | int | `1000` |
| dnsProxy.idleConnectionGracePeriod | Time during which idle but previously active connections with expired DNS lookups are still considered alive. | string | `"0s"` |
| dnsProxy.maxDeferredConnectionDeletes | Maximum number of IPs to retain for expired DNS lookups with still-active connections. | int | `10000` |
| dnsProxy.minTtl | The minimum time, in seconds, to use DNS data for toFQDNs policies. If the upstream DNS server returns a DNS record with a shorter TTL, Cilium overwrites the TTL with this value. Setting this value to zero means that Cilium will honor the TTLs returned by the upstream DNS server. | int | `0` |
| dnsProxy.preAllocateIdentities | Pre-allocate ToFQDN identities. This reduces DNS proxy tail latency, at the potential cost of some unnecessary policymap entries. Disable this if you have a large (200+) number of unique ToFQDN selectors. | bool | `true` |
| dnsProxy.preCache | DNS cache data at this path is preloaded on agent startup. | string | `""` |
| dnsProxy.proxyPort | Global port on which the in-agent DNS proxy should listen. Default 0 is a OS-assigned port. | int | `0` |
| dnsProxy.proxyResponseMaxDelay | The maximum time the DNS proxy holds an allowed DNS response before sending it along. Responses are sent as soon as the datapath is updated with the new IP information. | string | `"100ms"` |
| dnsProxy.socketLingerTimeout | Timeout (in seconds) when closing the connection between the DNS proxy and the upstream server. If set to 0, the connection is closed immediately (with TCP RST). If set to -1, the connection is closed asynchronously in the background. | int | `10` |
| egressGateway.enabled | Enables egress gateway to redirect and SNAT the traffic that leaves the cluster. | bool | `false` |
| egressGateway.reconciliationTriggerInterval | Time between triggers of egress gateway state reconciliations | string | `"1s"` |
| enableCriticalPriorityClass | Explicitly enable or disable priority class. .Capabilities.KubeVersion is unsettable in `helm template` calls, it depends on k8s libraries version that Helm was compiled against. This option allows to explicitly disable setting the priority class, which is useful for rendering charts for gke clusters in advance. | bool | `true` |
| enableIPv4BIGTCP | Enables IPv4 BIG TCP support which increases maximum IPv4 GSO/GRO limits for nodes and pods | bool | `false` |
| enableIPv4Masquerade | Enables masquerading of IPv4 traffic leaving the node from endpoints. | bool | `true` unless ipam eni mode is active |
| enableIPv6BIGTCP | Enables IPv6 BIG TCP support which increases maximum IPv6 GSO/GRO limits for nodes and pods | bool | `false` |
| enableIPv6Masquerade | Enables masquerading of IPv6 traffic leaving the node from endpoints. | bool | `true` |
| enableInternalTrafficPolicy | Enable Internal Traffic Policy | bool | `true` |
| enableLBIPAM | Enable LoadBalancer IP Address Management | bool | `true` |
| enableMasqueradeRouteSource | Enables masquerading to the source of the route for traffic leaving the node from endpoints. | bool | `false` |
| enableNoServiceEndpointsRoutable | Enable routing to a service that has zero endpoints | bool | `true` |
| enableNonDefaultDenyPolicies | Enable Non-Default-Deny policies | bool | `true` |
| enableXTSocketFallback | Enables the fallback compatibility solution for when the xt_socket kernel module is missing and it is needed for the datapath L7 redirection to work properly. See documentation for details on when this can be disabled: https://docs.cilium.io/en/stable/operations/system_requirements/#linux-kernel. | bool | `true` |
| encryption.enabled | Enable transparent network encryption. | bool | `false` |
| encryption.ipsec.encryptedOverlay | Enable IPsec encrypted overlay | bool | `false` |
| encryption.ipsec.interface | The interface to use for encrypted traffic. | string | `""` |
| encryption.ipsec.keyFile | Name of the key file inside the Kubernetes secret configured via secretName. | string | `"keys"` |
| encryption.ipsec.keyRotationDuration | Maximum duration of the IPsec key rotation. The previous key will be removed after that delay. | string | `"5m"` |
| encryption.ipsec.keyWatcher | Enable the key watcher. If disabled, a restart of the agent will be necessary on key rotations. | bool | `true` |
| encryption.ipsec.mountPath | Path to mount the secret inside the Cilium pod. | string | `"/etc/ipsec"` |
| encryption.ipsec.secretName | Name of the Kubernetes secret containing the encryption keys. | string | `"cilium-ipsec-keys"` |
| encryption.nodeEncryption | Enable encryption for pure node to node traffic. This option is only effective when encryption.type is set to "wireguard". | bool | `false` |
| encryption.strictMode | Configure the Encryption Pod2Pod strict mode. | object | `{"allowRemoteNodeIdentities":false,"cidr":"","egress":{"allowRemoteNodeIdentities":false,"cidr":"","enabled":false},"enabled":false,"ingress":{"enabled":false}}` |
| encryption.strictMode.allowRemoteNodeIdentities | Allow dynamic lookup of remote node identities. (deprecated: please use encryption.strictMode.egress.allowRemoteNodeIdentities) This is required when tunneling is used or direct routing is used and the node CIDR and pod CIDR overlap. | bool | `false` |
| encryption.strictMode.cidr | CIDR for the Encryption Pod2Pod strict mode. (deprecated: please use encryption.strictMode.egress.cidr) | string | `""` |
| encryption.strictMode.egress.allowRemoteNodeIdentities | Allow dynamic lookup of remote node identities. This is required when tunneling is used or direct routing is used and the node CIDR and pod CIDR overlap. | bool | `false` |
| encryption.strictMode.egress.cidr | CIDR for the Encryption Pod2Pod strict egress mode. | string | `""` |
| encryption.strictMode.egress.enabled | Enable strict egress encryption. | bool | `false` |
| encryption.strictMode.enabled | Enable Encryption Pod2Pod strict mode. (deprecated: please use encryption.strictMode.egress.enabled) | bool | `false` |
| encryption.strictMode.ingress.enabled | Enable strict ingress encryption. When enabled, all unencrypted overlay ingress traffic will be dropped. This option is only applicable when WireGuard and tunneling are enabled. | bool | `false` |
| encryption.type | Encryption method. Can be one of ipsec, wireguard or ztunnel. | string | `"ipsec"` |
| encryption.wireguard.persistentKeepalive | Controls WireGuard PersistentKeepalive option. Set 0s to disable. | string | `"0s"` |
| encryption.ztunnel | ztunnel encryption configuration. ztunnel is Istio's purpose-built, per-node proxy for handling L4 traffic in ambient mesh mode. These settings only apply when encryption.type is set to "ztunnel". | object | `{"affinity":{},"annotations":{},"caAddress":"https://localhost:15012","extraEnv":[],"extraVolumeMounts":[],"extraVolumes":[],"healthPort":15021,"image":{"digest":null,"override":null,"pullPolicy":"IfNotPresent","repository":"docker.io/istio/ztunnel","tag":"1.28.0-distroless","useDigest":false},"nodeSelector":{"kubernetes.io/os":"linux"},"podAnnotations":{},"podLabels":{},"priorityClassName":null,"readinessProbe":{"failureThreshold":3,"initialDelaySeconds":0,"periodSeconds":10},"resources":{"requests":{"cpu":"200m","memory":"512Mi"}},"secrets":{"bootstrapRootCert":null},"terminationGracePeriodSeconds":30,"tolerations":[{"effect":"NoSchedule","operator":"Exists"},{"key":"CriticalAddonsOnly","operator":"Exists"},{"effect":"NoExecute","operator":"Exists"}],"updateStrategy":{"rollingUpdate":{"maxSurge":1,"maxUnavailable":0},"type":"RollingUpdate"}}` |
| encryption.ztunnel.affinity | Affinity for ztunnel pods. | object | `{}` |
| encryption.ztunnel.annotations | Annotations to be added to all ztunnel resources. | object | `{}` |
| encryption.ztunnel.caAddress | CA server address for certificate requests. | string | `"https://localhost:15012"` |
| encryption.ztunnel.extraEnv | Additional ztunnel container environment variables. | list | `[]` |
| encryption.ztunnel.extraVolumeMounts | Additional ztunnel volumeMounts. | list | `[]` |
| encryption.ztunnel.extraVolumes | Additional ztunnel volumes. | list | `[]` |
| encryption.ztunnel.healthPort | TCP port for the health API. | int | `15021` |
| encryption.ztunnel.image | ztunnel container image. | object | `{"digest":null,"override":null,"pullPolicy":"IfNotPresent","repository":"docker.io/istio/ztunnel","tag":"1.28.0-distroless","useDigest":false}` |
| encryption.ztunnel.nodeSelector | Node selector for ztunnel pods. | object | `{"kubernetes.io/os":"linux"}` |
| encryption.ztunnel.podAnnotations | Annotations to be added to ztunnel pods. | object | `{}` |
| encryption.ztunnel.podLabels | Labels to be added to ztunnel pods. | object | `{}` |
| encryption.ztunnel.priorityClassName | The priority class to use for ztunnel pods. | string | `nil` |
| encryption.ztunnel.readinessProbe | Readiness probe configuration. | object | `{"failureThreshold":3,"initialDelaySeconds":0,"periodSeconds":10}` |
| encryption.ztunnel.resources | ztunnel resource limits & requests. | object | `{"requests":{"cpu":"200m","memory":"512Mi"}}` |
| encryption.ztunnel.secrets | ztunnel secrets configuration. | object | `{"bootstrapRootCert":null}` |
| encryption.ztunnel.secrets.bootstrapRootCert | Base64-encoded bootstrap root certificate content. If not provided, the secret must be created manually before deploying. @schema type: [null, string] @schema | string | `nil` |
| encryption.ztunnel.terminationGracePeriodSeconds | Configure termination grace period for ztunnel DaemonSet. | int | `30` |
| encryption.ztunnel.tolerations | Node tolerations for ztunnel scheduling. | list | `[{"effect":"NoSchedule","operator":"Exists"},{"key":"CriticalAddonsOnly","operator":"Exists"},{"effect":"NoExecute","operator":"Exists"}]` |
| encryption.ztunnel.updateStrategy | ztunnel update strategy. | object | `{"rollingUpdate":{"maxSurge":1,"maxUnavailable":0},"type":"RollingUpdate"}` |
| endpointHealthChecking.enabled | Enable connectivity health checking between virtual endpoints. | bool | `true` |
| endpointLockdownOnMapOverflow | Enable endpoint lockdown on policy map overflow. | bool | `false` |
| endpointRoutes.enabled | Enable use of per endpoint routes instead of routing via the cilium_host interface. | bool | `false` |
| eni.awsEnablePrefixDelegation | Enable ENI prefix delegation | bool | `false` |
| eni.awsReleaseExcessIPs | Release IPs not used from the ENI | bool | `false` |
| eni.ec2APIEndpoint | EC2 API endpoint to use | string | `""` |
| eni.enabled | Enable Elastic Network Interface (ENI) integration. | bool | `false` |
| eni.eniTags | Tags to apply to the newly created ENIs | object | `{}` |
| eni.gcInterval | Interval for garbage collection of unattached ENIs. Set to "0s" to disable. | string | `"5m"` |
| eni.gcTags | Additional tags attached to ENIs created by Cilium. Dangling ENIs with this tag will be garbage collected | object | `{"io.cilium/cilium-managed":"true,"io.cilium/cluster-name":"<auto-detected>"}` |
| eni.iamRole | If using IAM role for Service Accounts will not try to inject identity values from cilium-aws kubernetes secret. Adds annotation to service account if managed by Helm. See https://github.com/aws/amazon-eks-pod-identity-webhook | string | `""` |
| eni.instanceTagsFilter | Filter via AWS EC2 Instance tags (k=v) which will dictate which AWS EC2 Instances are going to be used to create new ENIs | list | `[]` |
| eni.nodeSpec | NodeSpec configuration for the ENI | object | `{"deleteOnTermination":null,"disablePrefixDelegation":false,"excludeInterfaceTags":[],"firstInterfaceIndex":null,"securityGroupTags":[],"securityGroups":[],"subnetIDs":[],"subnetTags":[],"usePrimaryAddress":false}` |
| eni.nodeSpec.deleteOnTermination | Delete ENI on termination @schema type: [null, boolean] @schema | string | `nil` |
| eni.nodeSpec.disablePrefixDelegation | Disable prefix delegation for IP allocation | bool | `false` |
| eni.nodeSpec.excludeInterfaceTags | Exclude interface tags to use for IP allocation | list | `[]` |
| eni.nodeSpec.firstInterfaceIndex | First interface index to use for IP allocation @schema type: [null, integer] @schema | string | `nil` |
| eni.nodeSpec.securityGroupTags | Security group tags to use for IP allocation | list | `[]` |
| eni.nodeSpec.securityGroups | Security groups to use for IP allocation | list | `[]` |
| eni.nodeSpec.subnetIDs | Subnet IDs to use for IP allocation | list | `[]` |
| eni.nodeSpec.subnetTags | Subnet tags to use for IP allocation | list | `[]` |
| eni.nodeSpec.usePrimaryAddress | Use primary address for IP allocation | bool | `false` |
| eni.subnetIDsFilter | Filter via subnet IDs which will dictate which subnets are going to be used to create new ENIs Important note: This requires that each instance has an ENI with a matching subnet attached when Cilium is deployed. If you only want to control subnets for ENIs attached by Cilium, use the CNI configuration file settings (cni.customConf) instead. | list | `[]` |
| eni.subnetTagsFilter | Filter via tags (k=v) which will dictate which subnets are going to be used to create new ENIs Important note: This requires that each instance has an ENI with a matching subnet attached when Cilium is deployed. If you only want to control subnets for ENIs attached by Cilium, use the CNI configuration file settings (cni.customConf) instead. | list | `[]` |
| envoy.affinity | Affinity for cilium-envoy. | object | `{"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"cilium.io/no-schedule","operator":"NotIn","values":["true"]}]}]}},"podAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"k8s-app":"cilium"}},"topologyKey":"kubernetes.io/hostname"}]},"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"k8s-app":"cilium-envoy"}},"topologyKey":"kubernetes.io/hostname"}]}}` |
| envoy.annotations | Annotations to be added to all top-level cilium-envoy objects (resources under templates/cilium-envoy) | object | `{}` |
| envoy.baseID |  Set Envoy'--base-id' to use when allocating shared memory regions. Only needs to be changed if multiple Envoy instances will run on the same node and may have conflicts. Supported values: 0 - 4294967295. Defaults to '0' | int | `0` |
| envoy.bootstrapConfigMap | ADVANCED OPTION: Bring your own custom Envoy bootstrap ConfigMap. Provide the name of a ConfigMap with a `bootstrap-config.json` key. When specified, Envoy will use this ConfigMap instead of the default provided by the chart. WARNING: Use of this setting has the potential to prevent cilium-envoy from starting up, and can cause unexpected behavior (e.g. due to syntax error or semantically incorrect configuration). Before submitting an issue, please ensure you have disabled this feature, as support cannot be provided for custom Envoy bootstrap configs. @schema type: [null, string] @schema | string | `nil` |
| envoy.clusterMaxConnections | Maximum number of connections on Envoy clusters | int | `1024` |
| envoy.clusterMaxRequests | Maximum number of requests on Envoy clusters | int | `1024` |
| envoy.connectTimeoutSeconds | Time in seconds after which a TCP connection attempt times out | int | `2` |
| envoy.debug.admin.enabled | Enable admin interface for cilium-envoy. This is useful for debugging and should not be enabled in production. | bool | `false` |
| envoy.debug.admin.port | Port number (bound to loopback interface). kubectl port-forward can be used to access the admin interface. | int | `9901` |
| envoy.dnsPolicy | DNS policy for Cilium envoy pods. Ref: https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pod-s-dns-policy | string | `nil` |
| envoy.enabled | Enable Envoy Proxy in standalone DaemonSet. This field is enabled by default for new installation. | string | `true` for new installation |
| envoy.extraArgs | Additional envoy container arguments. | list | `[]` |
| envoy.extraContainers | Additional containers added to the cilium Envoy DaemonSet. | list | `[]` |
| envoy.extraEnv | Additional envoy container environment variables. | list | `[]` |
| envoy.extraHostPathMounts | Additional envoy hostPath mounts. | list | `[]` |
| envoy.extraVolumeMounts | Additional envoy volumeMounts. | list | `[]` |
| envoy.extraVolumes | Additional envoy volumes. | list | `[]` |
| envoy.healthPort | TCP port for the health API. | int | `9878` |
| envoy.httpRetryCount | Maximum number of retries for each HTTP request | int | `3` |
| envoy.httpUpstreamLingerTimeout | Time in seconds to block Envoy worker thread while an upstream HTTP connection is closing. If set to 0, the connection is closed immediately (with TCP RST). If set to -1, the connection is closed asynchronously in the background. | string | `nil` |
| envoy.idleTimeoutDurationSeconds | Set Envoy upstream HTTP idle connection timeout seconds. Does not apply to connections with pending requests. Default 60s | int | `60` |
| envoy.image | Envoy container image. | object | `{"digest":"sha256:70cf6a84a5518bdc501b4fa96eafaf8a8d88517fa2cf42e65977680c3f6f1462","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/cilium-envoy","tag":"v1.36.5-1773729229-f15b6334115ed4d8027b2460a8eb1f6c611660f0","useDigest":true}` |
| envoy.initContainers | Init containers added to the cilium Envoy DaemonSet. | list | `[]` |
| envoy.initialFetchTimeoutSeconds | Time in seconds after which the initial fetch on an xDS stream is considered timed out | int | `30` |
| envoy.livenessProbe.enabled | Enable liveness probe for cilium-envoy | bool | `true` |
| envoy.livenessProbe.failureThreshold | failure threshold of liveness probe | int | `10` |
| envoy.livenessProbe.periodSeconds | interval between checks of the liveness probe | int | `30` |
| envoy.log.accessLogBufferSize | Size of the Envoy access log buffer created within the agent in bytes. Tune this value up if you encounter "Envoy: Discarded truncated access log message" errors. Large request/response header sizes (e.g. 16KiB) will require a larger buffer size. | int | `4096` |
| envoy.log.accessLogWorkers | Number of worker goroutines processing Envoy access log messages per connection. Increase this value on nodes with high L7 traffic to reduce per-connection processing latency. | int | `4` |
| envoy.log.defaultLevel | Default log level of Envoy application log that is configured if Cilium debug / verbose logging isn't enabled. This option allows to have a different log level than the Cilium Agent - e.g. lower it to `critical`. Possible values: trace, debug, info, warning, error, critical, off | string | Defaults to the default log level of the Cilium Agent - `info` |
| envoy.log.format | The format string to use for laying out the log message metadata of Envoy. If specified, Envoy will use text format output. This setting is mutually exclusive with envoy.log.format_json. | string | `"[%Y-%m-%d %T.%e][%t][%l][%n] [%g:%#] %v"` |
| envoy.log.format_json | The JSON logging format to use for Envoy. This setting is mutually exclusive with envoy.log.format. ref: https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/bootstrap/v3/bootstrap.proto#envoy-v3-api-field-config-bootstrap-v3-bootstrap-applicationlogconfig-logformat-json-format | string | `nil` |
| envoy.log.path | Path to a separate Envoy log file, if any. Defaults to /dev/stdout. | string | `""` |
| envoy.maxConcurrentRetries | Maximum number of concurrent retries on Envoy clusters | int | `128` |
| envoy.maxConnectionDurationSeconds | Set Envoy HTTP option max_connection_duration seconds. Default 0 (disable) | int | `0` |
| envoy.maxGlobalDownstreamConnections | Maximum number of global downstream connections | int | `50000` |
| envoy.maxRequestsPerConnection | ProxyMaxRequestsPerConnection specifies the max_requests_per_connection setting for Envoy | int | `0` |
| envoy.nodeSelector | Node selector for cilium-envoy. | object | `{"kubernetes.io/os":"linux"}` |
| envoy.podAnnotations | Annotations to be added to envoy pods | object | `{}` |
| envoy.podLabels | Labels to be added to envoy pods | object | `{}` |
| envoy.podSecurityContext | Security Context for cilium-envoy pods. | object | `{"appArmorProfile":{"type":"Unconfined"}}` |
| envoy.podSecurityContext.appArmorProfile | AppArmorProfile options for the `cilium-agent` and init containers | object | `{"type":"Unconfined"}` |
| envoy.policyRestoreTimeoutDuration | Max duration to wait for endpoint policies to be restored on restart. Default "3m". | string | `nil` |
| envoy.priorityClassName | The priority class to use for cilium-envoy. | string | `nil` |
| envoy.prometheus | Configure Cilium Envoy Prometheus options. Note that some of these apply to either cilium-agent or cilium-envoy. | object | `{"enabled":true,"port":"9964","serviceMonitor":{"annotations":{},"enabled":false,"interval":"10s","labels":{},"metricRelabelings":null,"relabelings":[{"action":"replace","replacement":"${1}","sourceLabels":["__meta_kubernetes_pod_node_name"],"targetLabel":"node"}],"scrapeTimeout":null}}` |
| envoy.prometheus.enabled | Enable prometheus metrics for cilium-envoy | bool | `true` |
| envoy.prometheus.port | Serve prometheus metrics for cilium-envoy on the configured port | string | `"9964"` |
| envoy.prometheus.serviceMonitor.annotations | Annotations to add to ServiceMonitor cilium-envoy | object | `{}` |
| envoy.prometheus.serviceMonitor.enabled | Enable service monitors. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml) Note that this setting applies to both cilium-envoy _and_ cilium-agent with Envoy enabled. | bool | `false` |
| envoy.prometheus.serviceMonitor.interval | Interval for scrape metrics. | string | `"10s"` |
| envoy.prometheus.serviceMonitor.labels | Labels to add to ServiceMonitor cilium-envoy | object | `{}` |
| envoy.prometheus.serviceMonitor.metricRelabelings | Metrics relabeling configs for the ServiceMonitor cilium-envoy or for cilium-agent with Envoy configured. | string | `nil` |
| envoy.prometheus.serviceMonitor.relabelings | Relabeling configs for the ServiceMonitor cilium-envoy or for cilium-agent with Envoy configured. | list | `[{"action":"replace","replacement":"${1}","sourceLabels":["__meta_kubernetes_pod_node_name"],"targetLabel":"node"}]` |
| envoy.prometheus.serviceMonitor.scrapeTimeout | Timeout after which scrape is considered to be failed. | string | `nil` |
| envoy.readinessProbe.failureThreshold | failure threshold of readiness probe | int | `3` |
| envoy.readinessProbe.periodSeconds | interval between checks of the readiness probe | int | `30` |
| envoy.resources | Envoy resource limits & requests ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/ | object | `{}` |
| envoy.rollOutPods | Roll out cilium envoy pods automatically when configmap is updated. | bool | `false` |
| envoy.securityContext.capabilities.envoy | Capabilities for the `cilium-envoy` container. Even though granted to the container, the cilium-envoy-starter wrapper drops all capabilities after forking the actual Envoy process. `NET_BIND_SERVICE` is the only capability that can be passed to the Envoy process by setting `envoy.securityContext.capabilities.keepNetBindService=true` (in addition to granting the capability to the container). Note: In case of embedded envoy, the capability must  be granted to the cilium-agent container. | list | `["NET_ADMIN","SYS_ADMIN"]` |
| envoy.securityContext.capabilities.keepCapNetBindService | Keep capability `NET_BIND_SERVICE` for Envoy process. | bool | `false` |
| envoy.securityContext.privileged | Run the pod with elevated privileges | bool | `false` |
| envoy.securityContext.seLinuxOptions | SELinux options for the `cilium-envoy` container | object | `{"level":"s0","type":"spc_t"}` |
| envoy.startupProbe.enabled | Enable startup probe for cilium-envoy | bool | `true` |
| envoy.startupProbe.failureThreshold | failure threshold of startup probe. 105 x 2s translates to the old behaviour of the readiness probe (120s delay + 30 x 3s) | int | `105` |
| envoy.startupProbe.periodSeconds | interval between checks of the startup probe | int | `2` |
| envoy.streamIdleTimeoutDurationSeconds | Set Envoy the amount of time that the connection manager will allow a stream to exist with no upstream or downstream activity. default 5 minutes | int | `300` |
| envoy.terminationGracePeriodSeconds | Configure termination grace period for cilium-envoy DaemonSet. | int | `1` |
| envoy.tolerations | Node tolerations for envoy scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/ | list | `[{"operator":"Exists"}]` |
| envoy.updateStrategy | cilium-envoy update strategy ref: https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/#updating-a-daemonset | object | `{"rollingUpdate":{"maxUnavailable":2},"type":"RollingUpdate"}` |
| envoy.useOriginalSourceAddress | For cases when CiliumEnvoyConfig is not used directly (Ingress, Gateway), configures Cilium BPF Metadata listener filter to use the original source address when extracting the metadata for a request. | bool | `true` |
| envoy.xffNumTrustedHopsL7PolicyEgress | Number of trusted hops regarding the x-forwarded-for and related HTTP headers for the egress L7 policy enforcement Envoy listeners. | int | `0` |
| envoy.xffNumTrustedHopsL7PolicyIngress | Number of trusted hops regarding the x-forwarded-for and related HTTP headers for the ingress L7 policy enforcement Envoy listeners. | int | `0` |
| envoyConfig.enabled | Enable CiliumEnvoyConfig CRD CiliumEnvoyConfig CRD can also be implicitly enabled by other options. | bool | `false` |
| envoyConfig.retryInterval | Interval in which an attempt is made to reconcile failed EnvoyConfigs. If the duration is zero, the retry is deactivated. | string | `"15s"` |
| envoyConfig.secretsNamespace | SecretsNamespace is the namespace in which envoy SDS will retrieve secrets from. | object | `{"create":true,"name":"cilium-secrets"}` |
| envoyConfig.secretsNamespace.create | Create secrets namespace for CiliumEnvoyConfig CRDs. | bool | `true` |
| envoyConfig.secretsNamespace.name | The name of the secret namespace to which Cilium agents are given read access. | string | `"cilium-secrets"` |
| etcd.enabled | Enable etcd mode for the agent. | bool | `false` |
| etcd.endpoints | List of etcd endpoints | list | `["https://CHANGE-ME:2379"]` |
| etcd.ssl | Enable use of TLS/SSL for connectivity to etcd. | bool | `false` |
| extraArgs | Additional agent container arguments. | list | `[]` |
| extraConfig | extraConfig allows you to specify additional configuration parameters to be included in the cilium-config configmap. | object | `{}` |
| extraContainers | Additional containers added to the cilium DaemonSet. | list | `[]` |
| extraEnv | Additional agent container environment variables. | list | `[]` |
| extraHostPathMounts | Additional agent hostPath mounts. | list | `[]` |
| extraInitContainers | Additional initContainers added to the cilium Daemonset. | list | `[]` |
| extraVolumeMounts | Additional agent volumeMounts. | list | `[]` |
| extraVolumes | Additional agent volumes. | list | `[]` |
| forceDeviceDetection | Forces the auto-detection of devices, even if specific devices are explicitly listed | bool | `false` |
| gatewayAPI.enableAlpn | Enable ALPN for all listeners configured with Gateway API. ALPN will attempt HTTP/2, then HTTP 1.1. Note that this will also enable `appProtocol` support, and services that wish to use HTTP/2 will need to indicate that via their `appProtocol`. | bool | `false` |
| gatewayAPI.enableAppProtocol | Enable Backend Protocol selection support (GEP-1911) for Gateway API via appProtocol. | bool | `false` |
| gatewayAPI.enableProxyProtocol | Enable proxy protocol for all GatewayAPI listeners. Note that _only_ Proxy protocol traffic will be accepted once this is enabled. | bool | `false` |
| gatewayAPI.enabled | Enable support for Gateway API in cilium This will automatically set enable-envoy-config as well. | bool | `false` |
| gatewayAPI.externalTrafficPolicy | Control how traffic from external sources is routed to the LoadBalancer Kubernetes Service for all Cilium GatewayAPI Gateway instances. Valid values are "Cluster" and "Local". Note that this value will be ignored when `hostNetwork.enabled == true`. ref: https://kubernetes.io/docs/reference/networking/virtual-ips/#external-traffic-policy | string | `"Cluster"` |
| gatewayAPI.gatewayClass.create | Enable creation of GatewayClass resource The default value is 'auto' which decides according to presence of gateway.networking.k8s.io/v1/GatewayClass in the cluster. Other possible values are 'true' and 'false', which will either always or never create the GatewayClass, respectively. | string | `"auto"` |
| gatewayAPI.hostNetwork.enabled | Configure whether the Envoy listeners should be exposed on the host network. | bool | `false` |
| gatewayAPI.hostNetwork.nodes.matchLabels | Specify the labels of the nodes where the Ingress listeners should be exposed  matchLabels:   kubernetes.io/os: linux   kubernetes.io/hostname: kind-worker | object | `{}` |
| gatewayAPI.secretsNamespace | SecretsNamespace is the namespace in which envoy SDS will retrieve TLS secrets from. | object | `{"create":true,"name":"cilium-secrets","sync":true}` |
| gatewayAPI.secretsNamespace.create | Create secrets namespace for Gateway API. | bool | `true` |
| gatewayAPI.secretsNamespace.name | Name of Gateway API secret namespace. | string | `"cilium-secrets"` |
| gatewayAPI.secretsNamespace.sync | Enable secret sync, which will make sure all TLS secrets used by Ingress are synced to secretsNamespace.name. If disabled, TLS secrets must be maintained externally. | bool | `true` |
| gatewayAPI.xffNumTrustedHops | The number of additional GatewayAPI proxy hops from the right side of the HTTP header to trust when determining the origin client's IP address. | int | `0` |
| gke.enabled | Enable Google Kubernetes Engine integration | bool | `false` |
| healthCheckICMPFailureThreshold | Number of ICMP requests sent for each health check before marking a node or endpoint unreachable. | int | `3` |
| healthChecking | Enable connectivity health checking. | bool | `true` |
| healthPort | TCP port for the agent health API. This is not the port for cilium-health. | int | `9879` |
| hostFirewall | Configure the host firewall. | object | `{"enabled":false}` |
| hostFirewall.enabled | Enables the enforcement of host policies in the eBPF datapath. | bool | `false` |
| hubble.annotations | Annotations to be added to all top-level hubble objects (resources under templates/hubble) | object | `{}` |
| hubble.dropEventEmitter | Emit v1.Events related to pods on detection of packet drops.    This feature is alpha, please provide feedback at https://github.com/cilium/cilium/issues/33975. | object | `{"enabled":false,"interval":"2m","reasons":["auth_required","policy_denied"]}` |
| hubble.dropEventEmitter.interval | - Minimum time between emitting same events. | string | `"2m"` |
| hubble.dropEventEmitter.reasons | - Drop reasons to emit events for. ref: https://docs.cilium.io/en/stable/_api/v1/flow/README/#dropreason | list | `["auth_required","policy_denied"]` |
| hubble.enabled | Enable Hubble (true by default). | bool | `true` |
| hubble.export | Hubble flows export. | object | `{"dynamic":{"config":{"configMapName":"cilium-flowlog-config","content":[{"aggregationInterval":"0s","excludeFilters":[],"fieldAggregate":[],"fieldMask":[],"fileCompress":false,"fileMaxBackups":5,"fileMaxSizeMb":10,"filePath":"/var/run/cilium/hubble/events.log","includeFilters":[],"name":"all"}],"createConfigMap":true},"enabled":false},"static":{"aggregationInterval":"0s","allowList":[],"denyList":[],"enabled":false,"fieldAggregate":[],"fieldMask":[],"fileCompress":false,"fileMaxBackups":5,"fileMaxSizeMb":10,"filePath":"/var/run/cilium/hubble/events.log"}}` |
| hubble.export.dynamic | - Dynamic exporters configuration. Dynamic exporters may be reconfigured without a need of agent restarts. | object | `{"config":{"configMapName":"cilium-flowlog-config","content":[{"aggregationInterval":"0s","excludeFilters":[],"fieldAggregate":[],"fieldMask":[],"fileCompress":false,"fileMaxBackups":5,"fileMaxSizeMb":10,"filePath":"/var/run/cilium/hubble/events.log","includeFilters":[],"name":"all"}],"createConfigMap":true},"enabled":false}` |
| hubble.export.dynamic.config.configMapName | -- Name of configmap with configuration that may be altered to reconfigure exporters within a running agents. | string | `"cilium-flowlog-config"` |
| hubble.export.dynamic.config.content | -- Exporters configuration in YAML format. | list | `[{"aggregationInterval":"0s","excludeFilters":[],"fieldAggregate":[],"fieldMask":[],"fileCompress":false,"fileMaxBackups":5,"fileMaxSizeMb":10,"filePath":"/var/run/cilium/hubble/events.log","includeFilters":[],"name":"all"}]` |
| hubble.export.dynamic.config.createConfigMap | -- True if helm installer should create config map. Switch to false if you want to self maintain the file content. | bool | `true` |
| hubble.export.static | - Static exporter configuration. Static exporter is bound to agent lifecycle. | object | `{"aggregationInterval":"0s","allowList":[],"denyList":[],"enabled":false,"fieldAggregate":[],"fieldMask":[],"fileCompress":false,"fileMaxBackups":5,"fileMaxSizeMb":10,"filePath":"/var/run/cilium/hubble/events.log"}` |
| hubble.export.static.aggregationInterval | - Defines the interval at which to aggregate before exporting Hubble flows.     Aggregation feature is only enabled when fieldAggregate is specified and aggregationInterval > 0s. | string | `"0s"` |
| hubble.export.static.fileCompress | - Enable compression of rotated files. | bool | `false` |
| hubble.export.static.fileMaxBackups | - Defines max number of backup/rotated files. | int | `5` |
| hubble.export.static.fileMaxSizeMb | - Defines max file size of output file before it gets rotated. | int | `10` |
| hubble.hostUsers | Enable hostUsers for Hubble. This will allow use of user-namespaces for hubble components. Not all clusters support user-namespaces. See: https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/ | bool | `nil` |
| hubble.listenAddress | An additional address for Hubble to listen to. Set this field ":4244" if you are enabling Hubble Relay, as it assumes that Hubble is listening on port 4244. | string | `":4244"` |
| hubble.metrics | Hubble metrics configuration. See https://docs.cilium.io/en/stable/observability/metrics/#hubble-metrics for more comprehensive documentation about Hubble metrics. | object | `{"dashboards":{"annotations":{},"enabled":false,"label":"grafana_dashboard","labelValue":"1","namespace":null},"dynamic":{"config":{"configMapName":"cilium-dynamic-metrics-config","content":[],"createConfigMap":true},"enabled":false},"enableOpenMetrics":false,"enabled":null,"port":9965,"serviceAnnotations":{},"serviceMonitor":{"annotations":{},"enabled":false,"interval":"10s","jobLabel":"","labels":{},"metricRelabelings":null,"relabelings":[{"action":"replace","replacement":"${1}","sourceLabels":["__meta_kubernetes_pod_node_name"],"targetLabel":"node"}],"scrapeTimeout":null,"tlsConfig":{}},"tls":{"enabled":false,"server":{"cert":"","existingSecret":"","extraDnsNames":[],"extraIpAddresses":[],"key":"","mtls":{"enabled":false,"key":"ca.crt","name":null,"useSecret":false}}}}` |
| hubble.metrics.dashboards | Grafana dashboards for hubble grafana can import dashboards based on the label and value ref: https://github.com/grafana/helm-charts/tree/main/charts/grafana#sidecar-for-dashboards | object | `{"annotations":{},"enabled":false,"label":"grafana_dashboard","labelValue":"1","namespace":null}` |
| hubble.metrics.dynamic.config.configMapName | -- Name of configmap with configuration that may be altered to reconfigure metric handlers within a running agent. | string | `"cilium-dynamic-metrics-config"` |
| hubble.metrics.dynamic.config.content | -- Exporters configuration in YAML format. | list | `[]` |
| hubble.metrics.dynamic.config.createConfigMap | -- True if helm installer should create config map. Switch to false if you want to self maintain the file content. | bool | `true` |
| hubble.metrics.enableOpenMetrics | Enables exporting hubble metrics in OpenMetrics format. | bool | `false` |
| hubble.metrics.enabled | Configures the list of metrics to collect. If empty or null, metrics are disabled. Example:    enabled:   - dns:query;ignoreAAAA   - drop   - tcp   - flow   - icmp   - http  You can specify the list of metrics from the helm CLI:    --set hubble.metrics.enabled="{dns:query;ignoreAAAA,drop,tcp,flow,icmp,http}"  | string | `nil` |
| hubble.metrics.port | Configure the port the hubble metric server listens on. | int | `9965` |
| hubble.metrics.serviceAnnotations | Annotations to be added to hubble-metrics service. | object | `{}` |
| hubble.metrics.serviceMonitor.annotations | Annotations to add to ServiceMonitor hubble | object | `{}` |
| hubble.metrics.serviceMonitor.enabled | Create ServiceMonitor resources for Prometheus Operator. This requires the prometheus CRDs to be available. ref: https://github.com/prometheus-operator/prometheus-operator/blob/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml) | bool | `false` |
| hubble.metrics.serviceMonitor.interval | Interval for scrape metrics. | string | `"10s"` |
| hubble.metrics.serviceMonitor.jobLabel | jobLabel to add for ServiceMonitor hubble | string | `""` |
| hubble.metrics.serviceMonitor.labels | Labels to add to ServiceMonitor hubble | object | `{}` |
| hubble.metrics.serviceMonitor.metricRelabelings | Metrics relabeling configs for the ServiceMonitor hubble | string | `nil` |
| hubble.metrics.serviceMonitor.relabelings | Relabeling configs for the ServiceMonitor hubble | list | `[{"action":"replace","replacement":"${1}","sourceLabels":["__meta_kubernetes_pod_node_name"],"targetLabel":"node"}]` |
| hubble.metrics.serviceMonitor.scrapeTimeout | Timeout after which scrape is considered to be failed. | string | `nil` |
| hubble.metrics.tls.server.cert | base64 encoded PEM values for the Hubble metrics server certificate (deprecated). Use existingSecret instead. | string | `""` |
| hubble.metrics.tls.server.existingSecret | Name of the Secret containing the certificate and key for the Hubble metrics server. If specified, cert and key are ignored. | string | `""` |
| hubble.metrics.tls.server.extraDnsNames | Extra DNS names added to certificate when it's auto generated | list | `[]` |
| hubble.metrics.tls.server.extraIpAddresses | Extra IP addresses added to certificate when it's auto generated | list | `[]` |
| hubble.metrics.tls.server.key | base64 encoded PEM values for the Hubble metrics server key (deprecated). Use existingSecret instead. | string | `""` |
| hubble.metrics.tls.server.mtls | Configure mTLS for the Hubble metrics server. | object | `{"enabled":false,"key":"ca.crt","name":null,"useSecret":false}` |
| hubble.metrics.tls.server.mtls.key | Entry of the ConfigMap containing the CA. | string | `"ca.crt"` |
| hubble.metrics.tls.server.mtls.name | Name of the ConfigMap containing the CA to validate client certificates against. If mTLS is enabled and this is unspecified, it will default to the same CA used for Hubble metrics server certificates. | string | `nil` |
| hubble.networkPolicyCorrelation | Enables network policy correlation of Hubble flows, i.e. populating `egress_allowed_by`, `ingress_denied_by` fields with policy information. | object | `{"enabled":true}` |
| hubble.peerService.clusterDomain | The cluster domain to use to query the Hubble Peer service. It should be the local cluster. | string | `"cluster.local"` |
| hubble.peerService.targetPort | Target Port for the Peer service, must match the hubble.listenAddress' port. | int | `4244` |
| hubble.preferIpv6 | Whether Hubble should prefer to announce IPv6 or IPv4 addresses if both are available. | bool | `false` |
| hubble.redact | Enables redacting sensitive information present in Layer 7 flows. | object | `{"enabled":false,"http":{"headers":{"allow":[],"deny":[]},"urlQuery":false,"userInfo":true}}` |
| hubble.redact.http.headers.allow | List of HTTP headers to allow: headers not matching will be redacted. Note: `allow` and `deny` lists cannot be used both at the same time, only one can be present. Example:   redact:     enabled: true     http:       headers:         allow:           - traceparent           - tracestate           - Cache-Control  You can specify the options from the helm CLI:   --set hubble.redact.enabled="true"   --set hubble.redact.http.headers.allow="traceparent,tracestate,Cache-Control" | list | `[]` |
| hubble.redact.http.headers.deny | List of HTTP headers to deny: matching headers will be redacted. Note: `allow` and `deny` lists cannot be used both at the same time, only one can be present. Example:   redact:     enabled: true     http:       headers:         deny:           - Authorization           - Proxy-Authorization  You can specify the options from the helm CLI:   --set hubble.redact.enabled="true"   --set hubble.redact.http.headers.deny="Authorization,Proxy-Authorization" | list | `[]` |
| hubble.redact.http.urlQuery | Enables redacting URL query (GET) parameters. Example:    redact:     enabled: true     http:       urlQuery: true  You can specify the options from the helm CLI:    --set hubble.redact.enabled="true"   --set hubble.redact.http.urlQuery="true" | bool | `false` |
| hubble.redact.http.userInfo | Enables redacting user info, e.g., password when basic auth is used. Example:    redact:     enabled: true     http:       userInfo: true  You can specify the options from the helm CLI:    --set hubble.redact.enabled="true"   --set hubble.redact.http.userInfo="true" | bool | `true` |
| hubble.relay.affinity | Affinity for hubble-replay | object | `{"podAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"k8s-app":"cilium"}},"topologyKey":"kubernetes.io/hostname"}]}}` |
| hubble.relay.annotations | Annotations to be added to all top-level hubble-relay objects (resources under templates/hubble-relay) | object | `{}` |
| hubble.relay.enabled | Enable Hubble Relay (requires hubble.enabled=true) | bool | `false` |
| hubble.relay.extraEnv | Additional hubble-relay environment variables. | list | `[]` |
| hubble.relay.extraVolumeMounts | Additional hubble-relay volumeMounts. | list | `[]` |
| hubble.relay.extraVolumes | Additional hubble-relay volumes. | list | `[]` |
| hubble.relay.gops.enabled | Enable gops for hubble-relay | bool | `true` |
| hubble.relay.gops.port | Configure gops listen port for hubble-relay | int | `9893` |
| hubble.relay.image | Hubble-relay container image. | object | `{"digest":"","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/hubble-relay-ci","tag":"latest","useDigest":false}` |
| hubble.relay.listenHost | Host to listen to. Specify an empty string to bind to all the interfaces. | string | `""` |
| hubble.relay.listenPort | Port to listen to. | string | `"4245"` |
| hubble.relay.logOptions | Logging configuration for hubble-relay. | object | `{"format":null,"level":null}` |
| hubble.relay.logOptions.format | Log format for hubble-relay. Valid values are: text, text-ts, json, json-ts. | string | text-ts |
| hubble.relay.logOptions.level | Log level for hubble-relay. Valid values are: debug, info, warn, error. | string | info |
| hubble.relay.nodeSelector | Node labels for pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector | object | `{"kubernetes.io/os":"linux"}` |
| hubble.relay.podAnnotations | Annotations to be added to hubble-relay pods | object | `{}` |
| hubble.relay.podDisruptionBudget.enabled | enable PodDisruptionBudget ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/ | bool | `false` |
| hubble.relay.podDisruptionBudget.maxUnavailable | Maximum number/percentage of pods that may be made unavailable | int | `1` |
| hubble.relay.podDisruptionBudget.minAvailable | Minimum number/percentage of pods that should remain scheduled. When it's set, maxUnavailable must be disabled by `maxUnavailable: null` | string | `nil` |
| hubble.relay.podDisruptionBudget.unhealthyPodEvictionPolicy | How are unhealthy, but running, pods counted for eviction | string | `nil` |
| hubble.relay.podLabels | Labels to be added to hubble-relay pods | object | `{}` |
| hubble.relay.podSecurityContext | hubble-relay pod security context | object | `{"fsGroup":65532,"seccompProfile":{"type":"RuntimeDefault"}}` |
| hubble.relay.pprof.address | Configure pprof listen address for hubble-relay | string | `"localhost"` |
| hubble.relay.pprof.blockProfileRate | Enable goroutine blocking profiling for hubble-relay and set the rate of sampled events in nanoseconds (set to 1 to sample all events [warning: performance overhead]) | int | `0` |
| hubble.relay.pprof.enabled | Enable pprof for hubble-relay | bool | `false` |
| hubble.relay.pprof.mutexProfileFraction | Enable mutex contention profiling for hubble-relay and set the fraction of sampled events (set to 1 to sample all events) | int | `0` |
| hubble.relay.pprof.port | Configure pprof listen port for hubble-relay | int | `6062` |
| hubble.relay.priorityClassName | The priority class to use for hubble-relay | string | `""` |
| hubble.relay.prometheus | Enable prometheus metrics for hubble-relay on the configured port at /metrics | object | `{"enabled":false,"port":9966,"serviceMonitor":{"annotations":{},"enabled":false,"interval":"10s","labels":{},"metricRelabelings":null,"relabelings":null,"scrapeTimeout":null}}` |
| hubble.relay.prometheus.serviceMonitor.annotations | Annotations to add to ServiceMonitor hubble-relay | object | `{}` |
| hubble.relay.prometheus.serviceMonitor.enabled | Enable service monitors. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml) | bool | `false` |
| hubble.relay.prometheus.serviceMonitor.interval | Interval for scrape metrics. | string | `"10s"` |
| hubble.relay.prometheus.serviceMonitor.labels | Labels to add to ServiceMonitor hubble-relay | object | `{}` |
| hubble.relay.prometheus.serviceMonitor.metricRelabelings | Metrics relabeling configs for the ServiceMonitor hubble-relay | string | `nil` |
| hubble.relay.prometheus.serviceMonitor.relabelings | Relabeling configs for the ServiceMonitor hubble-relay | string | `nil` |
| hubble.relay.prometheus.serviceMonitor.scrapeTimeout | Timeout after which scrape is considered to be failed. | string | `nil` |
| hubble.relay.replicas | Number of replicas run for the hubble-relay deployment. | int | `1` |
| hubble.relay.resources | Specifies the resources for the hubble-relay pods | object | `{}` |
| hubble.relay.retryTimeout | Backoff duration to retry connecting to the local hubble instance in case of failure (e.g. "30s"). | string | `nil` |
| hubble.relay.rollOutPods | Roll out Hubble Relay pods automatically when configmap is updated. | bool | `false` |
| hubble.relay.securityContext | hubble-relay container security context | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true,"runAsGroup":65532,"runAsNonRoot":true,"runAsUser":65532,"seccompProfile":{"type":"RuntimeDefault"}}` |
| hubble.relay.service | hubble-relay service configuration. | object | `{"nodePort":31234,"type":"ClusterIP"}` |
| hubble.relay.service.nodePort | - The port to use when the service type is set to NodePort. | int | `31234` |
| hubble.relay.service.type | - The type of service used for Hubble Relay access, either ClusterIP, NodePort or LoadBalancer. | string | `"ClusterIP"` |
| hubble.relay.sortBufferDrainTimeout | When the per-request flows sort buffer is not full, a flow is drained every time this timeout is reached (only affects requests in follow-mode) (e.g. "1s"). | string | `nil` |
| hubble.relay.sortBufferLenMax | Max number of flows that can be buffered for sorting before being sent to the client (per request) (e.g. 100). | int | `nil` |
| hubble.relay.terminationGracePeriodSeconds | Configure termination grace period for hubble relay Deployment. | int | `1` |
| hubble.relay.tls | TLS configuration for Hubble Relay | object | `{"client":{"cert":"","existingSecret":"","key":""},"server":{"cert":"","enabled":false,"existingSecret":"","extraDnsNames":[],"extraIpAddresses":[],"key":"","mtls":false,"relayName":"ui.hubble-relay.cilium.io"}}` |
| hubble.relay.tls.client | The hubble-relay client certificate and private key. This keypair is presented to Hubble server instances for mTLS authentication and is required when hubble.tls.enabled is true. These values need to be set manually if hubble.tls.auto.enabled is false. | object | `{"cert":"","existingSecret":"","key":""}` |
| hubble.relay.tls.client.cert | base64 encoded PEM values for the Hubble relay client certificate (deprecated). Use existingSecret instead. | string | `""` |
| hubble.relay.tls.client.existingSecret | Name of the Secret containing the certificate and key for the Hubble metrics server. If specified, cert and key are ignored. | string | `""` |
| hubble.relay.tls.client.key | base64 encoded PEM values for the Hubble relay client key (deprecated). Use existingSecret instead. | string | `""` |
| hubble.relay.tls.server | The hubble-relay server certificate and private key | object | `{"cert":"","enabled":false,"existingSecret":"","extraDnsNames":[],"extraIpAddresses":[],"key":"","mtls":false,"relayName":"ui.hubble-relay.cilium.io"}` |
| hubble.relay.tls.server.cert | base64 encoded PEM values for the Hubble relay server certificate (deprecated). Use existingSecret instead. | string | `""` |
| hubble.relay.tls.server.existingSecret | Name of the Secret containing the certificate and key for the Hubble relay server. If specified, cert and key are ignored. | string | `""` |
| hubble.relay.tls.server.extraDnsNames | extra DNS names added to certificate when its auto gen | list | `[]` |
| hubble.relay.tls.server.extraIpAddresses | extra IP addresses added to certificate when its auto gen | list | `[]` |
| hubble.relay.tls.server.key | base64 encoded PEM values for the Hubble relay server key (deprecated). Use existingSecret instead. | string | `""` |
| hubble.relay.tolerations | Node tolerations for pod assignment on nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/ | list | `[]` |
| hubble.relay.topologySpreadConstraints | Pod topology spread constraints for hubble-relay | list | `[]` |
| hubble.relay.updateStrategy | hubble-relay update strategy | object | `{"rollingUpdate":{"maxUnavailable":1},"type":"RollingUpdate"}` |
| hubble.skipUnknownCGroupIDs | Skip Hubble events with unknown cgroup ids | bool | `true` |
| hubble.socketPath | Unix domain socket path to listen to when Hubble is enabled. | string | `"/var/run/cilium/hubble.sock"` |
| hubble.tls | TLS configuration for Hubble | object | `{"auto":{"certManagerIssuerRef":{},"certValidityDuration":365,"enabled":true,"method":"helm","schedule":"0 0 1 */4 *"},"enabled":true,"server":{"cert":"","existingSecret":"","extraDnsNames":[],"extraIpAddresses":[],"key":""}}` |
| hubble.tls.auto | Configure automatic TLS certificates generation. | object | `{"certManagerIssuerRef":{},"certValidityDuration":365,"enabled":true,"method":"helm","schedule":"0 0 1 */4 *"}` |
| hubble.tls.auto.certManagerIssuerRef | certmanager issuer used when hubble.tls.auto.method=certmanager. | object | `{}` |
| hubble.tls.auto.certValidityDuration | Generated certificates validity duration in days.  Defaults to 365 days (1 year) because MacOS does not accept self-signed certificates with expirations > 825 days. | int | `365` |
| hubble.tls.auto.enabled | Auto-generate certificates. When set to true, automatically generate a CA and certificates to enable mTLS between Hubble server and Hubble Relay instances. If set to false, the certs for Hubble server need to be provided by setting appropriate values below. | bool | `true` |
| hubble.tls.auto.method | Set the method to auto-generate certificates. Supported values: - helm:         This method uses Helm to generate all certificates. - cronJob:      This method uses a Kubernetes CronJob the generate any                 certificates not provided by the user at installation                 time. - certmanager:  This method use cert-manager to generate & rotate certificates. | string | `"helm"` |
| hubble.tls.auto.schedule | Schedule for certificates regeneration (regardless of their expiration date). Only used if method is "cronJob". If nil, then no recurring job will be created. Instead, only the one-shot job is deployed to generate the certificates at installation time.  Defaults to midnight of the first day of every fourth month. For syntax, see https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/#schedule-syntax | string | `"0 0 1 */4 *"` |
| hubble.tls.enabled | Enable mutual TLS for listenAddress. Setting this value to false is highly discouraged as the Hubble API provides access to potentially sensitive network flow metadata and is exposed on the host network. | bool | `true` |
| hubble.tls.server | The Hubble server certificate and private key | object | `{"cert":"","existingSecret":"","extraDnsNames":[],"extraIpAddresses":[],"key":""}` |
| hubble.tls.server.cert | base64 encoded PEM values for the Hubble server certificate (deprecated). Use existingSecret instead. | string | `""` |
| hubble.tls.server.existingSecret | Name of the Secret containing the certificate and key for the Hubble server. If specified, cert and key are ignored. | string | `""` |
| hubble.tls.server.extraDnsNames | Extra DNS names added to certificate when it's auto generated | list | `[]` |
| hubble.tls.server.extraIpAddresses | Extra IP addresses added to certificate when it's auto generated | list | `[]` |
| hubble.tls.server.key | base64 encoded PEM values for the Hubble server key (deprecated). Use existingSecret instead. | string | `""` |
| hubble.ui.affinity | Affinity for hubble-ui | object | `{}` |
| hubble.ui.annotations | Annotations to be added to all top-level hubble-ui objects (resources under templates/hubble-ui) | object | `{}` |
| hubble.ui.backend.extraEnv | Additional hubble-ui backend environment variables. | list | `[]` |
| hubble.ui.backend.extraVolumeMounts | Additional hubble-ui backend volumeMounts. | list | `[]` |
| hubble.ui.backend.extraVolumes | Additional hubble-ui backend volumes. | list | `[]` |
| hubble.ui.backend.image | Hubble-ui backend image. | object | `{"digest":"sha256:db1454e45dc39ca41fbf7cad31eec95d99e5b9949c39daaad0fa81ef29d56953","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/hubble-ui-backend","tag":"v0.13.3","useDigest":true}` |
| hubble.ui.backend.resources | Resource requests and limits for the 'backend' container of the 'hubble-ui' deployment. | object | `{}` |
| hubble.ui.backend.securityContext | Hubble-ui backend security context. | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}` |
| hubble.ui.baseUrl | Defines base url prefix for all hubble-ui http requests. It needs to be changed in case if ingress for hubble-ui is configured under some sub-path. Trailing `/` is required for custom path, ex. `/service-map/` | string | `"/"` |
| hubble.ui.enabled | Whether to enable the Hubble UI. | bool | `false` |
| hubble.ui.frontend.extraEnv | Additional hubble-ui frontend environment variables. | list | `[]` |
| hubble.ui.frontend.extraVolumeMounts | Additional hubble-ui frontend volumeMounts. | list | `[]` |
| hubble.ui.frontend.extraVolumes | Additional hubble-ui frontend volumes. | list | `[]` |
| hubble.ui.frontend.image | Hubble-ui frontend image. | object | `{"digest":"sha256:661d5de7050182d495c6497ff0b007a7a1e379648e60830dd68c4d78ae21761d","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/hubble-ui","tag":"v0.13.3","useDigest":true}` |
| hubble.ui.frontend.resources | Resource requests and limits for the 'frontend' container of the 'hubble-ui' deployment. | object | `{}` |
| hubble.ui.frontend.securityContext | Hubble-ui frontend security context. | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}` |
| hubble.ui.frontend.server.ipv6 | Controls server listener for ipv6 | object | `{"enabled":true}` |
| hubble.ui.ingress | hubble-ui ingress configuration. | object | `{"annotations":{},"className":"","enabled":false,"hosts":["chart-example.local"],"labels":{},"tls":[]}` |
| hubble.ui.labels | Additional labels to be added to 'hubble-ui' deployment object | object | `{}` |
| hubble.ui.nodeSelector | Node labels for pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector | object | `{"kubernetes.io/os":"linux"}` |
| hubble.ui.podAnnotations | Annotations to be added to hubble-ui pods | object | `{}` |
| hubble.ui.podDisruptionBudget.enabled | enable PodDisruptionBudget ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/ | bool | `false` |
| hubble.ui.podDisruptionBudget.maxUnavailable | Maximum number/percentage of pods that may be made unavailable | int | `1` |
| hubble.ui.podDisruptionBudget.minAvailable | Minimum number/percentage of pods that should remain scheduled. When it's set, maxUnavailable must be disabled by `maxUnavailable: null` | string | `nil` |
| hubble.ui.podDisruptionBudget.unhealthyPodEvictionPolicy | How are unhealthy, but running, pods counted for eviction | string | `nil` |
| hubble.ui.podLabels | Labels to be added to hubble-ui pods | object | `{}` |
| hubble.ui.priorityClassName | The priority class to use for hubble-ui | string | `""` |
| hubble.ui.replicas | The number of replicas of Hubble UI to deploy. | int | `1` |
| hubble.ui.rollOutPods | Roll out Hubble-ui pods automatically when configmap is updated. | bool | `false` |
| hubble.ui.securityContext | Security context to be added to Hubble UI pods | object | `{"fsGroup":1001,"runAsGroup":1001,"runAsNonRoot":true,"runAsUser":1001,"seccompProfile":{"type":"RuntimeDefault"}}` |
| hubble.ui.service | hubble-ui service configuration. | object | `{"annotations":{},"labels":{},"nodePort":31235,"type":"ClusterIP"}` |
| hubble.ui.service.annotations | Annotations to be added for the Hubble UI service | object | `{}` |
| hubble.ui.service.labels | Labels to be added for the Hubble UI service | object | `{}` |
| hubble.ui.service.nodePort | - The port to use when the service type is set to NodePort. | int | `31235` |
| hubble.ui.service.type | - The type of service used for Hubble UI access, either ClusterIP or NodePort. | string | `"ClusterIP"` |
| hubble.ui.standalone.enabled | When true, it will allow installing the Hubble UI only, without checking dependencies. It is useful if a cluster already has cilium and Hubble relay installed and you just want Hubble UI to be deployed. When installed via helm, installing UI should be done via `helm upgrade` and when installed via the cilium cli, then `cilium hubble enable --ui` | bool | `false` |
| hubble.ui.standalone.tls.certsVolume | When deploying Hubble UI in standalone, with tls enabled for Hubble relay, it is required to provide a volume for mounting the client certificates. | object | `{}` |
| hubble.ui.tls.client.cert | base64 encoded PEM values for the Hubble UI client certificate (deprecated). Use existingSecret instead. | string | `""` |
| hubble.ui.tls.client.existingSecret | Name of the Secret containing the client certificate and key for Hubble UI If specified, cert and key are ignored. | string | `""` |
| hubble.ui.tls.client.key | base64 encoded PEM values for the Hubble UI client key (deprecated). Use existingSecret instead. | string | `""` |
| hubble.ui.tmpVolume | Configure temporary volume for hubble-ui | object | `{}` |
| hubble.ui.tolerations | Node tolerations for pod assignment on nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/ | list | `[]` |
| hubble.ui.topologySpreadConstraints | Pod topology spread constraints for hubble-ui | list | `[]` |
| hubble.ui.updateStrategy | hubble-ui update strategy. | object | `{"rollingUpdate":{"maxUnavailable":1},"type":"RollingUpdate"}` |
| identityAllocationMode | Method to use for identity allocation (`crd`, `kvstore` or `doublewrite-readkvstore` / `doublewrite-readcrd` for migrating between identity backends). | string | `"crd"` |
| identityChangeGracePeriod | Time to wait before using new identity on endpoint identity change. | string | `"5s"` |
| identityManagementMode | Control whether CiliumIdentities are created by the agent ("agent"), the operator ("operator") or both ("both"). "Both" should be used only to migrate between "agent" and "operator". Operator-managed identities is a beta feature. | string | `"agent"` |
| image | Agent container image. | object | `{"digest":"","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/cilium-ci","tag":"latest","useDigest":false}` |
| imagePullSecrets | Configure image pull secrets for pulling container images | list | `[]` |
| ingressController.default | Set cilium ingress controller to be the default ingress controller This will let cilium ingress controller route entries without ingress class set | bool | `false` |
| ingressController.defaultSecretName | Default secret name for ingresses without .spec.tls[].secretName set. | string | `nil` |
| ingressController.defaultSecretNamespace | Default secret namespace for ingresses without .spec.tls[].secretName set. | string | `nil` |
| ingressController.enableProxyProtocol | Enable proxy protocol for all Ingress listeners. Note that _only_ Proxy protocol traffic will be accepted once this is enabled. | bool | `false` |
| ingressController.enabled | Enable cilium ingress controller This will automatically set enable-envoy-config as well. | bool | `false` |
| ingressController.enforceHttps | Enforce https for host having matching TLS host in Ingress. Incoming traffic to http listener will return 308 http error code with respective location in header. | bool | `true` |
| ingressController.hostNetwork.enabled | Configure whether the Envoy listeners should be exposed on the host network. | bool | `false` |
| ingressController.hostNetwork.httpPort | Configure a specific port on the host network that gets used for the shared HTTP listener. If unset or 0, sharedListenerPort is used. | int | `0` |
| ingressController.hostNetwork.httpsPort | Configure a specific port on the host network that gets used for the shared HTTPS listener. If unset or 0, sharedListenerPort is used. | int | `0` |
| ingressController.hostNetwork.nodes.matchLabels | Specify the labels of the nodes where the Ingress listeners should be exposed  matchLabels:   kubernetes.io/os: linux   kubernetes.io/hostname: kind-worker | object | `{}` |
| ingressController.hostNetwork.sharedListenerPort | Configure a specific port on the host network that gets used for the shared listener. | int | `8080` |
| ingressController.hostNetwork.tlsPassthroughPort | Configure a specific port on the host network that gets used for the shared TLS passthrough listener. If unset or 0, sharedListenerPort is used. | int | `0` |
| ingressController.ingressLBAnnotationPrefixes | IngressLBAnnotations are the annotation and label prefixes, which are used to filter annotations and/or labels to propagate from Ingress to the Load Balancer service | list | `["lbipam.cilium.io","nodeipam.cilium.io","service.beta.kubernetes.io","service.kubernetes.io","cloud.google.com"]` |
| ingressController.loadbalancerMode | Default ingress load balancer mode Supported values: shared, dedicated For granular control, use the following annotations on the ingress resource: "ingress.cilium.io/loadbalancer-mode: dedicated" (or "shared"). | string | `"dedicated"` |
| ingressController.secretsNamespace | SecretsNamespace is the namespace in which envoy SDS will retrieve TLS secrets from. | object | `{"create":true,"name":"cilium-secrets","sync":true}` |
| ingressController.secretsNamespace.create | Create secrets namespace for Ingress. | bool | `true` |
| ingressController.secretsNamespace.name | Name of Ingress secret namespace. | string | `"cilium-secrets"` |
| ingressController.secretsNamespace.sync | Enable secret sync, which will make sure all TLS secrets used by Ingress are synced to secretsNamespace.name. If disabled, TLS secrets must be maintained externally. | bool | `true` |
| ingressController.service | Load-balancer service in shared mode. This is a single load-balancer service for all Ingress resources. | object | `{"allocateLoadBalancerNodePorts":null,"annotations":{},"externalTrafficPolicy":"Cluster","insecureNodePort":null,"labels":{},"loadBalancerClass":null,"loadBalancerIP":null,"name":"cilium-ingress","secureNodePort":null,"type":"LoadBalancer"}` |
| ingressController.service.allocateLoadBalancerNodePorts | Configure if node port allocation is required for LB service ref: https://kubernetes.io/docs/concepts/services-networking/service/#load-balancer-nodeport-allocation | string | `nil` |
| ingressController.service.annotations | Annotations to be added for the shared LB service | object | `{}` |
| ingressController.service.externalTrafficPolicy | Control how traffic from external sources is routed to the LoadBalancer Kubernetes Service for Cilium Ingress in shared mode. Valid values are "Cluster" and "Local". ref: https://kubernetes.io/docs/reference/networking/virtual-ips/#external-traffic-policy | string | `"Cluster"` |
| ingressController.service.insecureNodePort | Configure a specific nodePort for insecure HTTP traffic on the shared LB service | string | `nil` |
| ingressController.service.labels | Labels to be added for the shared LB service | object | `{}` |
| ingressController.service.loadBalancerClass | Configure a specific loadBalancerClass on the shared LB service (requires Kubernetes 1.24+) | string | `nil` |
| ingressController.service.loadBalancerIP | Configure a specific loadBalancerIP on the shared LB service | string | `nil` |
| ingressController.service.name | Service name | string | `"cilium-ingress"` |
| ingressController.service.secureNodePort | Configure a specific nodePort for secure HTTPS traffic on the shared LB service | string | `nil` |
| ingressController.service.type | Service type for the shared LB service | string | `"LoadBalancer"` |
| initResources | resources & limits for the agent init containers | object | `{}` |
| installNoConntrackIptablesRules | Install Iptables rules to skip netfilter connection tracking on all pod traffic. This option is only effective when Cilium is running in direct routing and full KPR mode. Moreover, this option cannot be enabled when Cilium is running in a managed Kubernetes environment or in a chained CNI setup. | bool | `false` |
| ipMasqAgent | Configure the eBPF-based ip-masq-agent | object | `{"enabled":false}` |
| ipam.ciliumNodeUpdateRate | Maximum rate at which the CiliumNode custom resource is updated. | string | `"15s"` |
| ipam.installUplinkRoutesForDelegatedIPAM | Install ingress/egress routes through uplink on host for Pods when working with delegated IPAM plugin. | bool | `false` |
| ipam.mode | Configure IP Address Management mode. ref: https://docs.cilium.io/en/stable/network/concepts/ipam/ | string | `"cluster-pool"` |
| ipam.multiPoolPreAllocation | Pre-allocation settings for IPAM in Multi-Pool mode | string | `""` |
| ipam.nodeSpec | NodeSpec configuration for the IPAM | object | `{"ipamMaxAllocate":null,"ipamMinAllocate":null,"ipamPreAllocate":null,"ipamStaticIPTags":[]}` |
| ipam.nodeSpec.ipamMaxAllocate | IPAM max allocate @schema type: [null, integer] @schema | string | `nil` |
| ipam.nodeSpec.ipamMinAllocate | IPAM min allocate @schema type: [null, integer] @schema | string | `nil` |
| ipam.nodeSpec.ipamPreAllocate | IPAM pre allocate @schema type: [null, integer] @schema | string | `nil` |
| ipam.nodeSpec.ipamStaticIPTags | IPAM static IP tags (currently only works with AWS and Azure) | list | `[]` |
| ipam.operator.autoCreateCiliumPodIPPools | IP pools to auto-create in multi-pool IPAM mode. | object | `{}` |
| ipam.operator.clusterPoolIPv4MaskSize | IPv4 CIDR mask size to delegate to individual nodes for IPAM. | int | `24` |
| ipam.operator.clusterPoolIPv4PodCIDRList | IPv4 CIDR list range to delegate to individual nodes for IPAM. | list | `["10.0.0.0/8"]` |
| ipam.operator.clusterPoolIPv6MaskSize | IPv6 CIDR mask size to delegate to individual nodes for IPAM. | int | `120` |
| ipam.operator.clusterPoolIPv6PodCIDRList | IPv6 CIDR list range to delegate to individual nodes for IPAM. | list | `["fd00::/104"]` |
| ipam.operator.externalAPILimitBurstSize | The maximum burst size when rate limiting access to external APIs. Also known as the token bucket capacity. | int | `20` |
| ipam.operator.externalAPILimitQPS | The maximum queries per second when rate limiting access to external APIs. Also known as the bucket refill rate, which is used to refill the bucket up to the burst size capacity. | float | `4.0` |
| iptablesRandomFully | Configure iptables--random-fully. Disabled by default. View https://github.com/cilium/cilium/issues/13037 for more information. | bool | `false` |
| ipv4.enabled | Enable IPv4 support. | bool | `true` |
| ipv4NativeRoutingCIDR | Allows to explicitly specify the IPv4 CIDR for native routing. When specified, Cilium assumes networking for this CIDR is preconfigured and hands traffic destined for that range to the Linux network stack without applying any SNAT. Generally speaking, specifying a native routing CIDR implies that Cilium can depend on the underlying networking stack to route packets to their destination. To offer a concrete example, if Cilium is configured to use direct routing and the Kubernetes CIDR is included in the native routing CIDR, the user must configure the routes to reach pods, either manually or by setting the auto-direct-node-routes flag. | string | `""` |
| ipv6.enabled | Enable IPv6 support. | bool | `false` |
| ipv6NativeRoutingCIDR | Allows to explicitly specify the IPv6 CIDR for native routing. When specified, Cilium assumes networking for this CIDR is preconfigured and hands traffic destined for that range to the Linux network stack without applying any SNAT. Generally speaking, specifying a native routing CIDR implies that Cilium can depend on the underlying networking stack to route packets to their destination. To offer a concrete example, if Cilium is configured to use direct routing and the Kubernetes CIDR is included in the native routing CIDR, the user must configure the routes to reach pods, either manually or by setting the auto-direct-node-routes flag. | string | `""` |
| k8s | Configure Kubernetes specific configuration | object | `{"requireIPv4PodCIDR":false,"requireIPv6PodCIDR":false}` |
| k8s.requireIPv4PodCIDR | requireIPv4PodCIDR enables waiting for Kubernetes to provide the PodCIDR range via the Kubernetes node resource | bool | `false` |
| k8s.requireIPv6PodCIDR | requireIPv6PodCIDR enables waiting for Kubernetes to provide the PodCIDR range via the Kubernetes node resource | bool | `false` |
| k8sClientExponentialBackoff | Configure exponential backoff for client-go in Cilium agent. | object | `{"backoffBaseSeconds":1,"backoffMaxDurationSeconds":120,"enabled":true}` |
| k8sClientExponentialBackoff.backoffBaseSeconds | Configure base (in seconds) for exponential backoff. | int | `1` |
| k8sClientExponentialBackoff.backoffMaxDurationSeconds | Configure maximum duration (in seconds) for exponential backoff. | int | `120` |
| k8sClientExponentialBackoff.enabled | Enable exponential backoff for client-go in Cilium agent. | bool | `true` |
| k8sClientRateLimit | Configure the client side rate limit for the agent  If the amount of requests to the Kubernetes API server exceeds the configured rate limit, the agent will start to throttle requests by delaying them until there is budget or the request times out. | object | `{"burst":null,"operator":{"burst":null,"qps":null},"qps":null}` |
| k8sClientRateLimit.burst | The burst request rate in requests per second. The rate limiter will allow short bursts with a higher rate. | int | 20 |
| k8sClientRateLimit.operator | Configure the client side rate limit for the Cilium Operator | object | `{"burst":null,"qps":null}` |
| k8sClientRateLimit.operator.burst | The burst request rate in requests per second. The rate limiter will allow short bursts with a higher rate. | int | 200 |
| k8sClientRateLimit.operator.qps | The sustained request rate in requests per second. | int | 100 |
| k8sClientRateLimit.qps | The sustained request rate in requests per second. | int | 10 |
| k8sClusterNetworkPolicy.enabled | Enable support for K8s Cluster Network Policy | bool | `false` |
| k8sNetworkPolicy.enabled | Enable support for K8s NetworkPolicy | bool | `true` |
| k8sServiceHost | Kubernetes service host - use "auto" for automatic lookup from the cluster-info ConfigMap | string | `""` |
| k8sServiceHostRef | Configure the Kubernetes service endpoint dynamically using a ConfigMap. Mutually exclusive with `k8sServiceHost`. | object | `{"key":null,"name":null}` |
| k8sServiceHostRef.key | Key in the ConfigMap containing the Kubernetes service endpoint | string | `nil` |
| k8sServiceHostRef.name | name of the ConfigMap containing the Kubernetes service endpoint | string | `nil` |
| k8sServiceLookupConfigMapName | When `k8sServiceHost=auto`, allows to customize the configMap name. It defaults to `cluster-info`. | string | `""` |
| k8sServiceLookupNamespace | When `k8sServiceHost=auto`, allows to customize the namespace that contains `k8sServiceLookupConfigMapName`. It defaults to `kube-public`. | string | `""` |
| k8sServicePort | Kubernetes service port | string | `""` |
| keepDeprecatedLabels | Keep the deprecated selector labels when deploying Cilium DaemonSet. | bool | `false` |
| keepDeprecatedProbes | Keep the deprecated probes when deploying Cilium DaemonSet | bool | `false` |
| kubeConfigPath | Kubernetes config path | string | `"~/.kube/config"` |
| kubeProxyReplacement | Configure the kube-proxy replacement in Cilium BPF datapath Valid options are "true" or "false". ref: https://docs.cilium.io/en/stable/network/kubernetes/kubeproxy-free/ @schema@ type: [string, boolean] @schema@ | string | `"false"` |
| kubeProxyReplacementHealthzBindAddr | healthz server bind address for the kube-proxy replacement. To enable set the value to '0.0.0.0:10256' for all ipv4 addresses and this '[::]:10256' for all ipv6 addresses. By default it is disabled. | string | `""` |
| l2NeighDiscovery.enabled | Enable L2 neighbor discovery in the agent | bool | `false` |
| l2announcements | Configure L2 announcements | object | `{"enabled":false}` |
| l2announcements.enabled | Enable L2 announcements | bool | `false` |
| l2podAnnouncements | Configure L2 pod announcements | object | `{"enabled":false,"interface":"eth0"}` |
| l2podAnnouncements.enabled | Enable L2 pod announcements | bool | `false` |
| l2podAnnouncements.interface | Interface used for sending Gratuitous ARP pod announcements | string | `"eth0"` |
| l7Proxy | Enable Layer 7 network policy. | bool | `true` |
| livenessProbe.failureThreshold | failure threshold of liveness probe | int | `10` |
| livenessProbe.periodSeconds | interval between checks of the liveness probe | int | `30` |
| livenessProbe.requireK8sConnectivity | whether to require k8s connectivity as part of the check. | bool | `false` |
| loadBalancer | Configure service load balancing | object | `{"acceleration":"disabled","l7":{"algorithm":"round_robin","backend":"disabled","ports":[]},"serviceTopology":false}` |
| loadBalancer.acceleration | acceleration is the option to accelerate service handling via XDP Applicable values can be: disabled (do not use XDP), native (XDP BPF program is run directly out of the networking driver's early receive path), or best-effort (use native mode XDP acceleration on devices that support it). | string | `"disabled"` |
| loadBalancer.l7 | L7 LoadBalancer | object | `{"algorithm":"round_robin","backend":"disabled","ports":[]}` |
| loadBalancer.l7.algorithm | Default LB algorithm The default LB algorithm to be used for services, which can be overridden by the service annotation (e.g. service.cilium.io/lb-l7-algorithm) Applicable values: round_robin, least_request, random | string | `"round_robin"` |
| loadBalancer.l7.backend | Enable L7 service load balancing via envoy proxy. The request to a k8s service, which has specific annotation e.g. service.cilium.io/lb-l7, will be forwarded to the local backend proxy to be load balanced to the service endpoints. Please refer to docs for supported annotations for more configuration.  Applicable values:   - envoy: Enable L7 load balancing via envoy proxy. This will automatically set enable-envoy-config as well.   - disabled: Disable L7 load balancing by way of service annotation. | string | `"disabled"` |
| loadBalancer.l7.ports | List of ports from service to be automatically redirected to above backend. Any service exposing one of these ports will be automatically redirected. Fine-grained control can be achieved by using the service annotation. | list | `[]` |
| loadBalancer.serviceTopology | serviceTopology enables K8s Topology Aware Hints -based service endpoints filtering | bool | `false` |
| localRedirectPolicies.addressMatcherCIDRs | Limit the allowed addresses in Address Matcher rule of Local Redirect Policies to the given CIDRs. @schema@ type: [null, array] @schema@ | string | `nil` |
| localRedirectPolicies.enabled | Enable local redirect policies. | bool | `false` |
| localRedirectPolicy | Enable Local Redirect Policy (deprecated, please use 'localRedirectPolicies.enabled' instead) | bool | `false` |
| logSystemLoad | Enables periodic logging of system load | bool | `false` |
| maglev | Configure maglev consistent hashing | object | `{}` |
| monitor | cilium-monitor sidecar. | object | `{"enabled":false}` |
| monitor.enabled | Enable the cilium-monitor sidecar. | bool | `false` |
| name | Agent daemonset name. | string | `"cilium"` |
| namespaceOverride | namespaceOverride allows to override the destination namespace for Cilium resources. | string | `""` |
| nat.mapStatsEntries | Number of the top-k SNAT map connections to track in Cilium statedb. | int | `32` |
| nat.mapStatsInterval | Interval between how often SNAT map is counted for stats. | string | `"30s"` |
| nat46x64Gateway | Configure standalone NAT46/NAT64 gateway | object | `{"enabled":false}` |
| nat46x64Gateway.enabled | Enable RFC6052-prefixed translation | bool | `false` |
| nodeIPAM.enabled | Configure Node IPAM ref: https://docs.cilium.io/en/stable/network/node-ipam/ | bool | `false` |
| nodePort | Configure N-S k8s service loadbalancing | object | `{"addresses":null,"autoProtectPortRange":true,"bindProtection":true,"enableHealthCheck":true,"enableHealthCheckLoadBalancerIP":false}` |
| nodePort.addresses | List of CIDRs for choosing which IP addresses assigned to native devices are used for NodePort load-balancing. By default this is empty and the first suitable, preferably private, IPv4 and IPv6 address assigned to each device is used.  Example:    addresses: ["192.168.1.0/24", "2001::/64"]  | string | `nil` |
| nodePort.autoProtectPortRange | Append NodePort range to ip_local_reserved_ports if clash with ephemeral ports is detected. | bool | `true` |
| nodePort.bindProtection | Set to true to prevent applications binding to service ports. | bool | `true` |
| nodePort.enableHealthCheck | Enable healthcheck nodePort server for NodePort services | bool | `true` |
| nodePort.enableHealthCheckLoadBalancerIP | Enable access of the healthcheck nodePort on the LoadBalancerIP. Needs EnableHealthCheck to be enabled | bool | `false` |
| nodeSelector | Node selector for cilium-agent. | object | `{"kubernetes.io/os":"linux"}` |
| nodeSelectorLabels | Enable/Disable use of node label based identity | bool | `false` |
| nodeinit.affinity | Affinity for cilium-nodeinit | object | `{}` |
| nodeinit.annotations | Annotations to be added to all top-level nodeinit objects (resources under templates/cilium-nodeinit) | object | `{}` |
| nodeinit.bootstrapFile | bootstrapFile is the location of the file where the bootstrap timestamp is written by the node-init DaemonSet | string | `"/tmp/cilium-bootstrap.d/cilium-bootstrap-time"` |
| nodeinit.enabled | Enable the node initialization DaemonSet | bool | `false` |
| nodeinit.extraEnv | Additional nodeinit environment variables. | list | `[]` |
| nodeinit.extraVolumeMounts | Additional nodeinit volumeMounts. | list | `[]` |
| nodeinit.extraVolumes | Additional nodeinit volumes. | list | `[]` |
| nodeinit.image | node-init image. | object | `{"digest":"sha256:bf1944bbdfd073bbb2b8d9c5baa315267a552aec6942102f930d2a7aa7ddc0e1","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/startup-script","tag":"1773335249-e45b074","useDigest":true}` |
| nodeinit.nodeSelector | Node labels for nodeinit pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector | object | `{"kubernetes.io/os":"linux"}` |
| nodeinit.podAnnotations | Annotations to be added to node-init pods. | object | `{}` |
| nodeinit.podLabels | Labels to be added to node-init pods. | object | `{}` |
| nodeinit.podSecurityContext | Security Context for cilium-node-init pods. | object | `{"appArmorProfile":{"type":"Unconfined"}}` |
| nodeinit.podSecurityContext.appArmorProfile | AppArmorProfile options for the `cilium-node-init` and init containers | object | `{"type":"Unconfined"}` |
| nodeinit.prestop | prestop offers way to customize prestop nodeinit script (pre and post position) | object | `{"postScript":"","preScript":""}` |
| nodeinit.priorityClassName | The priority class to use for the nodeinit pod. | string | `""` |
| nodeinit.resources | nodeinit resource limits & requests ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/ | object | `{"requests":{"cpu":"100m","memory":"100Mi"}}` |
| nodeinit.securityContext | Security context to be added to nodeinit pods. | object | `{"allowPrivilegeEscalation":false,"capabilities":{"add":["SYS_MODULE","NET_ADMIN","SYS_ADMIN","SYS_CHROOT","SYS_PTRACE"]},"privileged":false,"seLinuxOptions":{"level":"s0","type":"spc_t"}}` |
| nodeinit.startup | startup offers way to customize startup nodeinit script (pre and post position) | object | `{"postScript":"","preScript":""}` |
| nodeinit.tolerations | Node tolerations for nodeinit scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/ | list | `[{"operator":"Exists"}]` |
| nodeinit.updateStrategy | node-init update strategy | object | `{"type":"RollingUpdate"}` |
| nodeinit.waitForCloudInit | wait for Cloud init to finish on the host and assume the node has cloud init installed | bool | `false` |
| operator.affinity | Affinity for cilium-operator | object | `{"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"io.cilium/app":"operator"}},"topologyKey":"kubernetes.io/hostname"}]}}` |
| operator.annotations | Annotations to be added to all top-level cilium-operator objects (resources under templates/cilium-operator) | object | `{}` |
| operator.dashboards | Grafana dashboards for cilium-operator grafana can import dashboards based on the label and value ref: https://github.com/grafana/helm-charts/tree/main/charts/grafana#sidecar-for-dashboards | object | `{"annotations":{},"enabled":false,"label":"grafana_dashboard","labelValue":"1","namespace":null}` |
| operator.dnsPolicy | DNS policy for Cilium operator pods. Ref: https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pod-s-dns-policy | string | `""` |
| operator.enabled | Enable the cilium-operator component (required). | bool | `true` |
| operator.endpointGCInterval | Interval for endpoint garbage collection. | string | `"5m0s"` |
| operator.extraArgs | Additional cilium-operator container arguments. | list | `[]` |
| operator.extraEnv | Additional cilium-operator environment variables. | list | `[]` |
| operator.extraHostPathMounts | Additional cilium-operator hostPath mounts. | list | `[]` |
| operator.extraVolumeMounts | Additional cilium-operator volumeMounts. | list | `[]` |
| operator.extraVolumes | Additional cilium-operator volumes. | list | `[]` |
| operator.hostNetwork | HostNetwork setting | bool | `true` |
| operator.hostUsers | HostUsers setting (must be true if hostNetwork is true) | bool | `true` |
| operator.identityGCInterval | Interval for identity garbage collection. | string | `"15m0s"` |
| operator.identityHeartbeatTimeout | Timeout for identity heartbeats. | string | `"30m0s"` |
| operator.image | cilium-operator image. | object | `{"alibabacloudDigest":"","awsDigest":"","azureDigest":"","genericDigest":"","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/operator","suffix":"-ci","tag":"latest","useDigest":false}` |
| operator.nodeGCInterval | Interval for cilium node garbage collection. | string | `"5m0s"` |
| operator.nodeSelector | Node labels for cilium-operator pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector | object | `{"kubernetes.io/os":"linux"}` |
| operator.podAnnotations | Annotations to be added to cilium-operator pods | object | `{}` |
| operator.podDisruptionBudget.enabled | enable PodDisruptionBudget ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/ | bool | `false` |
| operator.podDisruptionBudget.maxUnavailable | Maximum number/percentage of pods that may be made unavailable | int | `1` |
| operator.podDisruptionBudget.minAvailable | Minimum number/percentage of pods that should remain scheduled. When it's set, maxUnavailable must be disabled by `maxUnavailable: null` | string | `nil` |
| operator.podDisruptionBudget.unhealthyPodEvictionPolicy | How are unhealthy, but running, pods counted for eviction | string | `nil` |
| operator.podLabels | Labels to be added to cilium-operator pods | object | `{}` |
| operator.podSecurityContext | Security context to be added to cilium-operator pods | object | `{"seccompProfile":{"type":"RuntimeDefault"}}` |
| operator.pprof.address | Configure pprof listen address for cilium-operator | string | `"localhost"` |
| operator.pprof.blockProfileRate | Enable goroutine blocking profiling for cilium-operator and set the rate of sampled events in nanoseconds (set to 1 to sample all events [warning: performance overhead]) | int | `0` |
| operator.pprof.enabled | Enable pprof for cilium-operator | bool | `false` |
| operator.pprof.mutexProfileFraction | Enable mutex contention profiling for cilium-operator and set the fraction of sampled events (set to 1 to sample all events) | int | `0` |
| operator.pprof.port | Configure pprof listen port for cilium-operator | int | `6061` |
| operator.priorityClassName | The priority class to use for cilium-operator | string | `""` |
| operator.prometheus | Enable prometheus metrics for cilium-operator on the configured port at /metrics | object | `{"enabled":true,"metricsService":false,"port":9963,"serviceMonitor":{"annotations":{},"enabled":false,"interval":"10s","jobLabel":"","labels":{},"metricRelabelings":null,"relabelings":null,"scrapeTimeout":null},"tls":{"enabled":false,"server":{"existingSecret":"","mtls":{"enabled":false}}}}` |
| operator.prometheus.serviceMonitor.annotations | Annotations to add to ServiceMonitor cilium-operator | object | `{}` |
| operator.prometheus.serviceMonitor.enabled | Enable service monitors. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml) | bool | `false` |
| operator.prometheus.serviceMonitor.interval | Interval for scrape metrics. | string | `"10s"` |
| operator.prometheus.serviceMonitor.jobLabel | jobLabel to add for ServiceMonitor cilium-operator | string | `""` |
| operator.prometheus.serviceMonitor.labels | Labels to add to ServiceMonitor cilium-operator | object | `{}` |
| operator.prometheus.serviceMonitor.metricRelabelings | Metrics relabeling configs for the ServiceMonitor cilium-operator | string | `nil` |
| operator.prometheus.serviceMonitor.relabelings | Relabeling configs for the ServiceMonitor cilium-operator | string | `nil` |
| operator.prometheus.serviceMonitor.scrapeTimeout | Timeout after which scrape is considered to be failed. | string | `nil` |
| operator.prometheus.tls | TLS configuration for Prometheus | object | `{"enabled":false,"server":{"existingSecret":"","mtls":{"enabled":false}}}` |
| operator.prometheus.tls.server.existingSecret | Name of the Secret containing the certificate, key and CA files for the Prometheus server. | string | `""` |
| operator.removeNodeTaints | Remove Cilium node taint from Kubernetes nodes that have a healthy Cilium pod running. | bool | `true` |
| operator.replicas | Number of replicas to run for the cilium-operator deployment | int | `2` |
| operator.resources | cilium-operator resource limits & requests ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/ | object | `{}` |
| operator.rollOutPods | Roll out cilium-operator pods automatically when configmap is updated. | bool | `false` |
| operator.securityContext | Security context to be added to cilium-operator pods | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}` |
| operator.setNodeNetworkStatus | Set Node condition NetworkUnavailable to 'false' with the reason 'CiliumIsUp' for nodes that have a healthy Cilium pod. | bool | `true` |
| operator.setNodeTaints | Taint nodes where Cilium is scheduled but not running. This prevents pods from being scheduled to nodes where Cilium is not the default CNI provider. | string | same as removeNodeTaints |
| operator.skipCRDCreation | Skip CRDs creation for cilium-operator | bool | `false` |
| operator.tolerations | Node tolerations for cilium-operator scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/ Toleration for agentNotReadyTaintKey taint is always added to cilium-operator pods. @schema type: [null, array] @schema | list | `[{"key":"node-role.kubernetes.io/control-plane","operator":"Exists"},{"key":"node-role.kubernetes.io/master","operator":"Exists"},{"key":"node.kubernetes.io/not-ready","operator":"Exists"},{"key":"node.cloudprovider.kubernetes.io/uninitialized","operator":"Exists"}]` |
| operator.topologySpreadConstraints | Pod topology spread constraints for cilium-operator | list | `[]` |
| operator.unmanagedPodWatcher.intervalSeconds | Interval, in seconds, to check if there are any pods that are not managed by Cilium. | int | `15` |
| operator.unmanagedPodWatcher.restart | Restart any pod that are not managed by Cilium. | bool | `true` |
| operator.unmanagedPodWatcher.selector | Selector for pods that should be restarted when not managed by Cilium. If not set, defaults to built-in selector "k8s-app=kube-dns". Set to empty string to select all pods. @schema type: [null, string] @schema | string | `nil` |
| operator.updateStrategy | cilium-operator update strategy | object | `{"rollingUpdate":{"maxSurge":"25%","maxUnavailable":"50%"},"type":"RollingUpdate"}` |
| pmtuDiscovery.enabled | Enable path MTU discovery to send ICMP fragmentation-needed replies to the client. | bool | `false` |
| pmtuDiscovery.packetizationLayerPMTUDMode | Enable kernel probing path MTU discovery for Pods which uses different message sizes to search for correct MTU value. Valid values are: always, blackhole, disabled and unset (or empty). If value is 'unset' or left empty then will not try to override setting. | string | `"blackhole"` |
| podAnnotations | Annotations to be added to agent pods | object | `{}` |
| podLabels | Labels to be added to agent pods | object | `{}` |
| podSecurityContext | Security Context for cilium-agent pods. | object | `{"appArmorProfile":{"type":"Unconfined"},"seccompProfile":{"type":"Unconfined"}}` |
| podSecurityContext.appArmorProfile | AppArmorProfile options for the `cilium-agent` and init containers | object | `{"type":"Unconfined"}` |
| policyCIDRMatchMode | policyCIDRMatchMode is a list of entities that may be selected by CIDR selector. The possible value is "nodes". | string | `nil` |
| policyDenyResponse | Configure what the response should be to pod egress traffic denied by network policy. Possible values:  - none (default)  - icmp | string | `"none"` |
| policyEnforcementMode | The agent can be put into one of the three policy enforcement modes: default, always and never. ref: https://docs.cilium.io/en/stable/security/policy/intro/#policy-enforcement-modes | string | `"default"` |
| pprof.address | Configure pprof listen address for cilium-agent | string | `"localhost"` |
| pprof.blockProfileRate | Enable goroutine blocking profiling for cilium-agent and set the rate of sampled events in nanoseconds (set to 1 to sample all events [warning: performance overhead]) | int | `0` |
| pprof.enabled | Enable pprof for cilium-agent | bool | `false` |
| pprof.mutexProfileFraction | Enable mutex contention profiling for cilium-agent and set the fraction of sampled events (set to 1 to sample all events) | int | `0` |
| pprof.port | Configure pprof listen port for cilium-agent | int | `6060` |
| preflight.affinity | Affinity for cilium-preflight | object | `{"podAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"k8s-app":"cilium"}},"topologyKey":"kubernetes.io/hostname"}]}}` |
| preflight.annotations | Annotations to be added to all top-level preflight objects (resources under templates/cilium-preflight) | object | `{}` |
| preflight.enabled | Enable Cilium pre-flight resources (required for upgrade) | bool | `false` |
| preflight.envoy.image | Envoy pre-flight image. | object | `{"digest":"sha256:70cf6a84a5518bdc501b4fa96eafaf8a8d88517fa2cf42e65977680c3f6f1462","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/cilium-envoy","tag":"v1.36.5-1773729229-f15b6334115ed4d8027b2460a8eb1f6c611660f0","useDigest":true}` |
| preflight.extraEnv | Additional preflight environment variables. | list | `[]` |
| preflight.extraVolumeMounts | Additional preflight volumeMounts. | list | `[]` |
| preflight.extraVolumes | Additional preflight volumes. | list | `[]` |
| preflight.image | Cilium pre-flight image. | object | `{"digest":"","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/cilium-ci","tag":"latest","useDigest":false}` |
| preflight.nodeSelector | Node labels for preflight pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector | object | `{"kubernetes.io/os":"linux"}` |
| preflight.podAnnotations | Annotations to be added to preflight pods | object | `{}` |
| preflight.podDisruptionBudget.enabled | enable PodDisruptionBudget ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/ | bool | `false` |
| preflight.podDisruptionBudget.maxUnavailable | Maximum number/percentage of pods that may be made unavailable | int | `1` |
| preflight.podDisruptionBudget.minAvailable | Minimum number/percentage of pods that should remain scheduled. When it's set, maxUnavailable must be disabled by `maxUnavailable: null` | string | `nil` |
| preflight.podDisruptionBudget.unhealthyPodEvictionPolicy | How are unhealthy, but running, pods counted for eviction | string | `nil` |
| preflight.podLabels | Labels to be added to the preflight pod. | object | `{}` |
| preflight.podSecurityContext | Security context to be added to preflight pods. | object | `{}` |
| preflight.priorityClassName | The priority class to use for the preflight pod. | string | `""` |
| preflight.readinessProbe.initialDelaySeconds | For how long kubelet should wait before performing the first probe | int | `5` |
| preflight.readinessProbe.periodSeconds | interval between checks of the readiness probe | int | `5` |
| preflight.resources | preflight resource limits & requests ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/ | object | `{}` |
| preflight.securityContext | Security context to be added to preflight pods | object | `{"allowPrivilegeEscalation":false}` |
| preflight.terminationGracePeriodSeconds | Configure termination grace period for preflight Deployment and DaemonSet. | int | `1` |
| preflight.tofqdnsPreCache | Path to write the `--tofqdns-pre-cache` file to. | string | `""` |
| preflight.tolerations | Node tolerations for preflight scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/ | list | `[{"operator":"Exists"}]` |
| preflight.updateStrategy | preflight update strategy | object | `{"type":"RollingUpdate"}` |
| preflight.validateCNPs | By default we should always validate the installed CNPs before upgrading Cilium. This will make sure the user will have the policies deployed in the cluster with the right schema. | bool | `true` |
| priorityClassName | The priority class to use for cilium-agent. | string | `""` |
| prometheus | Configure prometheus metrics on the configured port at /metrics | object | `{"controllerGroupMetrics":["write-cni-file","sync-host-ips","sync-lb-maps-with-k8s-services"],"enabled":false,"metrics":null,"metricsService":false,"port":9962,"serviceMonitor":{"annotations":{},"enabled":false,"interval":"10s","jobLabel":"","labels":{},"metricRelabelings":null,"relabelings":[{"action":"replace","replacement":"${1}","sourceLabels":["__meta_kubernetes_pod_node_name"],"targetLabel":"node"}],"scrapeTimeout":null,"trustCRDsExist":false}}` |
| prometheus.controllerGroupMetrics | - Enable controller group metrics for monitoring specific Cilium subsystems. The list is a list of controller group names. The special values of "all" and "none" are supported. The set of controller group names is not guaranteed to be stable between Cilium versions. | list | `["write-cni-file","sync-host-ips","sync-lb-maps-with-k8s-services"]` |
| prometheus.metrics | Metrics that should be enabled or disabled from the default metric list. The list is expected to be separated by a space. (+metric_foo to enable metric_foo , -metric_bar to disable metric_bar). ref: https://docs.cilium.io/en/stable/observability/metrics/ | string | `nil` |
| prometheus.serviceMonitor.annotations | Annotations to add to ServiceMonitor cilium-agent | object | `{}` |
| prometheus.serviceMonitor.enabled | Enable service monitors. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml) | bool | `false` |
| prometheus.serviceMonitor.interval | Interval for scrape metrics. | string | `"10s"` |
| prometheus.serviceMonitor.jobLabel | jobLabel to add for ServiceMonitor cilium-agent | string | `""` |
| prometheus.serviceMonitor.labels | Labels to add to ServiceMonitor cilium-agent | object | `{}` |
| prometheus.serviceMonitor.metricRelabelings | Metrics relabeling configs for the ServiceMonitor cilium-agent | string | `nil` |
| prometheus.serviceMonitor.relabelings | Relabeling configs for the ServiceMonitor cilium-agent | list | `[{"action":"replace","replacement":"${1}","sourceLabels":["__meta_kubernetes_pod_node_name"],"targetLabel":"node"}]` |
| prometheus.serviceMonitor.scrapeTimeout | Timeout after which scrape is considered to be failed. | string | `nil` |
| prometheus.serviceMonitor.trustCRDsExist | Set to `true` and helm will not check for monitoring.coreos.com/v1 CRDs before deploying | bool | `false` |
| rbac.create | Enable creation of Resource-Based Access Control configuration. | bool | `true` |
| readinessProbe.failureThreshold | failure threshold of readiness probe | int | `3` |
| readinessProbe.periodSeconds | interval between checks of the readiness probe | int | `30` |
| resourceQuotas | Enable resource quotas for priority classes used in the cluster. | object | `{"cilium":{"hard":{"pods":"10k"}},"enabled":false,"operator":{"hard":{"pods":"15"}}}` |
| resources | Agent resource limits & requests ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/ | object | `{}` |
| rollOutCiliumPods | Roll out cilium agent pods automatically when configmap is updated. | bool | `false` |
| routingMode | Enable native-routing mode or tunneling mode. Possible values:   - ""   - native   - tunnel | string | `"tunnel"` |
| scheduling | Scheduling configurations for cilium pods | object | `{"mode":"anti-affinity"}` |
| scheduling.mode | Mode specifies how Cilium daemonset pods should be scheduled to Nodes. `anti-affinity` mode applies a pod anti-affinity rule to the cilium daemonset. Pod anti-affinity may significantly impact scheduling throughput for large clusters. See: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#inter-pod-affinity-and-anti-affinity `kube-scheduler` mode forgoes the anti-affinity rule for full scheduling throughput. Kube-scheduler avoids host port conflict when scheduling pods. | string | Defaults to apply a pod anti-affinity rule to the agent pod - `anti-affinity` |
| sctp | SCTP Configuration Values | object | `{"enabled":false}` |
| sctp.enabled | Enable SCTP support. NOTE: Currently, SCTP support does not support rewriting ports or multihoming. | bool | `false` |
| secretsNamespaceAnnotations | Annotations to be added to all cilium-secret namespaces (resources under templates/cilium-secrets-namespace) | object | `{}` |
| secretsNamespaceLabels | Labels to be added to all cilium-secret namespaces (resources under templates/cilium-secrets-namespace) | object | `{}` |
| securityContext.allowPrivilegeEscalation | disable privilege escalation | bool | `false` |
| securityContext.capabilities.applySysctlOverwrites | capabilities for the `apply-sysctl-overwrites` init container | list | `["SYS_ADMIN","SYS_CHROOT","SYS_PTRACE"]` |
| securityContext.capabilities.ciliumAgent | Capabilities for the `cilium-agent` container | list | `["CHOWN","KILL","NET_ADMIN","NET_RAW","IPC_LOCK","SYS_MODULE","SYS_ADMIN","SYS_RESOURCE","DAC_OVERRIDE","FOWNER","SETGID","SETUID","SYSLOG"]` |
| securityContext.capabilities.cleanCiliumState | Capabilities for the `clean-cilium-state` init container | list | `["NET_ADMIN","SYS_MODULE","SYS_ADMIN","SYS_RESOURCE"]` |
| securityContext.capabilities.mountCgroup | Capabilities for the `mount-cgroup` init container | list | `["SYS_ADMIN","SYS_CHROOT","SYS_PTRACE"]` |
| securityContext.privileged | Run the pod with elevated privileges | bool | `false` |
| securityContext.seLinuxOptions | SELinux options for the `cilium-agent` and init containers | object | `{"level":"s0","type":"spc_t"}` |
| serviceAccounts | Define serviceAccount names for components. | object | Component's fully qualified name. |
| serviceAccounts.clustermeshcertgen | Clustermeshcertgen is used if clustermesh.apiserver.tls.auto.method=cronJob | object | `{"annotations":{},"automount":true,"create":true,"name":"clustermesh-apiserver-generate-certs"}` |
| serviceAccounts.corednsMCSAPI | CorednsMCSAPI is used if clustermesh.mcsapi.corednsAutoConfigure.enabled=true | object | `{"annotations":{},"automount":true,"create":true,"name":"cilium-coredns-mcsapi-autoconfig"}` |
| serviceAccounts.hubblecertgen | Hubblecertgen is used if hubble.tls.auto.method=cronJob | object | `{"annotations":{},"automount":true,"create":true,"name":"hubble-generate-certs"}` |
| serviceAccounts.nodeinit.enabled | Enabled is temporary until https://github.com/cilium/cilium-cli/issues/1396 is implemented. Cilium CLI doesn't create the SAs for node-init, thus the workaround. Helm is not affected by this issue. Name and automount can be configured, if enabled is set to true. Otherwise, they are ignored. Enabled can be removed once the issue is fixed. Cilium-nodeinit DS must also be fixed. | bool | `false` |
| serviceAccounts.ztunnel | Ztunnel is used if encryption.type=ztunnel | object | `{"annotations":{},"automount":false,"create":true,"name":"ztunnel-cilium"}` |
| serviceNoBackendResponse | Configure what the response should be to traffic for a service without backends. Possible values:  - reject (default)  - drop | string | `"reject"` |
| sleepAfterInit | Do not run Cilium agent when running with clean mode. Useful to completely uninstall Cilium as it will stop Cilium from starting and create artifacts in the node. | bool | `false` |
| socketLB | Configure socket LB | object | `{"enabled":false}` |
| socketLB.enabled | Enable socket LB | bool | `false` |
| standaloneDnsProxy | Standalone DNS Proxy Configuration Note: The standalone DNS proxy uses the agent's dnsProxy.* configuration for DNS settings (proxyPort, enableDnsCompression) to ensure consistency. | object | `{"annotations":{},"automountServiceAccountToken":false,"debug":false,"enabled":false,"image":{"digest":"","override":null,"pullPolicy":"Always","repository":"","tag":"","useDigest":false},"nodeSelector":{"kubernetes.io/os":"linux"},"rollOutPods":false,"serverPort":10095,"tolerations":[],"updateStrategy":{"rollingUpdate":{"maxSurge":2,"maxUnavailable":0},"type":"RollingUpdate"}}` |
| standaloneDnsProxy.annotations | Standalone DNS proxy annotations | object | `{}` |
| standaloneDnsProxy.automountServiceAccountToken | Standalone DNS proxy auto mount service account token | bool | `false` |
| standaloneDnsProxy.debug | Standalone DNS proxy debug mode | bool | `false` |
| standaloneDnsProxy.enabled | Enable standalone DNS proxy (alpha feature) | bool | `false` |
| standaloneDnsProxy.image | Standalone DNS proxy image | object | `{"digest":"","override":null,"pullPolicy":"Always","repository":"","tag":"","useDigest":false}` |
| standaloneDnsProxy.nodeSelector | Standalone DNS proxy Node Selector | object | `{"kubernetes.io/os":"linux"}` |
| standaloneDnsProxy.rollOutPods | Roll out Standalone DNS proxy automatically when configmap is updated. | bool | `false` |
| standaloneDnsProxy.serverPort | Standalone DNS proxy server port | int | `10095` |
| standaloneDnsProxy.tolerations | Standalone DNS proxy tolerations | list | `[]` |
| standaloneDnsProxy.updateStrategy | Standalone DNS proxy update strategy | object | `{"rollingUpdate":{"maxSurge":2,"maxUnavailable":0},"type":"RollingUpdate"}` |
| startupProbe.failureThreshold | failure threshold of startup probe. Allow Cilium to take up to 600s to start up (300 attempts with 2s between attempts). | int | `300` |
| startupProbe.periodSeconds | interval between checks of the startup probe | int | `2` |
| synchronizeK8sNodes | Synchronize Kubernetes nodes to kvstore and perform CNP GC. | bool | `true` |
| sysctlfix | Configure sysctl override described in #20072. | object | `{"enabled":true}` |
| sysctlfix.enabled | Enable the sysctl override. When enabled, the init container will mount the /proc of the host so that the `sysctlfix` utility can execute. | bool | `true` |
| terminationGracePeriodSeconds | Configure termination grace period for cilium-agent DaemonSet. | int | `1` |
| tls | Configure TLS configuration in the agent. | object | `{"ca":{"cert":"","certValidityDuration":1095,"key":""},"caBundle":{"enabled":false,"key":"ca.crt","name":"cilium-root-ca.crt","useSecret":false},"readSecretsOnlyFromSecretsNamespace":null,"secretSync":{"enabled":null},"secretsBackend":null,"secretsNamespace":{"create":true,"name":"cilium-secrets"}}` |
| tls.ca | Base64 encoded PEM values for the CA certificate and private key. This can be used as common CA to generate certificates used by hubble and clustermesh components. It is neither required nor used when cert-manager is used to generate the certificates. | object | `{"cert":"","certValidityDuration":1095,"key":""}` |
| tls.ca.cert | Optional CA cert. If it is provided, it will be used by cilium to generate all other certificates. Otherwise, an ephemeral CA is generated. | string | `""` |
| tls.ca.certValidityDuration | Generated certificates validity duration in days. This will be used for auto generated CA. | int | `1095` |
| tls.ca.key | Optional CA private key. If it is provided, it will be used by cilium to generate all other certificates. Otherwise, an ephemeral CA is generated. | string | `""` |
| tls.caBundle | Configure the CA trust bundle used for the validation of the certificates leveraged by hubble and clustermesh. When enabled, it overrides the content of the 'ca.crt' field of the respective certificates, allowing for CA rotation with no down-time. | object | `{"enabled":false,"key":"ca.crt","name":"cilium-root-ca.crt","useSecret":false}` |
| tls.caBundle.enabled | Enable the use of the CA trust bundle. | bool | `false` |
| tls.caBundle.key | Entry of the ConfigMap containing the CA trust bundle. | string | `"ca.crt"` |
| tls.caBundle.name | Name of the ConfigMap containing the CA trust bundle. | string | `"cilium-root-ca.crt"` |
| tls.caBundle.useSecret | Use a Secret instead of a ConfigMap. | bool | `false` |
| tls.readSecretsOnlyFromSecretsNamespace | Configure if the Cilium Agent will only look in `tls.secretsNamespace` for    CiliumNetworkPolicy relevant Secrets.    If false, the Cilium Agent will be granted READ (GET/LIST/WATCH) access    to _all_ secrets in the entire cluster. This is not recommended and is    included for backwards compatibility.    This value obsoletes `tls.secretsBackend`, with `true` == `local` in the old    setting, and `false` == `k8s`. | string | `nil` |
| tls.secretSync | Configures settings for synchronization of TLS Interception Secrets | object | `{"enabled":null}` |
| tls.secretSync.enabled | Enable synchronization of Secrets for TLS Interception. If disabled and tls.readSecretsOnlyFromSecretsNamespace is set to 'false', then secrets will be read directly by the agent. | string | `nil` |
| tls.secretsBackend | This configures how the Cilium agent loads the secrets used TLS-aware CiliumNetworkPolicies (namely the secrets referenced by terminatingTLS and originatingTLS). This value is DEPRECATED and will be removed in a future version. Use `tls.readSecretsOnlyFromSecretsNamespace` instead. Possible values:   - local   - k8s | string | `nil` |
| tls.secretsNamespace | Configures where secrets used in CiliumNetworkPolicies will be looked for | object | `{"create":true,"name":"cilium-secrets"}` |
| tls.secretsNamespace.create | Create secrets namespace for TLS Interception secrets. | bool | `true` |
| tls.secretsNamespace.name | Name of TLS Interception secret namespace. | string | `"cilium-secrets"` |
| tmpVolume | Configure temporary volume for cilium-agent | object | `{}` |
| tolerations | Node tolerations for agent scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/ | list | `[{"operator":"Exists"}]` |
| tunnelPort | Configure VXLAN and Geneve tunnel port. | int | Port 8472 for VXLAN, Port 6081 for Geneve |
| tunnelProtocol | Tunneling protocol to use in tunneling mode and for ad-hoc tunnels. Possible values:   - ""   - vxlan   - geneve | string | `"vxlan"` |
| tunnelSourcePortRange | Configure VXLAN and Geneve tunnel source port range hint. | string | 0-0 to let the kernel driver decide the range |
| underlayProtocol | IP family for the underlay. Possible values:   - "ipv4"   - "ipv6"   - "auto" | string | `"auto"` |
| updateStrategy | Cilium agent update strategy | object | `{"rollingUpdate":{"maxUnavailable":2},"type":"RollingUpdate"}` |
| upgradeCompatibility | upgradeCompatibility helps users upgrading to ensure that the configMap for Cilium will not change critical values to ensure continued operation This flag is not required for new installations. For example: '1.7', '1.8', '1.9' | string | `nil` |
| vtep.cidr | A space separated list of VTEP device CIDRs, for example "1.1.1.0/24 1.1.2.0/24" | string | `""` |
| vtep.enabled | Enables VXLAN Tunnel Endpoint (VTEP) Integration (beta) to allow Cilium-managed pods to talk to third party VTEP devices over Cilium tunnel. | bool | `false` |
| vtep.endpoint | A space separated list of VTEP device endpoint IPs, for example "1.1.1.1  1.1.2.1" | string | `""` |
| vtep.mac | A space separated list of VTEP device MAC addresses (VTEP MAC), for example "x:x:x:x:x:x  y:y:y:y:y:y:y" | string | `""` |
| vtep.mask | VTEP CIDRs Mask that applies to all VTEP CIDRs, for example "255.255.255.0" | string | `""` |
| waitForKubeProxy | Wait for KUBE-PROXY-CANARY iptables rule to appear in "wait-for-kube-proxy" init container before launching cilium-agent. More context can be found in the commit message of below PR https://github.com/cilium/cilium/pull/20123 | bool | `false` |
| wellKnownIdentities.enabled | Enable the use of well-known identities. | bool | `false` |
