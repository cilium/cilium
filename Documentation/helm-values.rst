..
  AUTO-GENERATED. Please DO NOT edit manually.

.. role:: raw-html-m2r(raw)
   :format: html


.. list-table::
   :header-rows: 1

   * - Key
     - Description
     - Type
     - Default
   * - MTU
     - Configure the underlying network MTU to overwrite auto-detected MTU.
     - int
     - ``0``
   * - affinity
     - Affinity for cilium-agent.
     - object
     - ``{"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"k8s-app":"cilium"}},"topologyKey":"kubernetes.io/hostname"}]}}``
   * - agent
     - Install the cilium agent resources.
     - bool
     - ``true``
   * - agentNotReadyTaintKey
     - Configure the key of the taint indicating that Cilium is not ready on the node. When set to a value starting with ``ignore-taint.cluster-autoscaler.kubernetes.io/``\ , the Cluster Autoscaler will ignore the taint on its decisions, allowing the cluster to scale up.
     - string
     - ``"node.cilium.io/agent-not-ready"``
   * - aksbyocni.enabled
     - Enable AKS BYOCNI integration. Note that this is incompatible with AKS clusters not created in BYOCNI mode: use Azure integration (\ ``azure.enabled``\ ) instead.
     - bool
     - ``false``
   * - alibabacloud.enabled
     - Enable AlibabaCloud ENI integration
     - bool
     - ``false``
   * - annotateK8sNode
     - Annotate k8s node upon initialization with Cilium's metadata.
     - bool
     - ``false``
   * - auth.mTLS.port
     - Port on the agent where mTLS handshakes between agents will be performed
     - int
     - ``4250``
   * - auth.mTLS.spire.adminSocketPath
     - SPIRE socket path where the SPIRE delegated api agent is listening
     - string
     - ``"/run/spire/sockets/admin.sock"``
   * - auth.mTLS.spire.agentSocketPath
     - SPIRE socket path where the SPIRE workload agent is listening. Applies to both the Cilium Agent and Operator
     - string
     - ``"/run/spire/sockets/agent/agent.sock"``
   * - auth.mTLS.spire.connectionTimeout
     - SPIRE connection timeout
     - string
     - ``"30s"``
   * - auth.mTLS.spire.enabled
     - Enable SPIRE integration
     - bool
     - ``false``
   * - auth.mTLS.spire.install
     - Settings to control the SPIRE installation and configuration
     - object
     - ``{"agent":{"annotations":{},"image":"ghcr.io/spiffe/spire-agent:1.6.3@sha256:8eef9857bf223181ecef10d9bbcd2f7838f3689e9bd2445bede35066a732e823","labels":{},"serviceAccount":{"create":true,"name":"spire-agent"},"skipKubeletVerification":true},"enabled":false,"namespace":"cilium-spire","server":{"annotations":{},"ca":{"keyType":"rsa-4096","subject":{"commonName":"Cilium SPIRE CA","country":"US","organization":"SPIRE"}},"dataStorage":{"accessMode":"ReadWriteOnce","enabled":true,"size":"1Gi","storageClass":null},"image":"ghcr.io/spiffe/spire-server:1.6.3@sha256:f4bc49fb0bd1d817a6c46204cc7ce943c73fb0a5496a78e0e4dc20c9a816ad7f","initContainers":[],"labels":{},"service":{"annotations":{},"labels":{},"type":"ClusterIP"},"serviceAccount":{"create":true,"name":"spire-server"}}}``
   * - auth.mTLS.spire.install.agent
     - SPIRE agent configuration
     - object
     - ``{"annotations":{},"image":"ghcr.io/spiffe/spire-agent:1.6.3@sha256:8eef9857bf223181ecef10d9bbcd2f7838f3689e9bd2445bede35066a732e823","labels":{},"serviceAccount":{"create":true,"name":"spire-agent"},"skipKubeletVerification":true}``
   * - auth.mTLS.spire.install.agent.annotations
     - SPIRE agent annotations
     - object
     - ``{}``
   * - auth.mTLS.spire.install.agent.image
     - SPIRE agent image
     - string
     - ``"ghcr.io/spiffe/spire-agent:1.6.3@sha256:8eef9857bf223181ecef10d9bbcd2f7838f3689e9bd2445bede35066a732e823"``
   * - auth.mTLS.spire.install.agent.labels
     - SPIRE agent labels
     - object
     - ``{}``
   * - auth.mTLS.spire.install.agent.serviceAccount
     - SPIRE agent service account
     - object
     - ``{"create":true,"name":"spire-agent"}``
   * - auth.mTLS.spire.install.agent.skipKubeletVerification
     - SPIRE Workload Attestor kubelet verification.
     - bool
     - ``true``
   * - auth.mTLS.spire.install.enabled
     - Enable SPIRE installation. This will only take effect only if auth.mTLS.spire.enabled is true
     - bool
     - ``false``
   * - auth.mTLS.spire.install.namespace
     - SPIRE namespace to install into
     - string
     - ``"cilium-spire"``
   * - auth.mTLS.spire.install.server.annotations
     - SPIRE server annotations
     - object
     - ``{}``
   * - auth.mTLS.spire.install.server.ca
     - SPIRE CA configuration
     - object
     - ``{"keyType":"rsa-4096","subject":{"commonName":"Cilium SPIRE CA","country":"US","organization":"SPIRE"}}``
   * - auth.mTLS.spire.install.server.ca.keyType
     - SPIRE CA key type AWS requires the use of RSA. EC cryptography is not supported
     - string
     - ``"rsa-4096"``
   * - auth.mTLS.spire.install.server.ca.subject
     - SPIRE CA Subject
     - object
     - ``{"commonName":"Cilium SPIRE CA","country":"US","organization":"SPIRE"}``
   * - auth.mTLS.spire.install.server.dataStorage
     - SPIRE server datastorage configuration
     - object
     - ``{"accessMode":"ReadWriteOnce","enabled":true,"size":"1Gi","storageClass":null}``
   * - auth.mTLS.spire.install.server.image
     - SPIRE server image
     - string
     - ``"ghcr.io/spiffe/spire-server:1.6.3@sha256:f4bc49fb0bd1d817a6c46204cc7ce943c73fb0a5496a78e0e4dc20c9a816ad7f"``
   * - auth.mTLS.spire.install.server.initContainers
     - SPIRE server init containers
     - list
     - ``[]``
   * - auth.mTLS.spire.install.server.labels
     - SPIRE server labels
     - object
     - ``{}``
   * - auth.mTLS.spire.install.server.service
     - SPIRE server service configuration
     - object
     - ``{"annotations":{},"labels":{},"type":"ClusterIP"}``
   * - auth.mTLS.spire.install.server.serviceAccount
     - SPIRE server service account
     - object
     - ``{"create":true,"name":"spire-server"}``
   * - auth.mTLS.spire.serverAddress
     - SPIRE server address
     - string
     - ``"spire-server.cilium-spire.svc:8081"``
   * - auth.mTLS.spire.trustDomain
     - SPIFFE trust domain to use for fetching certificates
     - string
     - ``"spiffe.cilium"``
   * - autoDirectNodeRoutes
     - Enable installation of PodCIDR routes between worker nodes if worker nodes share a common L2 network segment.
     - bool
     - ``false``
   * - azure.enabled
     - Enable Azure integration. Note that this is incompatible with AKS clusters created in BYOCNI mode: use AKS BYOCNI integration (\ ``aksbyocni.enabled``\ ) instead.
     - bool
     - ``false``
   * - bandwidthManager
     - Enable bandwidth manager to optimize TCP and UDP workloads and allow for rate-limiting traffic from individual Pods with EDT (Earliest Departure Time) through the "kubernetes.io/egress-bandwidth" Pod annotation.
     - object
     - ``{"bbr":false,"enabled":false}``
   * - bandwidthManager.bbr
     - Activate BBR TCP congestion control for Pods
     - bool
     - ``false``
   * - bandwidthManager.enabled
     - Enable bandwidth manager infrastructure (also prerequirement for BBR)
     - bool
     - ``false``
   * - bgp
     - Configure BGP
     - object
     - ``{"announce":{"loadbalancerIP":false,"podCIDR":false},"enabled":false}``
   * - bgp.announce.loadbalancerIP
     - Enable allocation and announcement of service LoadBalancer IPs
     - bool
     - ``false``
   * - bgp.announce.podCIDR
     - Enable announcement of node pod CIDR
     - bool
     - ``false``
   * - bgp.enabled
     - Enable BGP support inside Cilium; embeds a new ConfigMap for BGP inside cilium-agent and cilium-operator
     - bool
     - ``false``
   * - bgpControlPlane
     - This feature set enables virtual BGP routers to be created via CiliumBGPPeeringPolicy CRDs.
     - object
     - ``{"enabled":false}``
   * - bgpControlPlane.enabled
     - Enables the BGP control plane.
     - bool
     - ``false``
   * - bpf.authMapMax
     - Configure the maximum number of entries in auth map.
     - int
     - ``524288``
   * - bpf.autoMount.enabled
     - Enable automatic mount of BPF filesystem When ``autoMount`` is enabled, the BPF filesystem is mounted at ``bpf.root`` path on the underlying host and inside the cilium agent pod. If users disable ``autoMount``\ , it's expected that users have mounted bpffs filesystem at the specified ``bpf.root`` volume, and then the volume will be mounted inside the cilium agent pod at the same path.
     - bool
     - ``true``
   * - bpf.clockProbe
     - Enable BPF clock source probing for more efficient tick retrieval.
     - bool
     - ``false``
   * - bpf.ctAnyMax
     - Configure the maximum number of entries for the non-TCP connection tracking table.
     - int
     - ``262144``
   * - bpf.ctTcpMax
     - Configure the maximum number of entries in the TCP connection tracking table.
     - int
     - ``524288``
   * - bpf.hostLegacyRouting
     - Configure whether direct routing mode should route traffic via host stack (true) or directly and more efficiently out of BPF (false) if the kernel supports it. The latter has the implication that it will also bypass netfilter in the host namespace.
     - bool
     - ``false``
   * - bpf.lbExternalClusterIP
     - Allow cluster external access to ClusterIP services.
     - bool
     - ``false``
   * - bpf.lbMapMax
     - Configure the maximum number of service entries in the load balancer maps.
     - int
     - ``65536``
   * - bpf.mapDynamicSizeRatio
     - Configure auto-sizing for all BPF maps based on available memory. ref: https://docs.cilium.io/en/stable/network/ebpf/maps/
     - float64
     - ``0.0025``
   * - bpf.masquerade
     - Enable native IP masquerade support in eBPF
     - bool
     - ``false``
   * - bpf.monitorAggregation
     - Configure the level of aggregation for monitor notifications. Valid options are none, low, medium, maximum.
     - string
     - ``"medium"``
   * - bpf.monitorFlags
     - Configure which TCP flags trigger notifications when seen for the first time in a connection.
     - string
     - ``"all"``
   * - bpf.monitorInterval
     - Configure the typical time between monitor notifications for active connections.
     - string
     - ``"5s"``
   * - bpf.natMax
     - Configure the maximum number of entries for the NAT table.
     - int
     - ``524288``
   * - bpf.neighMax
     - Configure the maximum number of entries for the neighbor table.
     - int
     - ``524288``
   * - bpf.policyMapMax
     - Configure the maximum number of entries in endpoint policy map (per endpoint).
     - int
     - ``16384``
   * - bpf.preallocateMaps
     - Enables pre-allocation of eBPF map values. This increases memory usage but can reduce latency.
     - bool
     - ``false``
   * - bpf.root
     - Configure the mount point for the BPF filesystem
     - string
     - ``"/sys/fs/bpf"``
   * - bpf.tproxy
     - Configure the eBPF-based TPROXY to reduce reliance on iptables rules for implementing Layer 7 policy.
     - bool
     - ``false``
   * - bpf.vlanBypass
     - Configure explicitly allowed VLAN id's for bpf logic bypass. [0] will allow all VLAN id's without any filtering.
     - list
     - ``[]``
   * - certgen
     - Configure certificate generation for Hubble integration. If hubble.tls.auto.method=cronJob, these values are used for the Kubernetes CronJob which will be scheduled regularly to (re)generate any certificates not provided manually.
     - object
     - ``{"annotations":{"cronJob":{},"job":{}},"extraVolumeMounts":[],"extraVolumes":[],"image":{"digest":"sha256:4a456552a5f192992a6edcec2febb1c54870d665173a33dc7d876129b199ddbd","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/certgen","tag":"v0.1.8","useDigest":true},"podLabels":{},"tolerations":[],"ttlSecondsAfterFinished":1800}``
   * - certgen.annotations
     - Annotations to be added to the hubble-certgen initial Job and CronJob
     - object
     - ``{"cronJob":{},"job":{}}``
   * - certgen.extraVolumeMounts
     - Additional certgen volumeMounts.
     - list
     - ``[]``
   * - certgen.extraVolumes
     - Additional certgen volumes.
     - list
     - ``[]``
   * - certgen.podLabels
     - Labels to be added to hubble-certgen pods
     - object
     - ``{}``
   * - certgen.tolerations
     - Node tolerations for pod assignment on nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
     - list
     - ``[]``
   * - certgen.ttlSecondsAfterFinished
     - Seconds after which the completed job pod will be deleted
     - int
     - ``1800``
   * - cgroup
     - Configure cgroup related configuration
     - object
     - ``{"autoMount":{"enabled":true,"resources":{}},"hostRoot":"/run/cilium/cgroupv2"}``
   * - cgroup.autoMount.enabled
     - Enable auto mount of cgroup2 filesystem. When ``autoMount`` is enabled, cgroup2 filesystem is mounted at ``cgroup.hostRoot`` path on the underlying host and inside the cilium agent pod. If users disable ``autoMount``\ , it's expected that users have mounted cgroup2 filesystem at the specified ``cgroup.hostRoot`` volume, and then the volume will be mounted inside the cilium agent pod at the same path.
     - bool
     - ``true``
   * - cgroup.autoMount.resources
     - Init Container Cgroup Automount resource limits & requests
     - object
     - ``{}``
   * - cgroup.hostRoot
     - Configure cgroup root where cgroup2 filesystem is mounted on the host (see also: ``cgroup.autoMount``\ )
     - string
     - ``"/run/cilium/cgroupv2"``
   * - cleanBpfState
     - Clean all eBPF datapath state from the initContainer of the cilium-agent DaemonSet.  WARNING: Use with care!
     - bool
     - ``false``
   * - cleanState
     - Clean all local Cilium state from the initContainer of the cilium-agent DaemonSet. Implies cleanBpfState: true.  WARNING: Use with care!
     - bool
     - ``false``
   * - cluster.id
     - Unique ID of the cluster. Must be unique across all connected clusters and in the range of 1 to 255. Only required for Cluster Mesh, may be 0 if Cluster Mesh is not used.
     - int
     - ``0``
   * - cluster.name
     - Name of the cluster. Only required for Cluster Mesh and mTLS auth with SPIRE.
     - string
     - ``"default"``
   * - clustermesh.apiserver.affinity
     - Affinity for clustermesh.apiserver
     - object
     - ``{"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"k8s-app":"clustermesh-apiserver"}},"topologyKey":"kubernetes.io/hostname"}]}}``
   * - clustermesh.apiserver.etcd.image
     - Clustermesh API server etcd image.
     - object
     - ``{"digest":"sha256:795d8660c48c439a7c3764c2330ed9222ab5db5bb524d8d0607cac76f7ba82a3","override":null,"pullPolicy":"Always","repository":"quay.io/coreos/etcd","tag":"v3.5.4","useDigest":true}``
   * - clustermesh.apiserver.etcd.init.resources
     - Specifies the resources for etcd init container in the apiserver
     - object
     - ``{}``
   * - clustermesh.apiserver.etcd.resources
     - Specifies the resources for etcd container in the apiserver
     - object
     - ``{}``
   * - clustermesh.apiserver.etcd.securityContext
     - Security context to be added to clustermesh-apiserver etcd containers
     - object
     - ``{}``
   * - clustermesh.apiserver.extraEnv
     - Additional clustermesh-apiserver environment variables.
     - list
     - ``[]``
   * - clustermesh.apiserver.extraVolumeMounts
     - Additional clustermesh-apiserver volumeMounts.
     - list
     - ``[]``
   * - clustermesh.apiserver.extraVolumes
     - Additional clustermesh-apiserver volumes.
     - list
     - ``[]``
   * - clustermesh.apiserver.image
     - Clustermesh API server image.
     - object
     - ``{"digest":"","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/clustermesh-apiserver-ci","tag":"latest","useDigest":false}``
   * - clustermesh.apiserver.metrics.enabled
     - Enables exporting apiserver metrics in OpenMetrics format.
     - bool
     - ``false``
   * - clustermesh.apiserver.metrics.etcd.enabled
     - Enables exporting etcd metrics in OpenMetrics format.
     - bool
     - ``false``
   * - clustermesh.apiserver.metrics.etcd.mode
     - Set level of detail for etcd metrics; specify 'extensive' to include server side gRPC histogram metrics.
     - string
     - ``"basic"``
   * - clustermesh.apiserver.metrics.etcd.port
     - Configure the port the etcd metric server listens on.
     - int
     - ``9963``
   * - clustermesh.apiserver.metrics.port
     - Configure the port the apiserver metric server listens on.
     - int
     - ``9962``
   * - clustermesh.apiserver.metrics.serviceMonitor.annotations
     - Annotations to add to ServiceMonitor clustermesh-apiserver
     - object
     - ``{}``
   * - clustermesh.apiserver.metrics.serviceMonitor.enabled
     - Enable service monitor. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml)
     - bool
     - ``false``
   * - clustermesh.apiserver.metrics.serviceMonitor.etcd.interval
     - Interval for scrape metrics (etcd metrics)
     - string
     - ``"10s"``
   * - clustermesh.apiserver.metrics.serviceMonitor.etcd.metricRelabelings
     - Metrics relabeling configs for the ServiceMonitor clustermesh-apiserver (etcd metrics)
     - string
     - ``nil``
   * - clustermesh.apiserver.metrics.serviceMonitor.etcd.relabelings
     - Relabeling configs for the ServiceMonitor clustermesh-apiserver (etcd metrics)
     - string
     - ``nil``
   * - clustermesh.apiserver.metrics.serviceMonitor.interval
     - Interval for scrape metrics (apiserver metrics)
     - string
     - ``"10s"``
   * - clustermesh.apiserver.metrics.serviceMonitor.labels
     - Labels to add to ServiceMonitor clustermesh-apiserver
     - object
     - ``{}``
   * - clustermesh.apiserver.metrics.serviceMonitor.metricRelabelings
     - Metrics relabeling configs for the ServiceMonitor clustermesh-apiserver (apiserver metrics)
     - string
     - ``nil``
   * - clustermesh.apiserver.metrics.serviceMonitor.relabelings
     - Relabeling configs for the ServiceMonitor clustermesh-apiserver (apiserver metrics)
     - string
     - ``nil``
   * - clustermesh.apiserver.nodeSelector
     - Node labels for pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector
     - object
     - ``{"kubernetes.io/os":"linux"}``
   * - clustermesh.apiserver.podAnnotations
     - Annotations to be added to clustermesh-apiserver pods
     - object
     - ``{}``
   * - clustermesh.apiserver.podDisruptionBudget.enabled
     - enable PodDisruptionBudget ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/
     - bool
     - ``false``
   * - clustermesh.apiserver.podDisruptionBudget.maxUnavailable
     - Maximum number/percentage of pods that may be made unavailable
     - int
     - ``1``
   * - clustermesh.apiserver.podDisruptionBudget.minAvailable
     - Minimum number/percentage of pods that should remain scheduled. When it's set, maxUnavailable must be disabled by ``maxUnavailable: null``
     - string
     - ``nil``
   * - clustermesh.apiserver.podLabels
     - Labels to be added to clustermesh-apiserver pods
     - object
     - ``{}``
   * - clustermesh.apiserver.podSecurityContext
     - Security context to be added to clustermesh-apiserver pods
     - object
     - ``{}``
   * - clustermesh.apiserver.priorityClassName
     - The priority class to use for clustermesh-apiserver
     - string
     - ``""``
   * - clustermesh.apiserver.replicas
     - Number of replicas run for the clustermesh-apiserver deployment.
     - int
     - ``1``
   * - clustermesh.apiserver.resources
     - Resource requests and limits for the clustermesh-apiserver
     - object
     - ``{}``
   * - clustermesh.apiserver.securityContext
     - Security context to be added to clustermesh-apiserver containers
     - object
     - ``{}``
   * - clustermesh.apiserver.service.annotations
     - Annotations for the clustermesh-apiserver For GKE LoadBalancer, use annotation cloud.google.com/load-balancer-type: "Internal" For EKS LoadBalancer, use annotation service.beta.kubernetes.io/aws-load-balancer-internal: 0.0.0.0/0
     - object
     - ``{}``
   * - clustermesh.apiserver.service.externalTrafficPolicy
     - The externalTrafficPolicy of service used for apiserver access.
     - string
     - ``nil``
   * - clustermesh.apiserver.service.internalTrafficPolicy
     - The internalTrafficPolicy of service used for apiserver access.
     - string
     - ``nil``
   * - clustermesh.apiserver.service.nodePort
     - Optional port to use as the node port for apiserver access.  WARNING: make sure to configure a different NodePort in each cluster if kube-proxy replacement is enabled, as Cilium is currently affected by a known bug (#24692) when NodePorts are handled by the KPR implementation. If a service with the same NodePort exists both in the local and the remote cluster, all traffic originating from inside the cluster and targeting the corresponding NodePort will be redirected to a local backend, regardless of whether the destination node belongs to the local or the remote cluster.
     - int
     - ``32379``
   * - clustermesh.apiserver.service.type
     - The type of service used for apiserver access.
     - string
     - ``"NodePort"``
   * - clustermesh.apiserver.tls.admin
     - base64 encoded PEM values for the clustermesh-apiserver admin certificate and private key. Used if 'auto' is not enabled.
     - object
     - ``{"cert":"","key":""}``
   * - clustermesh.apiserver.tls.authMode
     - Configure the clustermesh authentication mode. Supported values: - legacy:     All clusters access remote clustermesh instances with the same               username (i.e., remote). The "remote" certificate must be               generated with CN=remote if provided manually. - migration:  Intermediate mode required to upgrade from legacy to cluster               (and vice versa) with no disruption. Specifically, it enables               the creation of the per-cluster usernames, while still using               the common one for authentication. The "remote" certificate must               be generated with CN=remote if provided manually (same as legacy). - cluster:    Each cluster accesses remote etcd instances with a username               depending on the local cluster name (i.e., remote-\ :raw-html-m2r:`<cluster-name>`\ ).               The "remote" certificate must be generated with CN=remote-\ :raw-html-m2r:`<cluster-name>`               if provided manually. Cluster mode is meaningful only when the same               CA is shared across all clusters part of the mesh.
     - string
     - ``"legacy"``
   * - clustermesh.apiserver.tls.auto
     - Configure automatic TLS certificates generation. A Kubernetes CronJob is used the generate any certificates not provided by the user at installation time.
     - object
     - ``{"certManagerIssuerRef":{},"certValidityDuration":1095,"enabled":true,"method":"helm"}``
   * - clustermesh.apiserver.tls.auto.certManagerIssuerRef
     - certmanager issuer used when clustermesh.apiserver.tls.auto.method=certmanager.
     - object
     - ``{}``
   * - clustermesh.apiserver.tls.auto.certValidityDuration
     - Generated certificates validity duration in days.
     - int
     - ``1095``
   * - clustermesh.apiserver.tls.auto.enabled
     - When set to true, automatically generate a CA and certificates to enable mTLS between clustermesh-apiserver and external workload instances. If set to false, the certs to be provided by setting appropriate values below.
     - bool
     - ``true``
   * - clustermesh.apiserver.tls.ca
     - Deprecated in favor of tls.ca. To be removed in 1.15. base64 encoded PEM values for the ExternalWorkload CA certificate and private key.
     - object
     - ``{"cert":"","key":""}``
   * - clustermesh.apiserver.tls.ca.cert
     - Deprecated in favor of tls.ca.cert. To be removed in 1.15. Optional CA cert. If it is provided, it will be used by the 'cronJob' method to generate all other certificates. Otherwise, an ephemeral CA is generated.
     - string
     - ``""``
   * - clustermesh.apiserver.tls.ca.key
     - Deprecated in favor of tls.ca.key. To be removed in 1.15. Optional CA private key. If it is provided, it will be used by the 'cronJob' method to generate all other certificates. Otherwise, an ephemeral CA is generated.
     - string
     - ``""``
   * - clustermesh.apiserver.tls.client
     - base64 encoded PEM values for the clustermesh-apiserver client certificate and private key. Used if 'auto' is not enabled.
     - object
     - ``{"cert":"","key":""}``
   * - clustermesh.apiserver.tls.remote
     - base64 encoded PEM values for the clustermesh-apiserver remote cluster certificate and private key. Used if 'auto' is not enabled.
     - object
     - ``{"cert":"","key":""}``
   * - clustermesh.apiserver.tls.server
     - base64 encoded PEM values for the clustermesh-apiserver server certificate and private key. Used if 'auto' is not enabled.
     - object
     - ``{"cert":"","extraDnsNames":[],"extraIpAddresses":[],"key":""}``
   * - clustermesh.apiserver.tls.server.extraDnsNames
     - Extra DNS names added to certificate when it's auto generated
     - list
     - ``[]``
   * - clustermesh.apiserver.tls.server.extraIpAddresses
     - Extra IP addresses added to certificate when it's auto generated
     - list
     - ``[]``
   * - clustermesh.apiserver.tolerations
     - Node tolerations for pod assignment on nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
     - list
     - ``[]``
   * - clustermesh.apiserver.topologySpreadConstraints
     - Pod topology spread constraints for clustermesh-apiserver
     - list
     - ``[]``
   * - clustermesh.apiserver.updateStrategy
     - clustermesh-apiserver update strategy
     - object
     - ``{"rollingUpdate":{"maxUnavailable":1},"type":"RollingUpdate"}``
   * - clustermesh.config
     - Clustermesh explicit configuration.
     - object
     - ``{"clusters":[],"domain":"mesh.cilium.io","enabled":false}``
   * - clustermesh.config.clusters
     - List of clusters to be peered in the mesh.
     - list
     - ``[]``
   * - clustermesh.config.domain
     - Default dns domain for the Clustermesh API servers This is used in the case cluster addresses are not provided and IPs are used.
     - string
     - ``"mesh.cilium.io"``
   * - clustermesh.config.enabled
     - Enable the Clustermesh explicit configuration.
     - bool
     - ``false``
   * - clustermesh.useAPIServer
     - Deploy clustermesh-apiserver for clustermesh
     - bool
     - ``false``
   * - cni.binPath
     - Configure the path to the CNI binary directory on the host.
     - string
     - ``"/opt/cni/bin"``
   * - cni.chainingMode
     - Configure chaining on top of other CNI plugins. Possible values:  - none  - aws-cni  - flannel  - generic-veth  - portmap
     - string
     - ``nil``
   * - cni.chainingTarget
     - A CNI network name in to which the Cilium plugin should be added as a chained plugin. This will cause the agent to watch for a CNI network with this network name. When it is found, this will be used as the basis for Cilium's CNI configuration file. If this is set, it assumes a chaining mode of generic-veth. As a special case, a chaining mode of aws-cni implies a chainingTarget of aws-cni.
     - string
     - ``nil``
   * - cni.confFileMountPath
     - Configure the path to where to mount the ConfigMap inside the agent pod.
     - string
     - ``"/tmp/cni-configuration"``
   * - cni.confPath
     - Configure the path to the CNI configuration directory on the host.
     - string
     - ``"/etc/cni/net.d"``
   * - cni.configMapKey
     - Configure the key in the CNI ConfigMap to read the contents of the CNI configuration from.
     - string
     - ``"cni-config"``
   * - cni.customConf
     - Skip writing of the CNI configuration. This can be used if writing of the CNI configuration is performed by external automation.
     - bool
     - ``false``
   * - cni.exclusive
     - Make Cilium take ownership over the ``/etc/cni/net.d`` directory on the node, renaming all non-Cilium CNI configurations to ``*.cilium_bak``. This ensures no Pods can be scheduled using other CNI plugins during Cilium agent downtime.
     - bool
     - ``true``
   * - cni.hostConfDirMountPath
     - Configure the path to where the CNI configuration directory is mounted inside the agent pod.
     - string
     - ``"/host/etc/cni/net.d"``
   * - cni.install
     - Install the CNI configuration and binary files into the filesystem.
     - bool
     - ``true``
   * - cni.logFile
     - Configure the log file for CNI logging with retention policy of 7 days. Disable CNI file logging by setting this field to empty explicitly.
     - string
     - ``"/var/run/cilium/cilium-cni.log"``
   * - cni.uninstall
     - Remove the CNI configuration and binary files on agent shutdown. Enable this if you're removing Cilium from the cluster. Disable this to prevent the CNI configuration file from being removed during agent upgrade, which can cause nodes to go unmanageable.
     - bool
     - ``false``
   * - conntrackGCInterval
     - Configure how frequently garbage collection should occur for the datapath connection tracking table.
     - string
     - ``"0s"``
   * - containerRuntime
     - Configure container runtime specific integration. Deprecated in favor of bpf.autoMount.enabled. To be removed in 1.15.
     - object
     - ``{"integration":"none"}``
   * - containerRuntime.integration
     - Enables specific integrations for container runtimes. Supported values: - crio - none
     - string
     - ``"none"``
   * - crdWaitTimeout
     - Configure timeout in which Cilium will exit if CRDs are not available
     - string
     - ``"5m"``
   * - customCalls
     - Tail call hooks for custom eBPF programs.
     - object
     - ``{"enabled":false}``
   * - customCalls.enabled
     - Enable tail call hooks for custom eBPF programs.
     - bool
     - ``false``
   * - daemon.allowedConfigOverrides
     - allowedConfigOverrides is a list of config-map keys that can be overridden. That is to say, if this value is set, config sources (excepting the first one) can only override keys in this list.  This takes precedence over blockedConfigOverrides.  By default, all keys may be overridden. To disable overrides, set this to "none" or change the configSources variable.
     - string
     - ``nil``
   * - daemon.blockedConfigOverrides
     - blockedConfigOverrides is a list of config-map keys that may not be overridden. In other words, if any of these keys appear in a configuration source excepting the first one, they will be ignored  This is ignored if allowedConfigOverrides is set.  By default, all keys may be overridden.
     - string
     - ``nil``
   * - daemon.configSources
     - Configure a custom list of possible configuration override sources The default is "config-map:cilium-config,cilium-node-config". For supported values, see the help text for the build-config subcommand. Note that this value should be a comma-separated string.
     - string
     - ``nil``
   * - daemon.runPath
     - Configure where Cilium runtime state should be stored.
     - string
     - ``"/var/run/cilium"``
   * - dashboards
     - Grafana dashboards for cilium-agent grafana can import dashboards based on the label and value ref: https://github.com/grafana/helm-charts/tree/main/charts/grafana#sidecar-for-dashboards
     - object
     - ``{"annotations":{},"enabled":false,"label":"grafana_dashboard","labelValue":"1","namespace":null}``
   * - debug.enabled
     - Enable debug logging
     - bool
     - ``false``
   * - debug.verbose
     - Configure verbosity levels for debug logging This option is used to enable debug messages for operations related to such sub-system such as (e.g. kvstore, envoy, datapath or policy), and flow is for enabling debug messages emitted per request, message and connection.  Applicable values: - flow - kvstore - envoy - datapath - policy
     - string
     - ``nil``
   * - disableEndpointCRD
     - Disable the usage of CiliumEndpoint CRD.
     - string
     - ``"false"``
   * - dnsPolicy
     - DNS policy for Cilium agent pods. Ref: https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pod-s-dns-policy
     - string
     - ``""``
   * - dnsProxy.dnsRejectResponseCode
     - DNS response code for rejecting DNS requests, available options are '[nameError refused]'.
     - string
     - ``"refused"``
   * - dnsProxy.enableDnsCompression
     - Allow the DNS proxy to compress responses to endpoints that are larger than 512 Bytes or the EDNS0 option, if present.
     - bool
     - ``true``
   * - dnsProxy.endpointMaxIpPerHostname
     - Maximum number of IPs to maintain per FQDN name for each endpoint.
     - int
     - ``50``
   * - dnsProxy.idleConnectionGracePeriod
     - Time during which idle but previously active connections with expired DNS lookups are still considered alive.
     - string
     - ``"0s"``
   * - dnsProxy.maxDeferredConnectionDeletes
     - Maximum number of IPs to retain for expired DNS lookups with still-active connections.
     - int
     - ``10000``
   * - dnsProxy.minTtl
     - The minimum time, in seconds, to use DNS data for toFQDNs policies. If the upstream DNS server returns a DNS record with a shorter TTL, Cilium overwrites the TTL with this value. Setting this value to zero means that Cilium will honor the TTLs returned by the upstream DNS server.
     - int
     - ``0``
   * - dnsProxy.preCache
     - DNS cache data at this path is preloaded on agent startup.
     - string
     - ``""``
   * - dnsProxy.proxyPort
     - Global port on which the in-agent DNS proxy should listen. Default 0 is a OS-assigned port.
     - int
     - ``0``
   * - dnsProxy.proxyResponseMaxDelay
     - The maximum time the DNS proxy holds an allowed DNS response before sending it along. Responses are sent as soon as the datapath is updated with the new IP information.
     - string
     - ``"100ms"``
   * - egressGateway
     - Enables egress gateway to redirect and SNAT the traffic that leaves the cluster.
     - object
     - ``{"enabled":false,"installRoutes":false}``
   * - egressGateway.installRoutes
     - Install egress gateway IP rules and routes in order to properly steer egress gateway traffic to the correct ENI interface
     - bool
     - ``false``
   * - enableCiliumEndpointSlice
     - Enable CiliumEndpointSlice feature.
     - bool
     - ``false``
   * - enableCnpStatusUpdates
     - Whether to enable CNP status updates.
     - bool
     - ``false``
   * - enableCriticalPriorityClass
     - Explicitly enable or disable priority class. .Capabilities.KubeVersion is unsettable in ``helm template`` calls, it depends on k8s libraries version that Helm was compiled against. This option allows to explicitly disable setting the priority class, which is useful for rendering charts for gke clusters in advance.
     - bool
     - ``true``
   * - enableIPv4Masquerade
     - Enables masquerading of IPv4 traffic leaving the node from endpoints.
     - bool
     - ``true``
   * - enableIPv6BIGTCP
     - Enables IPv6 BIG TCP support which increases maximum GSO/GRO limits for nodes and pods
     - bool
     - ``false``
   * - enableIPv6Masquerade
     - Enables masquerading of IPv6 traffic leaving the node from endpoints.
     - bool
     - ``true``
   * - enableK8sEventHandover
     - Configures the use of the KVStore to optimize Kubernetes event handling by mirroring it into the KVstore for reduced overhead in large clusters.
     - bool
     - ``false``
   * - enableK8sTerminatingEndpoint
     - Configure whether to enable auto detect of terminating state for endpoints in order to support graceful termination.
     - bool
     - ``true``
   * - enableRuntimeDeviceDetection
     - Enables experimental support for the detection of new and removed datapath devices. When devices change the eBPF datapath is reloaded and services updated. If "devices" is set then only those devices, or devices matching a wildcard will be considered.
     - bool
     - ``false``
   * - enableXTSocketFallback
     - Enables the fallback compatibility solution for when the xt_socket kernel module is missing and it is needed for the datapath L7 redirection to work properly. See documentation for details on when this can be disabled: https://docs.cilium.io/en/stable/operations/system_requirements/#linux-kernel.
     - bool
     - ``true``
   * - encryption.enabled
     - Enable transparent network encryption.
     - bool
     - ``false``
   * - encryption.interface
     - Deprecated in favor of encryption.ipsec.interface. To be removed in 1.15. The interface to use for encrypted traffic. This option is only effective when encryption.type is set to ipsec.
     - string
     - ``""``
   * - encryption.ipsec.interface
     - The interface to use for encrypted traffic.
     - string
     - ``""``
   * - encryption.ipsec.keyFile
     - Name of the key file inside the Kubernetes secret configured via secretName.
     - string
     - ``""``
   * - encryption.ipsec.mountPath
     - Path to mount the secret inside the Cilium pod.
     - string
     - ``""``
   * - encryption.ipsec.secretName
     - Name of the Kubernetes secret containing the encryption keys.
     - string
     - ``""``
   * - encryption.keyFile
     - Deprecated in favor of encryption.ipsec.keyFile. To be removed in 1.15. Name of the key file inside the Kubernetes secret configured via secretName. This option is only effective when encryption.type is set to ipsec.
     - string
     - ``"keys"``
   * - encryption.mountPath
     - Deprecated in favor of encryption.ipsec.mountPath. To be removed in 1.15. Path to mount the secret inside the Cilium pod. This option is only effective when encryption.type is set to ipsec.
     - string
     - ``"/etc/ipsec"``
   * - encryption.nodeEncryption
     - Enable encryption for pure node to node traffic. This option is only effective when encryption.type is set to "wireguard".
     - bool
     - ``false``
   * - encryption.secretName
     - Deprecated in favor of encryption.ipsec.secretName. To be removed in 1.15. Name of the Kubernetes secret containing the encryption keys. This option is only effective when encryption.type is set to ipsec.
     - string
     - ``"cilium-ipsec-keys"``
   * - encryption.type
     - Encryption method. Can be either ipsec or wireguard.
     - string
     - ``"ipsec"``
   * - encryption.wireguard.userspaceFallback
     - Enables the fallback to the user-space implementation.
     - bool
     - ``false``
   * - endpointHealthChecking.enabled
     - Enable connectivity health checking between virtual endpoints.
     - bool
     - ``true``
   * - endpointRoutes.enabled
     - Enable use of per endpoint routes instead of routing via the cilium_host interface.
     - bool
     - ``false``
   * - endpointStatus
     - Enable endpoint status. Status can be: policy, health, controllers, log and / or state. For 2 or more options use a space.
     - object
     - ``{"enabled":false,"status":""}``
   * - eni.awsEnablePrefixDelegation
     - Enable ENI prefix delegation
     - bool
     - ``false``
   * - eni.awsReleaseExcessIPs
     - Release IPs not used from the ENI
     - bool
     - ``false``
   * - eni.ec2APIEndpoint
     - EC2 API endpoint to use
     - string
     - ``""``
   * - eni.enabled
     - Enable Elastic Network Interface (ENI) integration.
     - bool
     - ``false``
   * - eni.eniTags
     - Tags to apply to the newly created ENIs
     - object
     - ``{}``
   * - eni.gcInterval
     - Interval for garbage collection of unattached ENIs. Set to "0s" to disable.
     - string
     - ``"5m"``
   * - eni.gcTags
     - Additional tags attached to ENIs created by Cilium. Dangling ENIs with this tag will be garbage collected
     - object
     - ``{"io.cilium/cilium-managed":"true,"io.cilium/cluster-name":"<auto-detected>"}``
   * - eni.iamRole
     - If using IAM role for Service Accounts will not try to inject identity values from cilium-aws kubernetes secret. Adds annotation to service account if managed by Helm. See https://github.com/aws/amazon-eks-pod-identity-webhook
     - string
     - ``""``
   * - eni.instanceTagsFilter
     - Filter via AWS EC2 Instance tags (k=v) which will dictate which AWS EC2 Instances are going to be used to create new ENIs
     - list
     - ``[]``
   * - eni.subnetIDsFilter
     - Filter via subnet IDs which will dictate which subnets are going to be used to create new ENIs Important note: This requires that each instance has an ENI with a matching subnet attached when Cilium is deployed. If you only want to control subnets for ENIs attached by Cilium, use the CNI configuration file settings (cni.customConf) instead.
     - list
     - ``[]``
   * - eni.subnetTagsFilter
     - Filter via tags (k=v) which will dictate which subnets are going to be used to create new ENIs Important note: This requires that each instance has an ENI with a matching subnet attached when Cilium is deployed. If you only want to control subnets for ENIs attached by Cilium, use the CNI configuration file settings (cni.customConf) instead.
     - list
     - ``[]``
   * - eni.updateEC2AdapterLimitViaAPI
     - Update ENI Adapter limits from the EC2 API
     - bool
     - ``true``
   * - envoy
     - Configure Cilium Envoy options.
     - object
     - ``{"affinity":{"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"k8s-app":"cilium-envoy"}},"topologyKey":"kubernetes.io/hostname"}]}},"connectTimeoutSeconds":2,"dnsPolicy":null,"enabled":false,"extraArgs":[],"extraContainers":[],"extraEnv":[],"extraHostPathMounts":[],"extraVolumeMounts":[],"extraVolumes":[],"healthPort":9878,"idleTimeoutDurationSeconds":60,"image":{"digest":"sha256:5d03695af25448768062fa42bffec7dbaa970f0d2b320d39e60b0a12f45027e8","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/cilium-envoy","tag":"v1.25.6-4350471813b173839df78f7a1ea5d77b5cdf714b","useDigest":true},"livenessProbe":{"failureThreshold":10,"periodSeconds":30},"log":{"format":"[%Y-%m-%d %T.%e][%t][%l][%n] [%g:%#] %v","path":""},"maxConnectionDurationSeconds":0,"maxRequestsPerConnection":0,"nodeSelector":{"kubernetes.io/os":"linux"},"podAnnotations":{},"podLabels":{},"podSecurityContext":{},"priorityClassName":null,"prometheus":{"enabled":true,"port":"9964","serviceMonitor":{"annotations":{},"enabled":false,"interval":"10s","labels":{},"metricRelabelings":null,"relabelings":[{"replacement":"${1}","sourceLabels":["__meta_kubernetes_pod_node_name"],"targetLabel":"node"}]}},"readinessProbe":{"failureThreshold":3,"periodSeconds":30},"resources":{},"rollOutPods":false,"securityContext":{"capabilities":{"envoy":["NET_ADMIN","SYS_ADMIN"]},"privileged":false,"seLinuxOptions":{"level":"s0","type":"spc_t"}},"startupProbe":{"failureThreshold":105,"periodSeconds":2},"terminationGracePeriodSeconds":1,"tolerations":[{"operator":"Exists"}],"updateStrategy":{"rollingUpdate":{"maxUnavailable":2},"type":"RollingUpdate"}}``
   * - envoy.affinity
     - Affinity for cilium-envoy.
     - object
     - ``{"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"k8s-app":"cilium-envoy"}},"topologyKey":"kubernetes.io/hostname"}]}}``
   * - envoy.dnsPolicy
     - DNS policy for Cilium envoy pods. Ref: https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pod-s-dns-policy
     - string
     - ``nil``
   * - envoy.extraArgs
     - Additional envoy container arguments.
     - list
     - ``[]``
   * - envoy.extraContainers
     - Additional containers added to the cilium Envoy DaemonSet.
     - list
     - ``[]``
   * - envoy.extraEnv
     - Additional envoy container environment variables.
     - list
     - ``[]``
   * - envoy.extraHostPathMounts
     - Additional envoy hostPath mounts.
     - list
     - ``[]``
   * - envoy.extraVolumeMounts
     - Additional envoy volumeMounts.
     - list
     - ``[]``
   * - envoy.extraVolumes
     - Additional envoy volumes.
     - list
     - ``[]``
   * - envoy.healthPort
     - TCP port for the health API.
     - int
     - ``9878``
   * - envoy.image
     - Envoy container image.
     - object
     - ``{"digest":"sha256:5d03695af25448768062fa42bffec7dbaa970f0d2b320d39e60b0a12f45027e8","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/cilium-envoy","tag":"v1.25.6-4350471813b173839df78f7a1ea5d77b5cdf714b","useDigest":true}``
   * - envoy.livenessProbe.failureThreshold
     - failure threshold of liveness probe
     - int
     - ``10``
   * - envoy.livenessProbe.periodSeconds
     - interval between checks of the liveness probe
     - int
     - ``30``
   * - envoy.nodeSelector
     - Node selector for cilium-envoy.
     - object
     - ``{"kubernetes.io/os":"linux"}``
   * - envoy.podAnnotations
     - Annotations to be added to envoy pods
     - object
     - ``{}``
   * - envoy.podLabels
     - Labels to be added to envoy pods
     - object
     - ``{}``
   * - envoy.podSecurityContext
     - Security Context for cilium-envoy pods.
     - object
     - ``{}``
   * - envoy.priorityClassName
     - The priority class to use for cilium-envoy.
     - string
     - ``nil``
   * - envoy.prometheus.serviceMonitor.annotations
     - Annotations to add to ServiceMonitor cilium-envoy
     - object
     - ``{}``
   * - envoy.prometheus.serviceMonitor.enabled
     - Enable service monitors. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml)
     - bool
     - ``false``
   * - envoy.prometheus.serviceMonitor.interval
     - Interval for scrape metrics.
     - string
     - ``"10s"``
   * - envoy.prometheus.serviceMonitor.labels
     - Labels to add to ServiceMonitor cilium-envoy
     - object
     - ``{}``
   * - envoy.prometheus.serviceMonitor.metricRelabelings
     - Metrics relabeling configs for the ServiceMonitor cilium-envoy
     - string
     - ``nil``
   * - envoy.prometheus.serviceMonitor.relabelings
     - Relabeling configs for the ServiceMonitor cilium-envoy
     - list
     - ``[{"replacement":"${1}","sourceLabels":["__meta_kubernetes_pod_node_name"],"targetLabel":"node"}]``
   * - envoy.readinessProbe.failureThreshold
     - failure threshold of readiness probe
     - int
     - ``3``
   * - envoy.readinessProbe.periodSeconds
     - interval between checks of the readiness probe
     - int
     - ``30``
   * - envoy.resources
     - Envoy resource limits & requests ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
     - object
     - ``{}``
   * - envoy.rollOutPods
     - Roll out cilium envoy pods automatically when configmap is updated.
     - bool
     - ``false``
   * - envoy.securityContext.capabilities.envoy
     - Capabilities for the ``cilium-envoy`` container
     - list
     - ``["NET_ADMIN","SYS_ADMIN"]``
   * - envoy.securityContext.privileged
     - Run the pod with elevated privileges
     - bool
     - ``false``
   * - envoy.securityContext.seLinuxOptions
     - SELinux options for the ``cilium-envoy`` container
     - object
     - ``{"level":"s0","type":"spc_t"}``
   * - envoy.startupProbe.failureThreshold
     - failure threshold of startup probe. 105 x 2s translates to the old behaviour of the readiness probe (120s delay + 30 x 3s)
     - int
     - ``105``
   * - envoy.startupProbe.periodSeconds
     - interval between checks of the startup probe
     - int
     - ``2``
   * - envoy.terminationGracePeriodSeconds
     - Configure termination grace period for cilium-envoy DaemonSet.
     - int
     - ``1``
   * - envoy.tolerations
     - Node tolerations for envoy scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
     - list
     - ``[{"operator":"Exists"}]``
   * - etcd.clusterDomain
     - Cluster domain for cilium-etcd-operator.
     - string
     - ``"cluster.local"``
   * - etcd.enabled
     - Enable etcd mode for the agent.
     - bool
     - ``false``
   * - etcd.endpoints
     - List of etcd endpoints (not needed when using managed=true).
     - list
     - ``["https://CHANGE-ME:2379"]``
   * - etcd.extraArgs
     - Additional cilium-etcd-operator container arguments.
     - list
     - ``[]``
   * - etcd.extraVolumeMounts
     - Additional cilium-etcd-operator volumeMounts.
     - list
     - ``[]``
   * - etcd.extraVolumes
     - Additional cilium-etcd-operator volumes.
     - list
     - ``[]``
   * - etcd.image
     - cilium-etcd-operator image.
     - object
     - ``{"digest":"sha256:04b8327f7f992693c2cb483b999041ed8f92efc8e14f2a5f3ab95574a65ea2dc","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/cilium-etcd-operator","tag":"v2.0.7","useDigest":true}``
   * - etcd.k8sService
     - If etcd is behind a k8s service set this option to true so that Cilium does the service translation automatically without requiring a DNS to be running.
     - bool
     - ``false``
   * - etcd.nodeSelector
     - Node labels for cilium-etcd-operator pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector
     - object
     - ``{"kubernetes.io/os":"linux"}``
   * - etcd.podAnnotations
     - Annotations to be added to cilium-etcd-operator pods
     - object
     - ``{}``
   * - etcd.podDisruptionBudget.enabled
     - enable PodDisruptionBudget ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/
     - bool
     - ``false``
   * - etcd.podDisruptionBudget.maxUnavailable
     - Maximum number/percentage of pods that may be made unavailable
     - int
     - ``1``
   * - etcd.podDisruptionBudget.minAvailable
     - Minimum number/percentage of pods that should remain scheduled. When it's set, maxUnavailable must be disabled by ``maxUnavailable: null``
     - string
     - ``nil``
   * - etcd.podLabels
     - Labels to be added to cilium-etcd-operator pods
     - object
     - ``{}``
   * - etcd.podSecurityContext
     - Security context to be added to cilium-etcd-operator pods
     - object
     - ``{}``
   * - etcd.priorityClassName
     - The priority class to use for cilium-etcd-operator
     - string
     - ``""``
   * - etcd.resources
     - cilium-etcd-operator resource limits & requests ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
     - object
     - ``{}``
   * - etcd.securityContext
     - Security context to be added to cilium-etcd-operator pods
     - object
     - ``{}``
   * - etcd.ssl
     - Enable use of TLS/SSL for connectivity to etcd. (auto-enabled if managed=true)
     - bool
     - ``false``
   * - etcd.tolerations
     - Node tolerations for cilium-etcd-operator scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
     - list
     - ``[{"operator":"Exists"}]``
   * - etcd.topologySpreadConstraints
     - Pod topology spread constraints for cilium-etcd-operator
     - list
     - ``[]``
   * - etcd.updateStrategy
     - cilium-etcd-operator update strategy
     - object
     - ``{"rollingUpdate":{"maxSurge":1,"maxUnavailable":1},"type":"RollingUpdate"}``
   * - externalIPs.enabled
     - Enable ExternalIPs service support.
     - bool
     - ``false``
   * - externalWorkloads
     - Configure external workloads support
     - object
     - ``{"enabled":false}``
   * - externalWorkloads.enabled
     - Enable support for external workloads, such as VMs (false by default).
     - bool
     - ``false``
   * - extraArgs
     - Additional agent container arguments.
     - list
     - ``[]``
   * - extraConfig
     - extraConfig allows you to specify additional configuration parameters to be included in the cilium-config configmap.
     - object
     - ``{}``
   * - extraContainers
     - Additional containers added to the cilium DaemonSet.
     - list
     - ``[]``
   * - extraEnv
     - Additional agent container environment variables.
     - list
     - ``[]``
   * - extraHostPathMounts
     - Additional agent hostPath mounts.
     - list
     - ``[]``
   * - extraVolumeMounts
     - Additional agent volumeMounts.
     - list
     - ``[]``
   * - extraVolumes
     - Additional agent volumes.
     - list
     - ``[]``
   * - gatewayAPI.enabled
     - Enable support for Gateway API in cilium This will automatically set enable-envoy-config as well.
     - bool
     - ``false``
   * - gatewayAPI.secretsNamespace
     - SecretsNamespace is the namespace in which envoy SDS will retrieve TLS secrets from.
     - object
     - ``{"create":true,"name":"cilium-secrets","sync":true}``
   * - gatewayAPI.secretsNamespace.create
     - Create secrets namespace for Gateway API.
     - bool
     - ``true``
   * - gatewayAPI.secretsNamespace.name
     - Name of Gateway API secret namespace.
     - string
     - ``"cilium-secrets"``
   * - gatewayAPI.secretsNamespace.sync
     - Enable secret sync, which will make sure all TLS secrets used by Ingress are synced to secretsNamespace.name. If disabled, TLS secrets must be maintained externally.
     - bool
     - ``true``
   * - gke.enabled
     - Enable Google Kubernetes Engine integration
     - bool
     - ``false``
   * - healthChecking
     - Enable connectivity health checking.
     - bool
     - ``true``
   * - healthPort
     - TCP port for the agent health API. This is not the port for cilium-health.
     - int
     - ``9879``
   * - highScaleIPcache
     - EnableHighScaleIPcache enables the special ipcache mode for high scale clusters. The ipcache content will be reduced to the strict minimum and traffic will be encapsulated to carry security identities.
     - object
     - ``{"enabled":false}``
   * - highScaleIPcache.enabled
     - Enable the high scale mode for the ipcache.
     - bool
     - ``false``
   * - hostFirewall
     - Configure the host firewall.
     - object
     - ``{"enabled":false}``
   * - hostFirewall.enabled
     - Enables the enforcement of host policies in the eBPF datapath.
     - bool
     - ``false``
   * - hostPort.enabled
     - Enable hostPort service support.
     - bool
     - ``false``
   * - hubble.enabled
     - Enable Hubble (true by default).
     - bool
     - ``true``
   * - hubble.listenAddress
     - An additional address for Hubble to listen to. Set this field ":4244" if you are enabling Hubble Relay, as it assumes that Hubble is listening on port 4244.
     - string
     - ``":4244"``
   * - hubble.metrics
     - Hubble metrics configuration. See https://docs.cilium.io/en/stable/observability/metrics/#hubble-metrics for more comprehensive documentation about Hubble metrics.
     - object
     - ``{"dashboards":{"annotations":{},"enabled":false,"label":"grafana_dashboard","labelValue":"1","namespace":null},"enableOpenMetrics":false,"enabled":null,"port":9965,"serviceAnnotations":{},"serviceMonitor":{"annotations":{},"enabled":false,"interval":"10s","labels":{},"metricRelabelings":null,"relabelings":[{"replacement":"${1}","sourceLabels":["__meta_kubernetes_pod_node_name"],"targetLabel":"node"}]}}``
   * - hubble.metrics.dashboards
     - Grafana dashboards for hubble grafana can import dashboards based on the label and value ref: https://github.com/grafana/helm-charts/tree/main/charts/grafana#sidecar-for-dashboards
     - object
     - ``{"annotations":{},"enabled":false,"label":"grafana_dashboard","labelValue":"1","namespace":null}``
   * - hubble.metrics.enableOpenMetrics
     - Enables exporting hubble metrics in OpenMetrics format.
     - bool
     - ``false``
   * - hubble.metrics.enabled
     - Configures the list of metrics to collect. If empty or null, metrics are disabled. Example:    enabled:   - dns:query;ignoreAAAA   - drop   - tcp   - flow   - icmp   - http  You can specify the list of metrics from the helm CLI:    --set metrics.enabled="{dns:query;ignoreAAAA,drop,tcp,flow,icmp,http}"
     - string
     - ``nil``
   * - hubble.metrics.port
     - Configure the port the hubble metric server listens on.
     - int
     - ``9965``
   * - hubble.metrics.serviceAnnotations
     - Annotations to be added to hubble-metrics service.
     - object
     - ``{}``
   * - hubble.metrics.serviceMonitor.annotations
     - Annotations to add to ServiceMonitor hubble
     - object
     - ``{}``
   * - hubble.metrics.serviceMonitor.enabled
     - Create ServiceMonitor resources for Prometheus Operator. This requires the prometheus CRDs to be available. ref: https://github.com/prometheus-operator/prometheus-operator/blob/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml)
     - bool
     - ``false``
   * - hubble.metrics.serviceMonitor.interval
     - Interval for scrape metrics.
     - string
     - ``"10s"``
   * - hubble.metrics.serviceMonitor.labels
     - Labels to add to ServiceMonitor hubble
     - object
     - ``{}``
   * - hubble.metrics.serviceMonitor.metricRelabelings
     - Metrics relabeling configs for the ServiceMonitor hubble
     - string
     - ``nil``
   * - hubble.metrics.serviceMonitor.relabelings
     - Relabeling configs for the ServiceMonitor hubble
     - list
     - ``[{"replacement":"${1}","sourceLabels":["__meta_kubernetes_pod_node_name"],"targetLabel":"node"}]``
   * - hubble.peerService.clusterDomain
     - The cluster domain to use to query the Hubble Peer service. It should be the local cluster.
     - string
     - ``"cluster.local"``
   * - hubble.peerService.targetPort
     - Target Port for the Peer service, must match the hubble.listenAddress' port.
     - int
     - ``4244``
   * - hubble.preferIpv6
     - Whether Hubble should prefer to announce IPv6 or IPv4 addresses if both are available.
     - bool
     - ``false``
   * - hubble.relay.affinity
     - Affinity for hubble-replay
     - object
     - ``{"podAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"k8s-app":"cilium"}},"topologyKey":"kubernetes.io/hostname"}]}}``
   * - hubble.relay.dialTimeout
     - Dial timeout to connect to the local hubble instance to receive peer information (e.g. "30s").
     - string
     - ``nil``
   * - hubble.relay.enabled
     - Enable Hubble Relay (requires hubble.enabled=true)
     - bool
     - ``false``
   * - hubble.relay.extraEnv
     - Additional hubble-relay environment variables.
     - list
     - ``[]``
   * - hubble.relay.gops.enabled
     - Enable gops for hubble-relay
     - bool
     - ``true``
   * - hubble.relay.gops.port
     - Configure gops listen port for hubble-relay
     - int
     - ``9893``
   * - hubble.relay.image
     - Hubble-relay container image.
     - object
     - ``{"digest":"","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/hubble-relay-ci","tag":"latest","useDigest":false}``
   * - hubble.relay.listenHost
     - Host to listen to. Specify an empty string to bind to all the interfaces.
     - string
     - ``""``
   * - hubble.relay.listenPort
     - Port to listen to.
     - string
     - ``"4245"``
   * - hubble.relay.nodeSelector
     - Node labels for pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector
     - object
     - ``{"kubernetes.io/os":"linux"}``
   * - hubble.relay.podAnnotations
     - Annotations to be added to hubble-relay pods
     - object
     - ``{}``
   * - hubble.relay.podDisruptionBudget.enabled
     - enable PodDisruptionBudget ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/
     - bool
     - ``false``
   * - hubble.relay.podDisruptionBudget.maxUnavailable
     - Maximum number/percentage of pods that may be made unavailable
     - int
     - ``1``
   * - hubble.relay.podDisruptionBudget.minAvailable
     - Minimum number/percentage of pods that should remain scheduled. When it's set, maxUnavailable must be disabled by ``maxUnavailable: null``
     - string
     - ``nil``
   * - hubble.relay.podLabels
     - Labels to be added to hubble-relay pods
     - object
     - ``{}``
   * - hubble.relay.podSecurityContext
     - hubble-relay pod security context
     - object
     - ``{"fsGroup":65532}``
   * - hubble.relay.pprof.address
     - Configure pprof listen address for hubble-relay
     - string
     - ``"localhost"``
   * - hubble.relay.pprof.enabled
     - Enable pprof for hubble-relay
     - bool
     - ``false``
   * - hubble.relay.pprof.port
     - Configure pprof listen port for hubble-relay
     - int
     - ``6062``
   * - hubble.relay.priorityClassName
     - The priority class to use for hubble-relay
     - string
     - ``""``
   * - hubble.relay.prometheus
     - Enable prometheus metrics for hubble-relay on the configured port at /metrics
     - object
     - ``{"enabled":false,"port":9966,"serviceMonitor":{"annotations":{},"enabled":false,"interval":"10s","labels":{},"metricRelabelings":null,"relabelings":null}}``
   * - hubble.relay.prometheus.serviceMonitor.annotations
     - Annotations to add to ServiceMonitor hubble-relay
     - object
     - ``{}``
   * - hubble.relay.prometheus.serviceMonitor.enabled
     - Enable service monitors. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml)
     - bool
     - ``false``
   * - hubble.relay.prometheus.serviceMonitor.interval
     - Interval for scrape metrics.
     - string
     - ``"10s"``
   * - hubble.relay.prometheus.serviceMonitor.labels
     - Labels to add to ServiceMonitor hubble-relay
     - object
     - ``{}``
   * - hubble.relay.prometheus.serviceMonitor.metricRelabelings
     - Metrics relabeling configs for the ServiceMonitor hubble-relay
     - string
     - ``nil``
   * - hubble.relay.prometheus.serviceMonitor.relabelings
     - Relabeling configs for the ServiceMonitor hubble-relay
     - string
     - ``nil``
   * - hubble.relay.replicas
     - Number of replicas run for the hubble-relay deployment.
     - int
     - ``1``
   * - hubble.relay.resources
     - Specifies the resources for the hubble-relay pods
     - object
     - ``{}``
   * - hubble.relay.retryTimeout
     - Backoff duration to retry connecting to the local hubble instance in case of failure (e.g. "30s").
     - string
     - ``nil``
   * - hubble.relay.rollOutPods
     - Roll out Hubble Relay pods automatically when configmap is updated.
     - bool
     - ``false``
   * - hubble.relay.securityContext
     - hubble-relay container security context
     - object
     - ``{"capabilities":{"drop":["ALL"]},"runAsGroup":65532,"runAsNonRoot":true,"runAsUser":65532}``
   * - hubble.relay.service
     - hubble-relay service configuration.
     - object
     - ``{"nodePort":31234,"type":"ClusterIP"}``
   * - hubble.relay.service.nodePort
     - - The port to use when the service type is set to NodePort.
     - int
     - ``31234``
   * - hubble.relay.service.type
     - - The type of service used for Hubble Relay access, either ClusterIP or NodePort.
     - string
     - ``"ClusterIP"``
   * - hubble.relay.sortBufferDrainTimeout
     - When the per-request flows sort buffer is not full, a flow is drained every time this timeout is reached (only affects requests in follow-mode) (e.g. "1s").
     - string
     - ``nil``
   * - hubble.relay.sortBufferLenMax
     - Max number of flows that can be buffered for sorting before being sent to the client (per request) (e.g. 100).
     - string
     - ``nil``
   * - hubble.relay.terminationGracePeriodSeconds
     - Configure termination grace period for hubble relay Deployment.
     - int
     - ``1``
   * - hubble.relay.tls
     - TLS configuration for Hubble Relay
     - object
     - ``{"client":{"cert":"","key":""},"server":{"cert":"","enabled":false,"extraDnsNames":[],"extraIpAddresses":[],"key":""}}``
   * - hubble.relay.tls.client
     - base64 encoded PEM values for the hubble-relay client certificate and private key This keypair is presented to Hubble server instances for mTLS authentication and is required when hubble.tls.enabled is true. These values need to be set manually if hubble.tls.auto.enabled is false.
     - object
     - ``{"cert":"","key":""}``
   * - hubble.relay.tls.server
     - base64 encoded PEM values for the hubble-relay server certificate and private key
     - object
     - ``{"cert":"","enabled":false,"extraDnsNames":[],"extraIpAddresses":[],"key":""}``
   * - hubble.relay.tls.server.extraDnsNames
     - extra DNS names added to certificate when its auto gen
     - list
     - ``[]``
   * - hubble.relay.tls.server.extraIpAddresses
     - extra IP addresses added to certificate when its auto gen
     - list
     - ``[]``
   * - hubble.relay.tolerations
     - Node tolerations for pod assignment on nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
     - list
     - ``[]``
   * - hubble.relay.topologySpreadConstraints
     - Pod topology spread constraints for hubble-relay
     - list
     - ``[]``
   * - hubble.relay.updateStrategy
     - hubble-relay update strategy
     - object
     - ``{"rollingUpdate":{"maxUnavailable":1},"type":"RollingUpdate"}``
   * - hubble.skipUnknownCGroupIDs
     - Skip Hubble events with unknown cgroup ids
     - bool
     - ``true``
   * - hubble.socketPath
     - Unix domain socket path to listen to when Hubble is enabled.
     - string
     - ``"/var/run/cilium/hubble.sock"``
   * - hubble.tls
     - TLS configuration for Hubble
     - object
     - ``{"auto":{"certManagerIssuerRef":{},"certValidityDuration":1095,"enabled":true,"method":"helm","schedule":"0 0 1 */4 *"},"enabled":true,"server":{"cert":"","extraDnsNames":[],"extraIpAddresses":[],"key":""}}``
   * - hubble.tls.auto
     - Configure automatic TLS certificates generation.
     - object
     - ``{"certManagerIssuerRef":{},"certValidityDuration":1095,"enabled":true,"method":"helm","schedule":"0 0 1 */4 *"}``
   * - hubble.tls.auto.certManagerIssuerRef
     - certmanager issuer used when hubble.tls.auto.method=certmanager.
     - object
     - ``{}``
   * - hubble.tls.auto.certValidityDuration
     - Generated certificates validity duration in days.
     - int
     - ``1095``
   * - hubble.tls.auto.enabled
     - Auto-generate certificates. When set to true, automatically generate a CA and certificates to enable mTLS between Hubble server and Hubble Relay instances. If set to false, the certs for Hubble server need to be provided by setting appropriate values below.
     - bool
     - ``true``
   * - hubble.tls.auto.method
     - Set the method to auto-generate certificates. Supported values: - helm:         This method uses Helm to generate all certificates. - cronJob:      This method uses a Kubernetes CronJob the generate any                 certificates not provided by the user at installation                 time. - certmanager:  This method use cert-manager to generate & rotate certificates.
     - string
     - ``"helm"``
   * - hubble.tls.auto.schedule
     - Schedule for certificates regeneration (regardless of their expiration date). Only used if method is "cronJob". If nil, then no recurring job will be created. Instead, only the one-shot job is deployed to generate the certificates at installation time.  Defaults to midnight of the first day of every fourth month. For syntax, see https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/#schedule-syntax
     - string
     - ``"0 0 1 */4 *"``
   * - hubble.tls.enabled
     - Enable mutual TLS for listenAddress. Setting this value to false is highly discouraged as the Hubble API provides access to potentially sensitive network flow metadata and is exposed on the host network.
     - bool
     - ``true``
   * - hubble.tls.server
     - base64 encoded PEM values for the Hubble server certificate and private key
     - object
     - ``{"cert":"","extraDnsNames":[],"extraIpAddresses":[],"key":""}``
   * - hubble.tls.server.extraDnsNames
     - Extra DNS names added to certificate when it's auto generated
     - list
     - ``[]``
   * - hubble.tls.server.extraIpAddresses
     - Extra IP addresses added to certificate when it's auto generated
     - list
     - ``[]``
   * - hubble.ui.affinity
     - Affinity for hubble-ui
     - object
     - ``{}``
   * - hubble.ui.backend.extraEnv
     - Additional hubble-ui backend environment variables.
     - list
     - ``[]``
   * - hubble.ui.backend.extraVolumeMounts
     - Additional hubble-ui backend volumeMounts.
     - list
     - ``[]``
   * - hubble.ui.backend.extraVolumes
     - Additional hubble-ui backend volumes.
     - list
     - ``[]``
   * - hubble.ui.backend.image
     - Hubble-ui backend image.
     - object
     - ``{"digest":"sha256:14c04d11f78da5c363f88592abae8d2ecee3cbe009f443ef11df6ac5f692d839","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/hubble-ui-backend","tag":"v0.11.0","useDigest":true}``
   * - hubble.ui.backend.resources
     - Resource requests and limits for the 'backend' container of the 'hubble-ui' deployment.
     - object
     - ``{}``
   * - hubble.ui.backend.securityContext
     - Hubble-ui backend security context.
     - object
     - ``{}``
   * - hubble.ui.baseUrl
     - Defines base url prefix for all hubble-ui http requests. It needs to be changed in case if ingress for hubble-ui is configured under some sub-path. Trailing ``/`` is required for custom path, ex. ``/service-map/``
     - string
     - ``"/"``
   * - hubble.ui.enabled
     - Whether to enable the Hubble UI.
     - bool
     - ``false``
   * - hubble.ui.frontend.extraEnv
     - Additional hubble-ui frontend environment variables.
     - list
     - ``[]``
   * - hubble.ui.frontend.extraVolumeMounts
     - Additional hubble-ui frontend volumeMounts.
     - list
     - ``[]``
   * - hubble.ui.frontend.extraVolumes
     - Additional hubble-ui frontend volumes.
     - list
     - ``[]``
   * - hubble.ui.frontend.image
     - Hubble-ui frontend image.
     - object
     - ``{"digest":"sha256:bcb369c47cada2d4257d63d3749f7f87c91dde32e010b223597306de95d1ecc8","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/hubble-ui","tag":"v0.11.0","useDigest":true}``
   * - hubble.ui.frontend.resources
     - Resource requests and limits for the 'frontend' container of the 'hubble-ui' deployment.
     - object
     - ``{}``
   * - hubble.ui.frontend.securityContext
     - Hubble-ui frontend security context.
     - object
     - ``{}``
   * - hubble.ui.frontend.server.ipv6
     - Controls server listener for ipv6
     - object
     - ``{"enabled":true}``
   * - hubble.ui.ingress
     - hubble-ui ingress configuration.
     - object
     - ``{"annotations":{},"className":"","enabled":false,"hosts":["chart-example.local"],"labels":{},"tls":[]}``
   * - hubble.ui.nodeSelector
     - Node labels for pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector
     - object
     - ``{"kubernetes.io/os":"linux"}``
   * - hubble.ui.podAnnotations
     - Annotations to be added to hubble-ui pods
     - object
     - ``{}``
   * - hubble.ui.podDisruptionBudget.enabled
     - enable PodDisruptionBudget ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/
     - bool
     - ``false``
   * - hubble.ui.podDisruptionBudget.maxUnavailable
     - Maximum number/percentage of pods that may be made unavailable
     - int
     - ``1``
   * - hubble.ui.podDisruptionBudget.minAvailable
     - Minimum number/percentage of pods that should remain scheduled. When it's set, maxUnavailable must be disabled by ``maxUnavailable: null``
     - string
     - ``nil``
   * - hubble.ui.podLabels
     - Labels to be added to hubble-ui pods
     - object
     - ``{}``
   * - hubble.ui.priorityClassName
     - The priority class to use for hubble-ui
     - string
     - ``""``
   * - hubble.ui.replicas
     - The number of replicas of Hubble UI to deploy.
     - int
     - ``1``
   * - hubble.ui.rollOutPods
     - Roll out Hubble-ui pods automatically when configmap is updated.
     - bool
     - ``false``
   * - hubble.ui.securityContext
     - Security context to be added to Hubble UI pods
     - object
     - ``{"fsGroup":1001,"runAsGroup":1001,"runAsUser":1001}``
   * - hubble.ui.service
     - hubble-ui service configuration.
     - object
     - ``{"annotations":{},"nodePort":31235,"type":"ClusterIP"}``
   * - hubble.ui.service.annotations
     - Annotations to be added for the Hubble UI service
     - object
     - ``{}``
   * - hubble.ui.service.nodePort
     - - The port to use when the service type is set to NodePort.
     - int
     - ``31235``
   * - hubble.ui.service.type
     - - The type of service used for Hubble UI access, either ClusterIP or NodePort.
     - string
     - ``"ClusterIP"``
   * - hubble.ui.standalone.enabled
     - When true, it will allow installing the Hubble UI only, without checking dependencies. It is useful if a cluster already has cilium and Hubble relay installed and you just want Hubble UI to be deployed. When installed via helm, installing UI should be done via ``helm upgrade`` and when installed via the cilium cli, then ``cilium hubble enable --ui``
     - bool
     - ``false``
   * - hubble.ui.standalone.tls.certsVolume
     - When deploying Hubble UI in standalone, with tls enabled for Hubble relay, it is required to provide a volume for mounting the client certificates.
     - object
     - ``{}``
   * - hubble.ui.tls.client
     - base64 encoded PEM values used to connect to hubble-relay This keypair is presented to Hubble Relay instances for mTLS authentication and is required when hubble.relay.tls.server.enabled is true. These values need to be set manually if hubble.tls.auto.enabled is false.
     - object
     - ``{"cert":"","key":""}``
   * - hubble.ui.tolerations
     - Node tolerations for pod assignment on nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
     - list
     - ``[]``
   * - hubble.ui.topologySpreadConstraints
     - Pod topology spread constraints for hubble-ui
     - list
     - ``[]``
   * - hubble.ui.updateStrategy
     - hubble-ui update strategy.
     - object
     - ``{"rollingUpdate":{"maxUnavailable":1},"type":"RollingUpdate"}``
   * - identityAllocationMode
     - Method to use for identity allocation (\ ``crd`` or ``kvstore``\ ).
     - string
     - ``"crd"``
   * - identityChangeGracePeriod
     - Time to wait before using new identity on endpoint identity change.
     - string
     - ``"5s"``
   * - image
     - Agent container image.
     - object
     - ``{"digest":"","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/cilium-ci","tag":"latest","useDigest":false}``
   * - imagePullSecrets
     - Configure image pull secrets for pulling container images
     - string
     - ``nil``
   * - ingressController.default
     - Set cilium ingress controller to be the default ingress controller This will let cilium ingress controller route entries without ingress class set
     - bool
     - ``false``
   * - ingressController.enabled
     - Enable cilium ingress controller This will automatically set enable-envoy-config as well.
     - bool
     - ``false``
   * - ingressController.enforceHttps
     - Enforce https for host having matching TLS host in Ingress. Incoming traffic to http listener will return 308 http error code with respective location in header.
     - bool
     - ``true``
   * - ingressController.ingressLBAnnotationPrefixes
     - IngressLBAnnotations are the annotation prefixes, which are used to filter annotations to propagate from Ingress to the Load Balancer service
     - list
     - ``["service.beta.kubernetes.io","service.kubernetes.io","cloud.google.com"]``
   * - ingressController.loadbalancerMode
     - Default ingress load balancer mode Supported values: shared, dedicated For granular control, use the following annotations on the ingress resource ingress.cilium.io/loadbalancer-mode: shared
     - string
     - ``"dedicated"``
   * - ingressController.secretsNamespace
     - SecretsNamespace is the namespace in which envoy SDS will retrieve TLS secrets from.
     - object
     - ``{"create":true,"name":"cilium-secrets","sync":true}``
   * - ingressController.secretsNamespace.create
     - Create secrets namespace for Ingress.
     - bool
     - ``true``
   * - ingressController.secretsNamespace.name
     - Name of Ingress secret namespace.
     - string
     - ``"cilium-secrets"``
   * - ingressController.secretsNamespace.sync
     - Enable secret sync, which will make sure all TLS secrets used by Ingress are synced to secretsNamespace.name. If disabled, TLS secrets must be maintained externally.
     - bool
     - ``true``
   * - ingressController.service
     - Load-balancer service in shared mode. This is a single load-balancer service for all Ingress resources.
     - object
     - ``{"annotations":{},"insecureNodePort":null,"labels":{},"loadBalancerClass":null,"loadBalancerIP":null,"name":"cilium-ingress","secureNodePort":null,"type":"LoadBalancer"}``
   * - ingressController.service.annotations
     - Annotations to be added for the shared LB service
     - object
     - ``{}``
   * - ingressController.service.insecureNodePort
     - Configure a specific nodePort for insecure HTTP traffic on the shared LB service
     - string
     - ``nil``
   * - ingressController.service.labels
     - Labels to be added for the shared LB service
     - object
     - ``{}``
   * - ingressController.service.loadBalancerClass
     - Configure a specific loadBalancerClass on the shared LB service (requires Kubernetes 1.24+)
     - string
     - ``nil``
   * - ingressController.service.loadBalancerIP
     - Configure a specific loadBalancerIP on the shared LB service
     - string
     - ``nil``
   * - ingressController.service.name
     - Service name
     - string
     - ``"cilium-ingress"``
   * - ingressController.service.secureNodePort
     - Configure a specific nodePort for secure HTTPS traffic on the shared LB service
     - string
     - ``nil``
   * - ingressController.service.type
     - Service type for the shared LB service
     - string
     - ``"LoadBalancer"``
   * - installNoConntrackIptablesRules
     - Install Iptables rules to skip netfilter connection tracking on all pod traffic. This option is only effective when Cilium is running in direct routing and full KPR mode. Moreover, this option cannot be enabled when Cilium is running in a managed Kubernetes environment or in a chained CNI setup.
     - bool
     - ``false``
   * - ipMasqAgent
     - Configure the eBPF-based ip-masq-agent
     - object
     - ``{"enabled":false}``
   * - ipam.ciliumNodeUpdateRate
     - Maximum rate at which the CiliumNode custom resource is updated.
     - string
     - ``"15s"``
   * - ipam.mode
     - Configure IP Address Management mode. ref: https://docs.cilium.io/en/stable/network/concepts/ipam/
     - string
     - ``"cluster-pool"``
   * - ipam.operator.clusterPoolIPv4MaskSize
     - IPv4 CIDR mask size to delegate to individual nodes for IPAM.
     - int
     - ``24``
   * - ipam.operator.clusterPoolIPv4PodCIDRList
     - IPv4 CIDR list range to delegate to individual nodes for IPAM.
     - list
     - ``["10.0.0.0/8"]``
   * - ipam.operator.clusterPoolIPv6MaskSize
     - IPv6 CIDR mask size to delegate to individual nodes for IPAM.
     - int
     - ``120``
   * - ipam.operator.clusterPoolIPv6PodCIDRList
     - IPv6 CIDR list range to delegate to individual nodes for IPAM.
     - list
     - ``["fd00::/104"]``
   * - ipam.operator.externalAPILimitBurstSize
     - The maximum burst size when rate limiting access to external APIs. Also known as the token bucket capacity.
     - string
     - ``20``
   * - ipam.operator.externalAPILimitQPS
     - The maximum queries per second when rate limiting access to external APIs. Also known as the bucket refill rate, which is used to refill the bucket up to the burst size capacity.
     - string
     - ``4.0``
   * - ipam.operator.multiPoolMap
     - IP pools defined for the multi-pool IPAM mode.
     - object
     - ``{}``
   * - ipv4.enabled
     - Enable IPv4 support.
     - bool
     - ``true``
   * - ipv4NativeRoutingCIDR
     - Allows to explicitly specify the IPv4 CIDR for native routing. When specified, Cilium assumes networking for this CIDR is preconfigured and hands traffic destined for that range to the Linux network stack without applying any SNAT. Generally speaking, specifying a native routing CIDR implies that Cilium can depend on the underlying networking stack to route packets to their destination. To offer a concrete example, if Cilium is configured to use direct routing and the Kubernetes CIDR is included in the native routing CIDR, the user must configure the routes to reach pods, either manually or by setting the auto-direct-node-routes flag.
     - string
     - ``""``
   * - ipv6.enabled
     - Enable IPv6 support.
     - bool
     - ``false``
   * - ipv6NativeRoutingCIDR
     - Allows to explicitly specify the IPv6 CIDR for native routing. When specified, Cilium assumes networking for this CIDR is preconfigured and hands traffic destined for that range to the Linux network stack without applying any SNAT. Generally speaking, specifying a native routing CIDR implies that Cilium can depend on the underlying networking stack to route packets to their destination. To offer a concrete example, if Cilium is configured to use direct routing and the Kubernetes CIDR is included in the native routing CIDR, the user must configure the routes to reach pods, either manually or by setting the auto-direct-node-routes flag.
     - string
     - ``""``
   * - k8s
     - Configure Kubernetes specific configuration
     - object
     - ``{}``
   * - k8sNetworkPolicy.enabled
     - Enable support for K8s NetworkPolicy
     - bool
     - ``true``
   * - k8sServiceHost
     - Kubernetes service host
     - string
     - ``""``
   * - k8sServicePort
     - Kubernetes service port
     - string
     - ``""``
   * - keepDeprecatedLabels
     - Keep the deprecated selector labels when deploying Cilium DaemonSet.
     - bool
     - ``false``
   * - keepDeprecatedProbes
     - Keep the deprecated probes when deploying Cilium DaemonSet
     - bool
     - ``false``
   * - kubeConfigPath
     - Kubernetes config path
     - string
     - ``"~/.kube/config"``
   * - kubeProxyReplacementHealthzBindAddr
     - healthz server bind address for the kube-proxy replacement. To enable set the value to '0.0.0.0:10256' for all ipv4 addresses and this '[::]:10256' for all ipv6 addresses. By default it is disabled.
     - string
     - ``""``
   * - l2NeighDiscovery.enabled
     - Enable L2 neighbor discovery in the agent
     - bool
     - ``true``
   * - l2NeighDiscovery.refreshPeriod
     - Override the agent's default neighbor resolution refresh period.
     - string
     - ``"30s"``
   * - l7Proxy
     - Enable Layer 7 network policy.
     - bool
     - ``true``
   * - livenessProbe.failureThreshold
     - failure threshold of liveness probe
     - int
     - ``10``
   * - livenessProbe.periodSeconds
     - interval between checks of the liveness probe
     - int
     - ``30``
   * - loadBalancer
     - Configure service load balancing
     - object
     - ``{"l7":{"algorithm":"round_robin","backend":"disabled","ports":[]}}``
   * - loadBalancer.l7
     - L7 LoadBalancer
     - object
     - ``{"algorithm":"round_robin","backend":"disabled","ports":[]}``
   * - loadBalancer.l7.algorithm
     - Default LB algorithm The default LB algorithm to be used for services, which can be overridden by the service annotation (e.g. service.cilium.io/lb-l7-algorithm) Applicable values: round_robin, least_request, random
     - string
     - ``"round_robin"``
   * - loadBalancer.l7.backend
     - Enable L7 service load balancing via envoy proxy. The request to a k8s service, which has specific annotation e.g. service.cilium.io/lb-l7, will be forwarded to the local backend proxy to be load balanced to the service endpoints. Please refer to docs for supported annotations for more configuration.  Applicable values:   - envoy: Enable L7 load balancing via envoy proxy. This will automatically set enable-envoy-config as well.   - disabled: Disable L7 load balancing.
     - string
     - ``"disabled"``
   * - loadBalancer.l7.ports
     - List of ports from service to be automatically redirected to above backend. Any service exposing one of these ports will be automatically redirected. Fine-grained control can be achieved by using the service annotation.
     - list
     - ``[]``
   * - localRedirectPolicy
     - Enable Local Redirect Policy.
     - bool
     - ``false``
   * - logSystemLoad
     - Enables periodic logging of system load
     - bool
     - ``false``
   * - maglev
     - Configure maglev consistent hashing
     - object
     - ``{}``
   * - monitor
     - cilium-monitor sidecar.
     - object
     - ``{"enabled":false}``
   * - monitor.enabled
     - Enable the cilium-monitor sidecar.
     - bool
     - ``false``
   * - name
     - Agent container name.
     - string
     - ``"cilium"``
   * - nat46x64Gateway
     - Configure standalone NAT46/NAT64 gateway
     - object
     - ``{"enabled":false}``
   * - nat46x64Gateway.enabled
     - Enable RFC8215-prefixed translation
     - bool
     - ``false``
   * - nodePort
     - Configure N-S k8s service loadbalancing
     - object
     - ``{"autoProtectPortRange":true,"bindProtection":true,"enableHealthCheck":true,"enabled":false}``
   * - nodePort.autoProtectPortRange
     - Append NodePort range to ip_local_reserved_ports if clash with ephemeral ports is detected.
     - bool
     - ``true``
   * - nodePort.bindProtection
     - Set to true to prevent applications binding to service ports.
     - bool
     - ``true``
   * - nodePort.enableHealthCheck
     - Enable healthcheck nodePort server for NodePort services
     - bool
     - ``true``
   * - nodePort.enabled
     - Enable the Cilium NodePort service implementation.
     - bool
     - ``false``
   * - nodeSelector
     - Node selector for cilium-agent.
     - object
     - ``{"kubernetes.io/os":"linux"}``
   * - nodeinit.affinity
     - Affinity for cilium-nodeinit
     - object
     - ``{}``
   * - nodeinit.bootstrapFile
     - bootstrapFile is the location of the file where the bootstrap timestamp is written by the node-init DaemonSet
     - string
     - ``"/tmp/cilium-bootstrap.d/cilium-bootstrap-time"``
   * - nodeinit.enabled
     - Enable the node initialization DaemonSet
     - bool
     - ``false``
   * - nodeinit.extraEnv
     - Additional nodeinit environment variables.
     - list
     - ``[]``
   * - nodeinit.extraVolumeMounts
     - Additional nodeinit volumeMounts.
     - list
     - ``[]``
   * - nodeinit.extraVolumes
     - Additional nodeinit volumes.
     - list
     - ``[]``
   * - nodeinit.image
     - node-init image.
     - object
     - ``{"override":null,"pullPolicy":"Always","repository":"quay.io/cilium/startup-script","tag":"62093c5c233ea914bfa26a10ba41f8780d9b737f"}``
   * - nodeinit.nodeSelector
     - Node labels for nodeinit pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector
     - object
     - ``{"kubernetes.io/os":"linux"}``
   * - nodeinit.podAnnotations
     - Annotations to be added to node-init pods.
     - object
     - ``{}``
   * - nodeinit.podLabels
     - Labels to be added to node-init pods.
     - object
     - ``{}``
   * - nodeinit.prestop
     - prestop offers way to customize prestop nodeinit script (pre and post position)
     - object
     - ``{"postScript":"","preScript":""}``
   * - nodeinit.priorityClassName
     - The priority class to use for the nodeinit pod.
     - string
     - ``""``
   * - nodeinit.resources
     - nodeinit resource limits & requests ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
     - object
     - ``{"requests":{"cpu":"100m","memory":"100Mi"}}``
   * - nodeinit.securityContext
     - Security context to be added to nodeinit pods.
     - object
     - ``{"capabilities":{"add":["SYS_MODULE","NET_ADMIN","SYS_ADMIN","SYS_CHROOT","SYS_PTRACE"]},"privileged":false,"seLinuxOptions":{"level":"s0","type":"spc_t"}}``
   * - nodeinit.startup
     - startup offers way to customize startup nodeinit script (pre and post position)
     - object
     - ``{"postScript":"","preScript":""}``
   * - nodeinit.tolerations
     - Node tolerations for nodeinit scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
     - list
     - ``[{"operator":"Exists"}]``
   * - nodeinit.updateStrategy
     - node-init update strategy
     - object
     - ``{"type":"RollingUpdate"}``
   * - operator.affinity
     - Affinity for cilium-operator
     - object
     - ``{"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"io.cilium/app":"operator"}},"topologyKey":"kubernetes.io/hostname"}]}}``
   * - operator.dashboards
     - Grafana dashboards for cilium-operator grafana can import dashboards based on the label and value ref: https://github.com/grafana/helm-charts/tree/main/charts/grafana#sidecar-for-dashboards
     - object
     - ``{"annotations":{},"enabled":false,"label":"grafana_dashboard","labelValue":"1","namespace":null}``
   * - operator.dnsPolicy
     - DNS policy for Cilium operator pods. Ref: https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pod-s-dns-policy
     - string
     - ``""``
   * - operator.enabled
     - Enable the cilium-operator component (required).
     - bool
     - ``true``
   * - operator.endpointGCInterval
     - Interval for endpoint garbage collection.
     - string
     - ``"5m0s"``
   * - operator.extraArgs
     - Additional cilium-operator container arguments.
     - list
     - ``[]``
   * - operator.extraEnv
     - Additional cilium-operator environment variables.
     - list
     - ``[]``
   * - operator.extraHostPathMounts
     - Additional cilium-operator hostPath mounts.
     - list
     - ``[]``
   * - operator.extraVolumeMounts
     - Additional cilium-operator volumeMounts.
     - list
     - ``[]``
   * - operator.extraVolumes
     - Additional cilium-operator volumes.
     - list
     - ``[]``
   * - operator.identityGCInterval
     - Interval for identity garbage collection.
     - string
     - ``"15m0s"``
   * - operator.identityHeartbeatTimeout
     - Timeout for identity heartbeats.
     - string
     - ``"30m0s"``
   * - operator.image
     - cilium-operator image.
     - object
     - ``{"alibabacloudDigest":"","awsDigest":"","azureDigest":"","genericDigest":"","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/operator","suffix":"-ci","tag":"latest","useDigest":false}``
   * - operator.nodeGCInterval
     - Interval for cilium node garbage collection.
     - string
     - ``"5m0s"``
   * - operator.nodeSelector
     - Node labels for cilium-operator pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector
     - object
     - ``{"kubernetes.io/os":"linux"}``
   * - operator.podAnnotations
     - Annotations to be added to cilium-operator pods
     - object
     - ``{}``
   * - operator.podDisruptionBudget.enabled
     - enable PodDisruptionBudget ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/
     - bool
     - ``false``
   * - operator.podDisruptionBudget.maxUnavailable
     - Maximum number/percentage of pods that may be made unavailable
     - int
     - ``1``
   * - operator.podDisruptionBudget.minAvailable
     - Minimum number/percentage of pods that should remain scheduled. When it's set, maxUnavailable must be disabled by ``maxUnavailable: null``
     - string
     - ``nil``
   * - operator.podLabels
     - Labels to be added to cilium-operator pods
     - object
     - ``{}``
   * - operator.podSecurityContext
     - Security context to be added to cilium-operator pods
     - object
     - ``{}``
   * - operator.pprof.address
     - Configure pprof listen address for cilium-operator
     - string
     - ``"localhost"``
   * - operator.pprof.enabled
     - Enable pprof for cilium-operator
     - bool
     - ``false``
   * - operator.pprof.port
     - Configure pprof listen port for cilium-operator
     - int
     - ``6061``
   * - operator.priorityClassName
     - The priority class to use for cilium-operator
     - string
     - ``""``
   * - operator.prometheus
     - Enable prometheus metrics for cilium-operator on the configured port at /metrics
     - object
     - ``{"enabled":false,"port":9963,"serviceMonitor":{"annotations":{},"enabled":false,"interval":"10s","labels":{},"metricRelabelings":null,"relabelings":null}}``
   * - operator.prometheus.serviceMonitor.annotations
     - Annotations to add to ServiceMonitor cilium-operator
     - object
     - ``{}``
   * - operator.prometheus.serviceMonitor.enabled
     - Enable service monitors. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml)
     - bool
     - ``false``
   * - operator.prometheus.serviceMonitor.interval
     - Interval for scrape metrics.
     - string
     - ``"10s"``
   * - operator.prometheus.serviceMonitor.labels
     - Labels to add to ServiceMonitor cilium-operator
     - object
     - ``{}``
   * - operator.prometheus.serviceMonitor.metricRelabelings
     - Metrics relabeling configs for the ServiceMonitor cilium-operator
     - string
     - ``nil``
   * - operator.prometheus.serviceMonitor.relabelings
     - Relabeling configs for the ServiceMonitor cilium-operator
     - string
     - ``nil``
   * - operator.removeNodeTaints
     - Remove Cilium node taint from Kubernetes nodes that have a healthy Cilium pod running.
     - bool
     - ``true``
   * - operator.replicas
     - Number of replicas to run for the cilium-operator deployment
     - int
     - ``2``
   * - operator.resources
     - cilium-operator resource limits & requests ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
     - object
     - ``{}``
   * - operator.rollOutPods
     - Roll out cilium-operator pods automatically when configmap is updated.
     - bool
     - ``false``
   * - operator.securityContext
     - Security context to be added to cilium-operator pods
     - object
     - ``{}``
   * - operator.setNodeNetworkStatus
     - Set Node condition NetworkUnavailable to 'false' with the reason 'CiliumIsUp' for nodes that have a healthy Cilium pod.
     - bool
     - ``true``
   * - operator.setNodeTaints
     - Taint nodes where Cilium is scheduled but not running. This prevents pods from being scheduled to nodes where Cilium is not the default CNI provider.
     - string
     - same as removeNodeTaints
   * - operator.skipCNPStatusStartupClean
     - Skip CNP node status clean up at operator startup.
     - bool
     - ``false``
   * - operator.skipCRDCreation
     - Skip CRDs creation for cilium-operator
     - bool
     - ``false``
   * - operator.tolerations
     - Node tolerations for cilium-operator scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
     - list
     - ``[{"operator":"Exists"}]``
   * - operator.topologySpreadConstraints
     - Pod topology spread constraints for cilium-operator
     - list
     - ``[]``
   * - operator.unmanagedPodWatcher.intervalSeconds
     - Interval, in seconds, to check if there are any pods that are not managed by Cilium.
     - int
     - ``15``
   * - operator.unmanagedPodWatcher.restart
     - Restart any pod that are not managed by Cilium.
     - bool
     - ``true``
   * - operator.updateStrategy
     - cilium-operator update strategy
     - object
     - ``{"rollingUpdate":{"maxSurge":"25%","maxUnavailable":"50%"},"type":"RollingUpdate"}``
   * - pmtuDiscovery.enabled
     - Enable path MTU discovery to send ICMP fragmentation-needed replies to the client.
     - bool
     - ``false``
   * - podAnnotations
     - Annotations to be added to agent pods
     - object
     - ``{}``
   * - podLabels
     - Labels to be added to agent pods
     - object
     - ``{}``
   * - podSecurityContext
     - Security Context for cilium-agent pods.
     - object
     - ``{}``
   * - policyEnforcementMode
     - The agent can be put into one of the three policy enforcement modes: default, always and never. ref: https://docs.cilium.io/en/stable/security/policy/intro/#policy-enforcement-modes
     - string
     - ``"default"``
   * - pprof.address
     - Configure pprof listen address for cilium-agent
     - string
     - ``"localhost"``
   * - pprof.enabled
     - Enable pprof for cilium-agent
     - bool
     - ``false``
   * - pprof.port
     - Configure pprof listen port for cilium-agent
     - int
     - ``6060``
   * - preflight.affinity
     - Affinity for cilium-preflight
     - object
     - ``{"podAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"k8s-app":"cilium"}},"topologyKey":"kubernetes.io/hostname"}]}}``
   * - preflight.enabled
     - Enable Cilium pre-flight resources (required for upgrade)
     - bool
     - ``false``
   * - preflight.extraEnv
     - Additional preflight environment variables.
     - list
     - ``[]``
   * - preflight.extraVolumeMounts
     - Additional preflight volumeMounts.
     - list
     - ``[]``
   * - preflight.extraVolumes
     - Additional preflight volumes.
     - list
     - ``[]``
   * - preflight.image
     - Cilium pre-flight image.
     - object
     - ``{"digest":"","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/cilium-ci","tag":"latest","useDigest":false}``
   * - preflight.nodeSelector
     - Node labels for preflight pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector
     - object
     - ``{"kubernetes.io/os":"linux"}``
   * - preflight.podAnnotations
     - Annotations to be added to preflight pods
     - object
     - ``{}``
   * - preflight.podDisruptionBudget.enabled
     - enable PodDisruptionBudget ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/
     - bool
     - ``false``
   * - preflight.podDisruptionBudget.maxUnavailable
     - Maximum number/percentage of pods that may be made unavailable
     - int
     - ``1``
   * - preflight.podDisruptionBudget.minAvailable
     - Minimum number/percentage of pods that should remain scheduled. When it's set, maxUnavailable must be disabled by ``maxUnavailable: null``
     - string
     - ``nil``
   * - preflight.podLabels
     - Labels to be added to the preflight pod.
     - object
     - ``{}``
   * - preflight.podSecurityContext
     - Security context to be added to preflight pods.
     - object
     - ``{}``
   * - preflight.priorityClassName
     - The priority class to use for the preflight pod.
     - string
     - ``""``
   * - preflight.resources
     - preflight resource limits & requests ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
     - object
     - ``{}``
   * - preflight.securityContext
     - Security context to be added to preflight pods
     - object
     - ``{}``
   * - preflight.terminationGracePeriodSeconds
     - Configure termination grace period for preflight Deployment and DaemonSet.
     - int
     - ``1``
   * - preflight.tofqdnsPreCache
     - Path to write the ``--tofqdns-pre-cache`` file to.
     - string
     - ``""``
   * - preflight.tolerations
     - Node tolerations for preflight scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
     - list
     - ``[{"effect":"NoSchedule","key":"node.kubernetes.io/not-ready"},{"effect":"NoSchedule","key":"node-role.kubernetes.io/master"},{"effect":"NoSchedule","key":"node-role.kubernetes.io/control-plane"},{"effect":"NoSchedule","key":"node.cloudprovider.kubernetes.io/uninitialized","value":"true"},{"key":"CriticalAddonsOnly","operator":"Exists"}]``
   * - preflight.updateStrategy
     - preflight update strategy
     - object
     - ``{"type":"RollingUpdate"}``
   * - preflight.validateCNPs
     - By default we should always validate the installed CNPs before upgrading Cilium. This will make sure the user will have the policies deployed in the cluster with the right schema.
     - bool
     - ``true``
   * - priorityClassName
     - The priority class to use for cilium-agent.
     - string
     - ``""``
   * - prometheus
     - Configure prometheus metrics on the configured port at /metrics
     - object
     - ``{"enabled":false,"metrics":null,"port":9962,"serviceMonitor":{"annotations":{},"enabled":false,"interval":"10s","labels":{},"metricRelabelings":null,"relabelings":[{"replacement":"${1}","sourceLabels":["__meta_kubernetes_pod_node_name"],"targetLabel":"node"}]}}``
   * - prometheus.metrics
     - Metrics that should be enabled or disabled from the default metric list. The list is expected to be separated by a space. (+metric_foo to enable metric_foo , -metric_bar to disable metric_bar). ref: https://docs.cilium.io/en/stable/observability/metrics/
     - string
     - ``nil``
   * - prometheus.serviceMonitor.annotations
     - Annotations to add to ServiceMonitor cilium-agent
     - object
     - ``{}``
   * - prometheus.serviceMonitor.enabled
     - Enable service monitors. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml)
     - bool
     - ``false``
   * - prometheus.serviceMonitor.interval
     - Interval for scrape metrics.
     - string
     - ``"10s"``
   * - prometheus.serviceMonitor.labels
     - Labels to add to ServiceMonitor cilium-agent
     - object
     - ``{}``
   * - prometheus.serviceMonitor.metricRelabelings
     - Metrics relabeling configs for the ServiceMonitor cilium-agent
     - string
     - ``nil``
   * - prometheus.serviceMonitor.relabelings
     - Relabeling configs for the ServiceMonitor cilium-agent
     - list
     - ``[{"replacement":"${1}","sourceLabels":["__meta_kubernetes_pod_node_name"],"targetLabel":"node"}]``
   * - proxy
     - Configure Istio proxy options.
     - object
     - ``{"prometheus":{"enabled":true,"port":null},"sidecarImageRegex":"cilium/istio_proxy"}``
   * - proxy.prometheus.enabled
     - Deprecated in favor of envoy.prometheus.enabled
     - bool
     - ``true``
   * - proxy.prometheus.port
     - Deprecated in favor of envoy.prometheus.port
     - string
     - ``nil``
   * - proxy.sidecarImageRegex
     - Regular expression matching compatible Istio sidecar istio-proxy container image names
     - string
     - ``"cilium/istio_proxy"``
   * - rbac.create
     - Enable creation of Resource-Based Access Control configuration.
     - bool
     - ``true``
   * - readinessProbe.failureThreshold
     - failure threshold of readiness probe
     - int
     - ``3``
   * - readinessProbe.periodSeconds
     - interval between checks of the readiness probe
     - int
     - ``30``
   * - remoteNodeIdentity
     - Enable use of the remote node identity. ref: https://docs.cilium.io/en/v1.7/install/upgrade/#configmap-remote-node-identity
     - bool
     - ``true``
   * - resourceQuotas
     - Enable resource quotas for priority classes used in the cluster.
     - object
     - ``{"cilium":{"hard":{"pods":"10k"}},"enabled":false,"operator":{"hard":{"pods":"15"}}}``
   * - resources
     - Agent resource limits & requests ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
     - object
     - ``{}``
   * - rollOutCiliumPods
     - Roll out cilium agent pods automatically when configmap is updated.
     - bool
     - ``false``
   * - routingMode
     - Enable native-routing mode or tunneling mode.
     - string
     - ``"tunnel"``
   * - sctp
     - SCTP Configuration Values
     - object
     - ``{"enabled":false}``
   * - sctp.enabled
     - Enable SCTP support. NOTE: Currently, SCTP support does not support rewriting ports or multihoming.
     - bool
     - ``false``
   * - securityContext.capabilities.applySysctlOverwrites
     - capabilities for the ``apply-sysctl-overwrites`` init container
     - list
     - ``["SYS_ADMIN","SYS_CHROOT","SYS_PTRACE"]``
   * - securityContext.capabilities.ciliumAgent
     - Capabilities for the ``cilium-agent`` container
     - list
     - ``["CHOWN","KILL","NET_ADMIN","NET_RAW","IPC_LOCK","SYS_MODULE","SYS_ADMIN","SYS_RESOURCE","DAC_OVERRIDE","FOWNER","SETGID","SETUID"]``
   * - securityContext.capabilities.cleanCiliumState
     - Capabilities for the ``clean-cilium-state`` init container
     - list
     - ``["NET_ADMIN","SYS_MODULE","SYS_ADMIN","SYS_RESOURCE"]``
   * - securityContext.capabilities.mountCgroup
     - Capabilities for the ``mount-cgroup`` init container
     - list
     - ``["SYS_ADMIN","SYS_CHROOT","SYS_PTRACE"]``
   * - securityContext.privileged
     - Run the pod with elevated privileges
     - bool
     - ``false``
   * - securityContext.seLinuxOptions
     - SELinux options for the ``cilium-agent`` and init containers
     - object
     - ``{"level":"s0","type":"spc_t"}``
   * - serviceAccounts
     - Define serviceAccount names for components.
     - object
     - Component's fully qualified name.
   * - serviceAccounts.clustermeshcertgen
     - Clustermeshcertgen is used if clustermesh.apiserver.tls.auto.method=cronJob
     - object
     - ``{"annotations":{},"automount":true,"create":true,"name":"clustermesh-apiserver-generate-certs"}``
   * - serviceAccounts.hubblecertgen
     - Hubblecertgen is used if hubble.tls.auto.method=cronJob
     - object
     - ``{"annotations":{},"automount":true,"create":true,"name":"hubble-generate-certs"}``
   * - serviceAccounts.nodeinit.enabled
     - Enabled is temporary until https://github.com/cilium/cilium-cli/issues/1396 is implemented. Cilium CLI doesn't create the SAs for node-init, thus the workaround. Helm is not affected by this issue. Name and automount can be configured, if enabled is set to true. Otherwise, they are ignored. Enabled can be removed once the issue is fixed. Cilium-nodeinit DS must also be fixed.
     - bool
     - ``false``
   * - sleepAfterInit
     - Do not run Cilium agent when running with clean mode. Useful to completely uninstall Cilium as it will stop Cilium from starting and create artifacts in the node.
     - bool
     - ``false``
   * - socketLB
     - Configure socket LB
     - object
     - ``{"enabled":false}``
   * - socketLB.enabled
     - Enable socket LB
     - bool
     - ``false``
   * - startupProbe.failureThreshold
     - failure threshold of startup probe. 105 x 2s translates to the old behaviour of the readiness probe (120s delay + 30 x 3s)
     - int
     - ``105``
   * - startupProbe.periodSeconds
     - interval between checks of the startup probe
     - int
     - ``2``
   * - svcSourceRangeCheck
     - Enable check of service source ranges (currently, only for LoadBalancer).
     - bool
     - ``true``
   * - synchronizeK8sNodes
     - Synchronize Kubernetes nodes to kvstore and perform CNP GC.
     - bool
     - ``true``
   * - terminationGracePeriodSeconds
     - Configure termination grace period for cilium-agent DaemonSet.
     - int
     - ``1``
   * - tls
     - Configure TLS configuration in the agent.
     - object
     - ``{"ca":{"cert":"","certValidityDuration":1095,"key":""},"caBundle":{"enabled":false,"key":"ca.crt","name":"cilium-root-ca.crt"},"secretsBackend":"local"}``
   * - tls.ca
     - Base64 encoded PEM values for the CA certificate and private key. This can be used as common CA to generate certificates used by hubble and clustermesh components. It is neither required nor used when cert-manager is used to generate the certificates.
     - object
     - ``{"cert":"","certValidityDuration":1095,"key":""}``
   * - tls.ca.cert
     - Optional CA cert. If it is provided, it will be used by cilium to generate all other certificates. Otherwise, an ephemeral CA is generated.
     - string
     - ``""``
   * - tls.ca.certValidityDuration
     - Generated certificates validity duration in days. This will be used for auto generated CA.
     - int
     - ``1095``
   * - tls.ca.key
     - Optional CA private key. If it is provided, it will be used by cilium to generate all other certificates. Otherwise, an ephemeral CA is generated.
     - string
     - ``""``
   * - tls.caBundle
     - Configure the CA trust bundle used for the validation of the certificates leveraged by hubble and clustermesh. When enabled, it overrides the content of the 'ca.crt' field of the respective certificates, allowing for CA rotation with no down-time.
     - object
     - ``{"enabled":false,"key":"ca.crt","name":"cilium-root-ca.crt"}``
   * - tls.caBundle.enabled
     - Enable the use of the CA trust bundle.
     - bool
     - ``false``
   * - tls.caBundle.key
     - Entry of the ConfigMap containing the CA trust bundle.
     - string
     - ``"ca.crt"``
   * - tls.caBundle.name
     - Name of the ConfigMap containing the CA trust bundle.
     - string
     - ``"cilium-root-ca.crt"``
   * - tls.secretsBackend
     - This configures how the Cilium agent loads the secrets used TLS-aware CiliumNetworkPolicies (namely the secrets referenced by terminatingTLS and originatingTLS). Possible values:   - local   - k8s
     - string
     - ``"local"``
   * - tolerations
     - Node tolerations for agent scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
     - list
     - ``[{"operator":"Exists"}]``
   * - tunnel
     - Configure the encapsulation configuration for communication between nodes. Possible values:   - disabled   - vxlan (default)   - geneve
     - string
     - ``""``
   * - tunnelPort
     - Configure VXLAN and Geneve tunnel port.
     - int
     - Port 8472 for VXLAN, Port 6081 for Geneve
   * - tunnelProtocol
     - Tunneling protocol to use in tunneling mode and for ad-hoc tunnels.
     - string
     - ``"vxlan"``
   * - updateStrategy
     - Cilium agent update strategy
     - object
     - ``{"rollingUpdate":{"maxUnavailable":2},"type":"RollingUpdate"}``
   * - vtep.cidr
     - A space separated list of VTEP device CIDRs, for example "1.1.1.0/24 1.1.2.0/24"
     - string
     - ``""``
   * - vtep.enabled
     - Enables VXLAN Tunnel Endpoint (VTEP) Integration (beta) to allow Cilium-managed pods to talk to third party VTEP devices over Cilium tunnel.
     - bool
     - ``false``
   * - vtep.endpoint
     - A space separated list of VTEP device endpoint IPs, for example "1.1.1.1  1.1.2.1"
     - string
     - ``""``
   * - vtep.mac
     - A space separated list of VTEP device MAC addresses (VTEP MAC), for example "x:x:x:x:x:x  y:y:y:y:y:y:y"
     - string
     - ``""``
   * - vtep.mask
     - VTEP CIDRs Mask that applies to all VTEP CIDRs, for example "255.255.255.0"
     - string
     - ``""``
   * - waitForKubeProxy
     - Wait for KUBE-PROXY-CANARY iptables rule to appear in "wait-for-kube-proxy" init container before launching cilium-agent. More context can be found in the commit message of below PR https://github.com/cilium/cilium/pull/20123
     - bool
     - ``false``
   * - wellKnownIdentities.enabled
     - Enable the use of well-known identities.
     - bool
     - ``false``
