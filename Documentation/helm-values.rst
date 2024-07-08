..
  AUTO-GENERATED. Please DO NOT edit manually.


.. list-table::
   :header-rows: 1

   * - :spelling:ignore:`Key`
     - Description
     - Type
     - Default
   * - :spelling:ignore:`MTU`
     - Configure the underlying network MTU to overwrite auto-detected MTU.
     - int
     - ``0``
   * - :spelling:ignore:`affinity`
     - Affinity for cilium-agent.
     - object
     - ``{"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"k8s-app":"cilium"}},"topologyKey":"kubernetes.io/hostname"}]}}``
   * - :spelling:ignore:`agent`
     - Install the cilium agent resources.
     - bool
     - ``true``
   * - :spelling:ignore:`agentNotReadyTaintKey`
     - Configure the key of the taint indicating that Cilium is not ready on the node. When set to a value starting with ``ignore-taint.cluster-autoscaler.kubernetes.io/``\ , the Cluster Autoscaler will ignore the taint on its decisions, allowing the cluster to scale up.
     - string
     - ``"node.cilium.io/agent-not-ready"``
   * - :spelling:ignore:`aksbyocni.enabled`
     - Enable AKS BYOCNI integration. Note that this is incompatible with AKS clusters not created in BYOCNI mode: use Azure integration (\ ``azure.enabled``\ ) instead.
     - bool
     - ``false``
   * - :spelling:ignore:`alibabacloud.enabled`
     - Enable AlibabaCloud ENI integration
     - bool
     - ``false``
   * - :spelling:ignore:`annotateK8sNode`
     - Annotate k8s node upon initialization with Cilium's metadata.
     - bool
     - ``false``
   * - :spelling:ignore:`autoDirectNodeRoutes`
     - Enable installation of PodCIDR routes between worker nodes if worker nodes share a common L2 network segment.
     - bool
     - ``false``
   * - :spelling:ignore:`azure.enabled`
     - Enable Azure integration. Note that this is incompatible with AKS clusters created in BYOCNI mode: use AKS BYOCNI integration (\ ``aksbyocni.enabled``\ ) instead.
     - bool
     - ``false``
   * - :spelling:ignore:`bandwidthManager`
     - Enable bandwidth manager to optimize TCP and UDP workloads and allow for rate-limiting traffic from individual Pods with EDT (Earliest Departure Time) through the "kubernetes.io/egress-bandwidth" Pod annotation.
     - object
     - ``{"bbr":false,"enabled":false}``
   * - :spelling:ignore:`bandwidthManager.bbr`
     - Activate BBR TCP congestion control for Pods
     - bool
     - ``false``
   * - :spelling:ignore:`bandwidthManager.enabled`
     - Enable bandwidth manager infrastructure (also prerequirement for BBR)
     - bool
     - ``false``
   * - :spelling:ignore:`bgp`
     - Configure BGP
     - object
     - ``{"announce":{"loadbalancerIP":false,"podCIDR":false},"enabled":false}``
   * - :spelling:ignore:`bgp.announce.loadbalancerIP`
     - Enable allocation and announcement of service LoadBalancer IPs
     - bool
     - ``false``
   * - :spelling:ignore:`bgp.announce.podCIDR`
     - Enable announcement of node pod CIDR
     - bool
     - ``false``
   * - :spelling:ignore:`bgp.enabled`
     - Enable BGP support inside Cilium; embeds a new ConfigMap for BGP inside cilium-agent and cilium-operator
     - bool
     - ``false``
   * - :spelling:ignore:`bgpControlPlane`
     - This feature set enables virtual BGP routers to be created via CiliumBGPPeeringPolicy CRDs.
     - object
     - ``{"enabled":false}``
   * - :spelling:ignore:`bgpControlPlane.enabled`
     - Enables the BGP control plane.
     - bool
     - ``false``
   * - :spelling:ignore:`bpf.ctAnyMax`
     - Configure the maximum number of entries for the non-TCP connection tracking table.
     - int
     - ``262144``
   * - :spelling:ignore:`bpf.ctTcpMax`
     - Configure the maximum number of entries in the TCP connection tracking table.
     - int
     - ``524288``
   * - :spelling:ignore:`bpf.hostLegacyRouting`
     - Configure whether direct routing mode should route traffic via host stack (true) or directly and more efficiently out of BPF (false) if the kernel supports it. The latter has the implication that it will also bypass netfilter in the host namespace.
     - bool
     - ``false``
   * - :spelling:ignore:`bpf.lbExternalClusterIP`
     - Allow cluster external access to ClusterIP services.
     - bool
     - ``false``
   * - :spelling:ignore:`bpf.lbMapMax`
     - Configure the maximum number of service entries in the load balancer maps.
     - int
     - ``65536``
   * - :spelling:ignore:`bpf.mapDynamicSizeRatio`
     - Configure auto-sizing for all BPF maps based on available memory. ref: https://docs.cilium.io/en/stable/network/ebpf/maps/
     - float64
     - ``0.0025``
   * - :spelling:ignore:`bpf.masquerade`
     - Enable native IP masquerade support in eBPF
     - bool
     - ``false``
   * - :spelling:ignore:`bpf.monitorAggregation`
     - Configure the level of aggregation for monitor notifications. Valid options are none, low, medium, maximum.
     - string
     - ``"medium"``
   * - :spelling:ignore:`bpf.monitorFlags`
     - Configure which TCP flags trigger notifications when seen for the first time in a connection.
     - string
     - ``"all"``
   * - :spelling:ignore:`bpf.monitorInterval`
     - Configure the typical time between monitor notifications for active connections.
     - string
     - ``"5s"``
   * - :spelling:ignore:`bpf.natMax`
     - Configure the maximum number of entries for the NAT table.
     - int
     - ``524288``
   * - :spelling:ignore:`bpf.neighMax`
     - Configure the maximum number of entries for the neighbor table.
     - int
     - ``524288``
   * - :spelling:ignore:`bpf.policyMapMax`
     - Configure the maximum number of entries in endpoint policy map (per endpoint).
     - int
     - ``16384``
   * - :spelling:ignore:`bpf.preallocateMaps`
     - Enables pre-allocation of eBPF map values. This increases memory usage but can reduce latency.
     - bool
     - ``false``
   * - :spelling:ignore:`bpf.root`
     - Configure the mount point for the BPF filesystem
     - string
     - ``"/sys/fs/bpf"``
   * - :spelling:ignore:`bpf.tproxy`
     - Configure the eBPF-based TPROXY to reduce reliance on iptables rules for implementing Layer 7 policy.
     - bool
     - ``false``
   * - :spelling:ignore:`bpf.vlanBypass`
     - Configure explicitly allowed VLAN id's for bpf logic bypass. [0] will allow all VLAN id's without any filtering.
     - list
     - ``[]``
   * - :spelling:ignore:`bpfClockProbe`
     - Enable BPF clock source probing for more efficient tick retrieval.
     - bool
     - ``false``
   * - :spelling:ignore:`certgen`
     - Configure certificate generation for Hubble integration. If hubble.tls.auto.method=cronJob, these values are used for the Kubernetes CronJob which will be scheduled regularly to (re)generate any certificates not provided manually.
     - object
     - ``{"extraVolumeMounts":[],"extraVolumes":[],"image":{"override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/certgen","tag":"v0.1.13@sha256:01802e6a153a9473b06ebade7ee5730f8f2c6cc8db8768508161da3cdd778641"},"podLabels":{},"tolerations":[],"ttlSecondsAfterFinished":1800}``
   * - :spelling:ignore:`certgen.extraVolumeMounts`
     - Additional certgen volumeMounts.
     - list
     - ``[]``
   * - :spelling:ignore:`certgen.extraVolumes`
     - Additional certgen volumes.
     - list
     - ``[]``
   * - :spelling:ignore:`certgen.podLabels`
     - Labels to be added to hubble-certgen pods
     - object
     - ``{}``
   * - :spelling:ignore:`certgen.tolerations`
     - Node tolerations for pod assignment on nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
     - list
     - ``[]``
   * - :spelling:ignore:`certgen.ttlSecondsAfterFinished`
     - Seconds after which the completed job pod will be deleted
     - int
     - ``1800``
   * - :spelling:ignore:`cgroup`
     - Configure cgroup related configuration
     - object
     - ``{"autoMount":{"enabled":true,"resources":{}},"hostRoot":"/run/cilium/cgroupv2"}``
   * - :spelling:ignore:`cgroup.autoMount.enabled`
     - Enable auto mount of cgroup2 filesystem. When ``autoMount`` is enabled, cgroup2 filesystem is mounted at ``cgroup.hostRoot`` path on the underlying host and inside the cilium agent pod. If users disable ``autoMount``\ , it's expected that users have mounted cgroup2 filesystem at the specified ``cgroup.hostRoot`` volume, and then the volume will be mounted inside the cilium agent pod at the same path.
     - bool
     - ``true``
   * - :spelling:ignore:`cgroup.autoMount.resources`
     - Init Container Cgroup Automount resource limits & requests
     - object
     - ``{}``
   * - :spelling:ignore:`cgroup.hostRoot`
     - Configure cgroup root where cgroup2 filesystem is mounted on the host (see also: ``cgroup.autoMount``\ )
     - string
     - ``"/run/cilium/cgroupv2"``
   * - :spelling:ignore:`cleanBpfState`
     - Clean all eBPF datapath state from the initContainer of the cilium-agent DaemonSet.  WARNING: Use with care!
     - bool
     - ``false``
   * - :spelling:ignore:`cleanState`
     - Clean all local Cilium state from the initContainer of the cilium-agent DaemonSet. Implies cleanBpfState: true.  WARNING: Use with care!
     - bool
     - ``false``
   * - :spelling:ignore:`cluster.id`
     - Unique ID of the cluster. Must be unique across all connected clusters and in the range of 1 to 255. Only required for Cluster Mesh, may be 0 if Cluster Mesh is not used.
     - int
     - ``0``
   * - :spelling:ignore:`cluster.name`
     - Name of the cluster. Only required for Cluster Mesh.
     - string
     - ``"default"``
   * - :spelling:ignore:`clustermesh.apiserver.affinity`
     - Affinity for clustermesh.apiserver
     - object
     - ``{"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"k8s-app":"clustermesh-apiserver"}},"topologyKey":"kubernetes.io/hostname"}]}}``
   * - :spelling:ignore:`clustermesh.apiserver.etcd.image`
     - Clustermesh API server etcd image.
     - object
     - ``{"override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/coreos/etcd","tag":"v3.5.4@sha256:795d8660c48c439a7c3764c2330ed9222ab5db5bb524d8d0607cac76f7ba82a3"}``
   * - :spelling:ignore:`clustermesh.apiserver.etcd.init.resources`
     - Specifies the resources for etcd init container in the apiserver
     - object
     - ``{}``
   * - :spelling:ignore:`clustermesh.apiserver.etcd.resources`
     - Specifies the resources for etcd container in the apiserver
     - object
     - ``{}``
   * - :spelling:ignore:`clustermesh.apiserver.etcd.securityContext`
     - Security context to be added to clustermesh-apiserver etcd containers
     - object
     - ``{}``
   * - :spelling:ignore:`clustermesh.apiserver.extraEnv`
     - Additional clustermesh-apiserver environment variables.
     - list
     - ``[]``
   * - :spelling:ignore:`clustermesh.apiserver.extraVolumeMounts`
     - Additional clustermesh-apiserver volumeMounts.
     - list
     - ``[]``
   * - :spelling:ignore:`clustermesh.apiserver.extraVolumes`
     - Additional clustermesh-apiserver volumes.
     - list
     - ``[]``
   * - :spelling:ignore:`clustermesh.apiserver.image`
     - Clustermesh API server image.
     - object
     - ``{"digest":"sha256:c2a38a7fd080c4159ef6a499945f3af069333385255ddc80c2fd35328f6b512a","override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/clustermesh-apiserver","tag":"v1.13.18","useDigest":true}``
   * - :spelling:ignore:`clustermesh.apiserver.nodeSelector`
     - Node labels for pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector
     - object
     - ``{"kubernetes.io/os":"linux"}``
   * - :spelling:ignore:`clustermesh.apiserver.podAnnotations`
     - Annotations to be added to clustermesh-apiserver pods
     - object
     - ``{}``
   * - :spelling:ignore:`clustermesh.apiserver.podDisruptionBudget.enabled`
     - enable PodDisruptionBudget ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/
     - bool
     - ``false``
   * - :spelling:ignore:`clustermesh.apiserver.podDisruptionBudget.maxUnavailable`
     - Maximum number/percentage of pods that may be made unavailable
     - int
     - ``1``
   * - :spelling:ignore:`clustermesh.apiserver.podDisruptionBudget.minAvailable`
     - Minimum number/percentage of pods that should remain scheduled. When it's set, maxUnavailable must be disabled by ``maxUnavailable: null``
     - string
     - ``nil``
   * - :spelling:ignore:`clustermesh.apiserver.podLabels`
     - Labels to be added to clustermesh-apiserver pods
     - object
     - ``{}``
   * - :spelling:ignore:`clustermesh.apiserver.podSecurityContext`
     - Security context to be added to clustermesh-apiserver pods
     - object
     - ``{}``
   * - :spelling:ignore:`clustermesh.apiserver.priorityClassName`
     - The priority class to use for clustermesh-apiserver
     - string
     - ``""``
   * - :spelling:ignore:`clustermesh.apiserver.replicas`
     - Number of replicas run for the clustermesh-apiserver deployment.
     - int
     - ``1``
   * - :spelling:ignore:`clustermesh.apiserver.resources`
     - Resource requests and limits for the clustermesh-apiserver
     - object
     - ``{}``
   * - :spelling:ignore:`clustermesh.apiserver.securityContext`
     - Security context to be added to clustermesh-apiserver containers
     - object
     - ``{}``
   * - :spelling:ignore:`clustermesh.apiserver.service.annotations`
     - Annotations for the clustermesh-apiserver For GKE LoadBalancer, use annotation cloud.google.com/load-balancer-type: "Internal" For EKS LoadBalancer, use annotation service.beta.kubernetes.io/aws-load-balancer-internal: 0.0.0.0/0
     - object
     - ``{}``
   * - :spelling:ignore:`clustermesh.apiserver.service.nodePort`
     - Optional port to use as the node port for apiserver access.  WARNING: make sure to configure a different NodePort in each cluster if kube-proxy replacement is enabled, as Cilium is currently affected by a known bug (#24692) when NodePorts are handled by the KPR implementation. If a service with the same NodePort exists both in the local and the remote cluster, all traffic originating from inside the cluster and targeting the corresponding NodePort will be redirected to a local backend, regardless of whether the destination node belongs to the local or the remote cluster.
     - int
     - ``32379``
   * - :spelling:ignore:`clustermesh.apiserver.service.type`
     - The type of service used for apiserver access.
     - string
     - ``"NodePort"``
   * - :spelling:ignore:`clustermesh.apiserver.tls.admin`
     - base64 encoded PEM values for the clustermesh-apiserver admin certificate and private key. Used if 'auto' is not enabled.
     - object
     - ``{"cert":"","key":""}``
   * - :spelling:ignore:`clustermesh.apiserver.tls.auto`
     - Configure automatic TLS certificates generation. A Kubernetes CronJob is used the generate any certificates not provided by the user at installation time.
     - object
     - ``{"certManagerIssuerRef":{},"certValidityDuration":1095,"enabled":true,"method":"helm"}``
   * - :spelling:ignore:`clustermesh.apiserver.tls.auto.certManagerIssuerRef`
     - certmanager issuer used when clustermesh.apiserver.tls.auto.method=certmanager.
     - object
     - ``{}``
   * - :spelling:ignore:`clustermesh.apiserver.tls.auto.certValidityDuration`
     - Generated certificates validity duration in days.
     - int
     - ``1095``
   * - :spelling:ignore:`clustermesh.apiserver.tls.auto.enabled`
     - When set to true, automatically generate a CA and certificates to enable mTLS between clustermesh-apiserver and external workload instances. If set to false, the certs to be provided by setting appropriate values below.
     - bool
     - ``true``
   * - :spelling:ignore:`clustermesh.apiserver.tls.ca`
     - base64 encoded PEM values for the ExternalWorkload CA certificate and private key.
     - object
     - ``{"cert":"","key":""}``
   * - :spelling:ignore:`clustermesh.apiserver.tls.ca.cert`
     - Optional CA cert. If it is provided, it will be used by the 'cronJob' method to generate all other certificates. Otherwise, an ephemeral CA is generated.
     - string
     - ``""``
   * - :spelling:ignore:`clustermesh.apiserver.tls.ca.key`
     - Optional CA private key. If it is provided, it will be used by the 'cronJob' method to generate all other certificates. Otherwise, an ephemeral CA is generated.
     - string
     - ``""``
   * - :spelling:ignore:`clustermesh.apiserver.tls.client`
     - base64 encoded PEM values for the clustermesh-apiserver client certificate and private key. Used if 'auto' is not enabled.
     - object
     - ``{"cert":"","key":""}``
   * - :spelling:ignore:`clustermesh.apiserver.tls.remote`
     - base64 encoded PEM values for the clustermesh-apiserver remote cluster certificate and private key. Used if 'auto' is not enabled.
     - object
     - ``{"cert":"","key":""}``
   * - :spelling:ignore:`clustermesh.apiserver.tls.server`
     - base64 encoded PEM values for the clustermesh-apiserver server certificate and private key. Used if 'auto' is not enabled.
     - object
     - ``{"cert":"","extraDnsNames":[],"extraIpAddresses":[],"key":""}``
   * - :spelling:ignore:`clustermesh.apiserver.tls.server.extraDnsNames`
     - Extra DNS names added to certificate when it's auto generated
     - list
     - ``[]``
   * - :spelling:ignore:`clustermesh.apiserver.tls.server.extraIpAddresses`
     - Extra IP addresses added to certificate when it's auto generated
     - list
     - ``[]``
   * - :spelling:ignore:`clustermesh.apiserver.tolerations`
     - Node tolerations for pod assignment on nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
     - list
     - ``[]``
   * - :spelling:ignore:`clustermesh.apiserver.topologySpreadConstraints`
     - Pod topology spread constraints for clustermesh-apiserver
     - list
     - ``[]``
   * - :spelling:ignore:`clustermesh.apiserver.updateStrategy`
     - clustermesh-apiserver update strategy
     - object
     - ``{"rollingUpdate":{"maxUnavailable":1},"type":"RollingUpdate"}``
   * - :spelling:ignore:`clustermesh.config`
     - Clustermesh explicit configuration.
     - object
     - ``{"clusters":[],"domain":"mesh.cilium.io","enabled":false}``
   * - :spelling:ignore:`clustermesh.config.clusters`
     - List of clusters to be peered in the mesh.
     - list
     - ``[]``
   * - :spelling:ignore:`clustermesh.config.domain`
     - Default dns domain for the Clustermesh API servers This is used in the case cluster addresses are not provided and IPs are used.
     - string
     - ``"mesh.cilium.io"``
   * - :spelling:ignore:`clustermesh.config.enabled`
     - Enable the Clustermesh explicit configuration.
     - bool
     - ``false``
   * - :spelling:ignore:`clustermesh.useAPIServer`
     - Deploy clustermesh-apiserver for clustermesh
     - bool
     - ``false``
   * - :spelling:ignore:`cni.binPath`
     - Configure the path to the CNI binary directory on the host.
     - string
     - ``"/opt/cni/bin"``
   * - :spelling:ignore:`cni.chainingMode`
     - Configure chaining on top of other CNI plugins. Possible values:  - none  - aws-cni  - flannel  - generic-veth  - portmap
     - string
     - ``"none"``
   * - :spelling:ignore:`cni.confFileMountPath`
     - Configure the path to where to mount the ConfigMap inside the agent pod.
     - string
     - ``"/tmp/cni-configuration"``
   * - :spelling:ignore:`cni.confPath`
     - Configure the path to the CNI configuration directory on the host.
     - string
     - ``"/etc/cni/net.d"``
   * - :spelling:ignore:`cni.configMapKey`
     - Configure the key in the CNI ConfigMap to read the contents of the CNI configuration from.
     - string
     - ``"cni-config"``
   * - :spelling:ignore:`cni.customConf`
     - Skip writing of the CNI configuration. This can be used if writing of the CNI configuration is performed by external automation.
     - bool
     - ``false``
   * - :spelling:ignore:`cni.exclusive`
     - Make Cilium take ownership over the ``/etc/cni/net.d`` directory on the node, renaming all non-Cilium CNI configurations to ``*.cilium_bak``. This ensures no Pods can be scheduled using other CNI plugins during Cilium agent downtime.
     - bool
     - ``true``
   * - :spelling:ignore:`cni.hostConfDirMountPath`
     - Configure the path to where the CNI configuration directory is mounted inside the agent pod.
     - string
     - ``"/host/etc/cni/net.d"``
   * - :spelling:ignore:`cni.install`
     - Install the CNI configuration and binary files into the filesystem.
     - bool
     - ``true``
   * - :spelling:ignore:`cni.logFile`
     - Configure the log file for CNI logging with retention policy of 7 days. Disable CNI file logging by setting this field to empty explicitly.
     - string
     - ``"/var/run/cilium/cilium-cni.log"``
   * - :spelling:ignore:`cni.uninstall`
     - Remove the CNI configuration and binary files on agent shutdown. Enable this if you're removing Cilium from the cluster. Disable this to prevent the CNI configuration file from being removed during agent upgrade, which can cause nodes to go unmanageable.
     - bool
     - ``true``
   * - :spelling:ignore:`conntrackGCInterval`
     - Configure how frequently garbage collection should occur for the datapath connection tracking table.
     - string
     - ``"0s"``
   * - :spelling:ignore:`conntrackGCMaxInterval`
     - Configure the maximum frequency for the garbage collection of the connection tracking table. Only affects the automatic computation for the frequency and has no effect when 'conntrackGCInterval' is set. This can be set to more frequently clean up unused identities created from ToFQDN policies.
     - string
     - ``""``
   * - :spelling:ignore:`containerRuntime`
     - Configure container runtime specific integration.
     - object
     - ``{"integration":"none"}``
   * - :spelling:ignore:`containerRuntime.integration`
     - Enables specific integrations for container runtimes. Supported values: - containerd - crio - docker - none - auto (automatically detect the container runtime)
     - string
     - ``"none"``
   * - :spelling:ignore:`crdWaitTimeout`
     - Configure timeout in which Cilium will exit if CRDs are not available
     - string
     - ``"5m"``
   * - :spelling:ignore:`customCalls`
     - Tail call hooks for custom eBPF programs.
     - object
     - ``{"enabled":false}``
   * - :spelling:ignore:`customCalls.enabled`
     - Enable tail call hooks for custom eBPF programs.
     - bool
     - ``false``
   * - :spelling:ignore:`daemon.allowedConfigOverrides`
     - allowedConfigOverrides is a list of config-map keys that can be overridden. That is to say, if this value is set, config sources (excepting the first one) can only override keys in this list.  This takes precedence over blockedConfigOverrides.  By default, all keys may be overridden. To disable overrides, set this to "none" or change the configSources variable.
     - string
     - ``nil``
   * - :spelling:ignore:`daemon.blockedConfigOverrides`
     - blockedConfigOverrides is a list of config-map keys that may not be overridden. In other words, if any of these keys appear in a configuration source excepting the first one, they will be ignored  This is ignored if allowedConfigOverrides is set.  By default, all keys may be overridden.
     - string
     - ``nil``
   * - :spelling:ignore:`daemon.configSources`
     - Configure a custom list of possible configuration override sources The default is "config-map:cilium-config,cilium-node-config". For supported values, see the help text for the build-config subcommand. Note that this value should be a comma-separated string.
     - string
     - ``nil``
   * - :spelling:ignore:`daemon.runPath`
     - Configure where Cilium runtime state should be stored.
     - string
     - ``"/var/run/cilium"``
   * - :spelling:ignore:`debug.enabled`
     - Enable debug logging
     - bool
     - ``false``
   * - :spelling:ignore:`debug.verbose`
     - Configure verbosity levels for debug logging This option is used to enable debug messages for operations related to such sub-system such as (e.g. kvstore, envoy, datapath or policy), and flow is for enabling debug messages emitted per request, message and connection.  Applicable values: - flow - kvstore - envoy - datapath - policy
     - string
     - ``nil``
   * - :spelling:ignore:`disableEndpointCRD`
     - Disable the usage of CiliumEndpoint CRD.
     - string
     - ``"false"``
   * - :spelling:ignore:`dnsPolicy`
     - DNS policy for Cilium agent pods. Ref: https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pod-s-dns-policy
     - string
     - ``""``
   * - :spelling:ignore:`dnsProxy.dnsRejectResponseCode`
     - DNS response code for rejecting DNS requests, available options are '[nameError refused]'.
     - string
     - ``"refused"``
   * - :spelling:ignore:`dnsProxy.enableDnsCompression`
     - Allow the DNS proxy to compress responses to endpoints that are larger than 512 Bytes or the EDNS0 option, if present.
     - bool
     - ``true``
   * - :spelling:ignore:`dnsProxy.endpointMaxIpPerHostname`
     - Maximum number of IPs to maintain per FQDN name for each endpoint.
     - int
     - ``50``
   * - :spelling:ignore:`dnsProxy.idleConnectionGracePeriod`
     - Time during which idle but previously active connections with expired DNS lookups are still considered alive.
     - string
     - ``"0s"``
   * - :spelling:ignore:`dnsProxy.maxDeferredConnectionDeletes`
     - Maximum number of IPs to retain for expired DNS lookups with still-active connections.
     - int
     - ``10000``
   * - :spelling:ignore:`dnsProxy.minTtl`
     - The minimum time, in seconds, to use DNS data for toFQDNs policies.
     - int
     - ``3600``
   * - :spelling:ignore:`dnsProxy.preCache`
     - DNS cache data at this path is preloaded on agent startup.
     - string
     - ``""``
   * - :spelling:ignore:`dnsProxy.proxyPort`
     - Global port on which the in-agent DNS proxy should listen. Default 0 is a OS-assigned port.
     - int
     - ``0``
   * - :spelling:ignore:`dnsProxy.proxyResponseMaxDelay`
     - The maximum time the DNS proxy holds an allowed DNS response before sending it along. Responses are sent as soon as the datapath is updated with the new IP information.
     - string
     - ``"100ms"``
   * - :spelling:ignore:`dnsProxy.socketLingerTimeout`
     - Timeout (in seconds) when closing the connection between the DNS proxy and the upstream server. If set to 0, the connection is closed immediately (with TCP RST). If set to -1, the connection is closed asynchronously in the background.
     - int
     - ``10``
   * - :spelling:ignore:`egressGateway`
     - Enables egress gateway to redirect and SNAT the traffic that leaves the cluster.
     - object
     - ``{"enabled":false,"installRoutes":false}``
   * - :spelling:ignore:`egressGateway.installRoutes`
     - Install egress gateway IP rules and routes in order to properly steer egress gateway traffic to the correct ENI interface
     - bool
     - ``false``
   * - :spelling:ignore:`enableCiliumEndpointSlice`
     - Enable CiliumEndpointSlice feature.
     - bool
     - ``false``
   * - :spelling:ignore:`enableCnpStatusUpdates`
     - Whether to enable CNP status updates.
     - bool
     - ``false``
   * - :spelling:ignore:`enableCriticalPriorityClass`
     - Explicitly enable or disable priority class. .Capabilities.KubeVersion is unsettable in ``helm template`` calls, it depends on k8s libraries version that Helm was compiled against. This option allows to explicitly disable setting the priority class, which is useful for rendering charts for gke clusters in advance.
     - bool
     - ``true``
   * - :spelling:ignore:`enableIPv4Masquerade`
     - Enables masquerading of IPv4 traffic leaving the node from endpoints.
     - bool
     - ``true``
   * - :spelling:ignore:`enableIPv6BIGTCP`
     - Enables IPv6 BIG TCP support which increases maximum GSO/GRO limits for nodes and pods
     - bool
     - ``false``
   * - :spelling:ignore:`enableIPv6Masquerade`
     - Enables masquerading of IPv6 traffic leaving the node from endpoints.
     - bool
     - ``true``
   * - :spelling:ignore:`enableK8sEventHandover`
     - Configures the use of the KVStore to optimize Kubernetes event handling by mirroring it into the KVstore for reduced overhead in large clusters.
     - bool
     - ``false``
   * - :spelling:ignore:`enableK8sTerminatingEndpoint`
     - Configure whether to enable auto detect of terminating state for endpoints in order to support graceful termination.
     - bool
     - ``true``
   * - :spelling:ignore:`enableRuntimeDeviceDetection`
     - Enables experimental support for the detection of new and removed datapath devices. When devices change the eBPF datapath is reloaded and services updated. If "devices" is set then only those devices, or devices matching a wildcard will be considered.
     - bool
     - ``false``
   * - :spelling:ignore:`enableXTSocketFallback`
     - Enables the fallback compatibility solution for when the xt_socket kernel module is missing and it is needed for the datapath L7 redirection to work properly. See documentation for details on when this can be disabled: https://docs.cilium.io/en/stable/operations/system_requirements/#linux-kernel.
     - bool
     - ``true``
   * - :spelling:ignore:`encryption.enabled`
     - Enable transparent network encryption.
     - bool
     - ``false``
   * - :spelling:ignore:`encryption.interface`
     - Deprecated in favor of encryption.ipsec.interface. The interface to use for encrypted traffic. This option is only effective when encryption.type is set to ipsec.
     - string
     - ``""``
   * - :spelling:ignore:`encryption.ipsec.interface`
     - The interface to use for encrypted traffic.
     - string
     - ``""``
   * - :spelling:ignore:`encryption.ipsec.keyFile`
     - Name of the key file inside the Kubernetes secret configured via secretName.
     - string
     - ``""``
   * - :spelling:ignore:`encryption.ipsec.keyWatcher`
     - Enable the key watcher. If disabled, a restart of the agent will be necessary on key rotations.
     - bool
     - ``true``
   * - :spelling:ignore:`encryption.ipsec.mountPath`
     - Path to mount the secret inside the Cilium pod.
     - string
     - ``""``
   * - :spelling:ignore:`encryption.ipsec.secretName`
     - Name of the Kubernetes secret containing the encryption keys.
     - string
     - ``""``
   * - :spelling:ignore:`encryption.keyFile`
     - Deprecated in favor of encryption.ipsec.keyFile. Name of the key file inside the Kubernetes secret configured via secretName. This option is only effective when encryption.type is set to ipsec.
     - string
     - ``"keys"``
   * - :spelling:ignore:`encryption.mountPath`
     - Deprecated in favor of encryption.ipsec.mountPath. Path to mount the secret inside the Cilium pod. This option is only effective when encryption.type is set to ipsec.
     - string
     - ``"/etc/ipsec"``
   * - :spelling:ignore:`encryption.nodeEncryption`
     - Enable encryption for pure node to node traffic. This option is only effective when encryption.type is set to ipsec.
     - bool
     - ``false``
   * - :spelling:ignore:`encryption.secretName`
     - Deprecated in favor of encryption.ipsec.secretName. Name of the Kubernetes secret containing the encryption keys. This option is only effective when encryption.type is set to ipsec.
     - string
     - ``"cilium-ipsec-keys"``
   * - :spelling:ignore:`encryption.type`
     - Encryption method. Can be either ipsec or wireguard.
     - string
     - ``"ipsec"``
   * - :spelling:ignore:`encryption.wireguard.userspaceFallback`
     - Enables the fallback to the user-space implementation.
     - bool
     - ``false``
   * - :spelling:ignore:`endpointHealthChecking.enabled`
     - Enable connectivity health checking between virtual endpoints.
     - bool
     - ``true``
   * - :spelling:ignore:`endpointRoutes.enabled`
     - Enable use of per endpoint routes instead of routing via the cilium_host interface.
     - bool
     - ``false``
   * - :spelling:ignore:`endpointStatus`
     - Enable endpoint status. Status can be: policy, health, controllers, log and / or state. For 2 or more options use a space.
     - object
     - ``{"enabled":false,"status":""}``
   * - :spelling:ignore:`eni.awsEnablePrefixDelegation`
     - Enable ENI prefix delegation
     - bool
     - ``false``
   * - :spelling:ignore:`eni.awsReleaseExcessIPs`
     - Release IPs not used from the ENI
     - bool
     - ``false``
   * - :spelling:ignore:`eni.ec2APIEndpoint`
     - EC2 API endpoint to use
     - string
     - ``""``
   * - :spelling:ignore:`eni.enabled`
     - Enable Elastic Network Interface (ENI) integration.
     - bool
     - ``false``
   * - :spelling:ignore:`eni.eniTags`
     - Tags to apply to the newly created ENIs
     - object
     - ``{}``
   * - :spelling:ignore:`eni.gcInterval`
     - Interval for garbage collection of unattached ENIs. Set to "0s" to disable.
     - string
     - ``"5m"``
   * - :spelling:ignore:`eni.gcTags`
     - Additional tags attached to ENIs created by Cilium. Dangling ENIs with this tag will be garbage collected
     - object
     - ``{"io.cilium/cilium-managed":"true,"io.cilium/cluster-name":"<auto-detected>"}``
   * - :spelling:ignore:`eni.iamRole`
     - If using IAM role for Service Accounts will not try to inject identity values from cilium-aws kubernetes secret. Adds annotation to service account if managed by Helm. See https://github.com/aws/amazon-eks-pod-identity-webhook
     - string
     - ``""``
   * - :spelling:ignore:`eni.instanceTagsFilter`
     - Filter via AWS EC2 Instance tags (k=v) which will dictate which AWS EC2 Instances are going to be used to create new ENIs
     - list
     - ``[]``
   * - :spelling:ignore:`eni.subnetIDsFilter`
     - Filter via subnet IDs which will dictate which subnets are going to be used to create new ENIs Important note: This requires that each instance has an ENI with a matching subnet attached when Cilium is deployed. If you only want to control subnets for ENIs attached by Cilium, use the CNI configuration file settings (cni.customConf) instead.
     - list
     - ``[]``
   * - :spelling:ignore:`eni.subnetTagsFilter`
     - Filter via tags (k=v) which will dictate which subnets are going to be used to create new ENIs Important note: This requires that each instance has an ENI with a matching subnet attached when Cilium is deployed. If you only want to control subnets for ENIs attached by Cilium, use the CNI configuration file settings (cni.customConf) instead.
     - list
     - ``[]``
   * - :spelling:ignore:`eni.updateEC2AdapterLimitViaAPI`
     - Update ENI Adapter limits from the EC2 API
     - bool
     - ``false``
   * - :spelling:ignore:`envoyConfig.enabled`
     - Enable CiliumEnvoyConfig CRD CiliumEnvoyConfig CRD can also be implicitly enabled by other options.
     - bool
     - ``false``
   * - :spelling:ignore:`envoyConfig.secretsNamespace`
     - SecretsNamespace is the namespace in which envoy SDS will retrieve secrets from.
     - object
     - ``{"create":true,"name":"cilium-secrets"}``
   * - :spelling:ignore:`envoyConfig.secretsNamespace.create`
     - Create secrets namespace for CiliumEnvoyConfig CRDs.
     - bool
     - ``true``
   * - :spelling:ignore:`envoyConfig.secretsNamespace.name`
     - Name of secret namespace which Cilium agents are given read access to.
     - string
     - ``"cilium-secrets"``
   * - :spelling:ignore:`etcd.clusterDomain`
     - Cluster domain for cilium-etcd-operator.
     - string
     - ``"cluster.local"``
   * - :spelling:ignore:`etcd.enabled`
     - Enable etcd mode for the agent.
     - bool
     - ``false``
   * - :spelling:ignore:`etcd.endpoints`
     - List of etcd endpoints (not needed when using managed=true).
     - list
     - ``["https://CHANGE-ME:2379"]``
   * - :spelling:ignore:`etcd.extraArgs`
     - Additional cilium-etcd-operator container arguments.
     - list
     - ``[]``
   * - :spelling:ignore:`etcd.extraVolumeMounts`
     - Additional cilium-etcd-operator volumeMounts.
     - list
     - ``[]``
   * - :spelling:ignore:`etcd.extraVolumes`
     - Additional cilium-etcd-operator volumes.
     - list
     - ``[]``
   * - :spelling:ignore:`etcd.image`
     - cilium-etcd-operator image.
     - object
     - ``{"override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/cilium-etcd-operator","tag":"v2.0.7@sha256:04b8327f7f992693c2cb483b999041ed8f92efc8e14f2a5f3ab95574a65ea2dc"}``
   * - :spelling:ignore:`etcd.k8sService`
     - If etcd is behind a k8s service set this option to true so that Cilium does the service translation automatically without requiring a DNS to be running.
     - bool
     - ``false``
   * - :spelling:ignore:`etcd.nodeSelector`
     - Node labels for cilium-etcd-operator pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector
     - object
     - ``{"kubernetes.io/os":"linux"}``
   * - :spelling:ignore:`etcd.podAnnotations`
     - Annotations to be added to cilium-etcd-operator pods
     - object
     - ``{}``
   * - :spelling:ignore:`etcd.podDisruptionBudget.enabled`
     - enable PodDisruptionBudget ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/
     - bool
     - ``false``
   * - :spelling:ignore:`etcd.podDisruptionBudget.maxUnavailable`
     - Maximum number/percentage of pods that may be made unavailable
     - int
     - ``1``
   * - :spelling:ignore:`etcd.podDisruptionBudget.minAvailable`
     - Minimum number/percentage of pods that should remain scheduled. When it's set, maxUnavailable must be disabled by ``maxUnavailable: null``
     - string
     - ``nil``
   * - :spelling:ignore:`etcd.podLabels`
     - Labels to be added to cilium-etcd-operator pods
     - object
     - ``{}``
   * - :spelling:ignore:`etcd.podSecurityContext`
     - Security context to be added to cilium-etcd-operator pods
     - object
     - ``{}``
   * - :spelling:ignore:`etcd.priorityClassName`
     - The priority class to use for cilium-etcd-operator
     - string
     - ``""``
   * - :spelling:ignore:`etcd.resources`
     - cilium-etcd-operator resource limits & requests ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
     - object
     - ``{}``
   * - :spelling:ignore:`etcd.securityContext`
     - Security context to be added to cilium-etcd-operator pods
     - object
     - ``{}``
   * - :spelling:ignore:`etcd.ssl`
     - Enable use of TLS/SSL for connectivity to etcd. (auto-enabled if managed=true)
     - bool
     - ``false``
   * - :spelling:ignore:`etcd.tolerations`
     - Node tolerations for cilium-etcd-operator scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
     - list
     - ``[{"operator":"Exists"}]``
   * - :spelling:ignore:`etcd.topologySpreadConstraints`
     - Pod topology spread constraints for cilium-etcd-operator
     - list
     - ``[]``
   * - :spelling:ignore:`etcd.updateStrategy`
     - cilium-etcd-operator update strategy
     - object
     - ``{"rollingUpdate":{"maxSurge":1,"maxUnavailable":1},"type":"RollingUpdate"}``
   * - :spelling:ignore:`externalIPs.enabled`
     - Enable ExternalIPs service support.
     - bool
     - ``false``
   * - :spelling:ignore:`externalWorkloads`
     - Configure external workloads support
     - object
     - ``{"enabled":false}``
   * - :spelling:ignore:`externalWorkloads.enabled`
     - Enable support for external workloads, such as VMs (false by default).
     - bool
     - ``false``
   * - :spelling:ignore:`extraArgs`
     - Additional agent container arguments.
     - list
     - ``[]``
   * - :spelling:ignore:`extraConfig`
     - extraConfig allows you to specify additional configuration parameters to be included in the cilium-config configmap.
     - object
     - ``{}``
   * - :spelling:ignore:`extraContainers`
     - Additional containers added to the cilium DaemonSet.
     - list
     - ``[]``
   * - :spelling:ignore:`extraEnv`
     - Additional agent container environment variables.
     - list
     - ``[]``
   * - :spelling:ignore:`extraHostPathMounts`
     - Additional agent hostPath mounts.
     - list
     - ``[]``
   * - :spelling:ignore:`extraVolumeMounts`
     - Additional agent volumeMounts.
     - list
     - ``[]``
   * - :spelling:ignore:`extraVolumes`
     - Additional agent volumes.
     - list
     - ``[]``
   * - :spelling:ignore:`gatewayAPI.enabled`
     - Enable support for Gateway API in cilium This will automatically set enable-envoy-config as well.
     - bool
     - ``false``
   * - :spelling:ignore:`gatewayAPI.secretsNamespace`
     - SecretsNamespace is the namespace in which envoy SDS will retrieve TLS secrets from.
     - object
     - ``{"create":true,"name":"cilium-secrets","sync":true}``
   * - :spelling:ignore:`gatewayAPI.secretsNamespace.create`
     - Create secrets namespace for Gateway API.
     - bool
     - ``true``
   * - :spelling:ignore:`gatewayAPI.secretsNamespace.name`
     - Name of Gateway API secret namespace.
     - string
     - ``"cilium-secrets"``
   * - :spelling:ignore:`gatewayAPI.secretsNamespace.sync`
     - Enable secret sync, which will make sure all TLS secrets used by Ingress are synced to secretsNamespace.name. If disabled, TLS secrets must be maintained externally.
     - bool
     - ``true``
   * - :spelling:ignore:`gke.enabled`
     - Enable Google Kubernetes Engine integration
     - bool
     - ``false``
   * - :spelling:ignore:`healthChecking`
     - Enable connectivity health checking.
     - bool
     - ``true``
   * - :spelling:ignore:`healthPort`
     - TCP port for the agent health API. This is not the port for cilium-health.
     - int
     - ``9879``
   * - :spelling:ignore:`hostFirewall`
     - Configure the host firewall.
     - object
     - ``{"enabled":false}``
   * - :spelling:ignore:`hostFirewall.enabled`
     - Enables the enforcement of host policies in the eBPF datapath.
     - bool
     - ``false``
   * - :spelling:ignore:`hostPort.enabled`
     - Enable hostPort service support.
     - bool
     - ``false``
   * - :spelling:ignore:`hubble.enabled`
     - Enable Hubble (true by default).
     - bool
     - ``true``
   * - :spelling:ignore:`hubble.listenAddress`
     - An additional address for Hubble to listen to. Set this field ":4244" if you are enabling Hubble Relay, as it assumes that Hubble is listening on port 4244.
     - string
     - ``":4244"``
   * - :spelling:ignore:`hubble.metrics`
     - Hubble metrics configuration. See https://docs.cilium.io/en/stable/observability/metrics/#hubble-metrics for more comprehensive documentation about Hubble metrics.
     - object
     - ``{"dashboards":{"annotations":{},"enabled":false,"label":"grafana_dashboard","labelValue":"1","namespace":null},"enableOpenMetrics":false,"enabled":null,"port":9965,"serviceAnnotations":{},"serviceMonitor":{"annotations":{},"enabled":false,"interval":"10s","labels":{},"metricRelabelings":null,"relabelings":[{"replacement":"${1}","sourceLabels":["__meta_kubernetes_pod_node_name"],"targetLabel":"node"}]}}``
   * - :spelling:ignore:`hubble.metrics.enableOpenMetrics`
     - Enables exporting hubble metrics in OpenMetrics format.
     - bool
     - ``false``
   * - :spelling:ignore:`hubble.metrics.enabled`
     - Configures the list of metrics to collect. If empty or null, metrics are disabled. Example:    enabled:   - dns:query;ignoreAAAA   - drop   - tcp   - flow   - icmp   - http  You can specify the list of metrics from the helm CLI:    --set metrics.enabled="{dns:query;ignoreAAAA,drop,tcp,flow,icmp,http}"
     - string
     - ``nil``
   * - :spelling:ignore:`hubble.metrics.port`
     - Configure the port the hubble metric server listens on.
     - int
     - ``9965``
   * - :spelling:ignore:`hubble.metrics.serviceAnnotations`
     - Annotations to be added to hubble-metrics service.
     - object
     - ``{}``
   * - :spelling:ignore:`hubble.metrics.serviceMonitor.annotations`
     - Annotations to add to ServiceMonitor hubble
     - object
     - ``{}``
   * - :spelling:ignore:`hubble.metrics.serviceMonitor.enabled`
     - Create ServiceMonitor resources for Prometheus Operator. This requires the prometheus CRDs to be available. ref: https://github.com/prometheus-operator/prometheus-operator/blob/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml)
     - bool
     - ``false``
   * - :spelling:ignore:`hubble.metrics.serviceMonitor.interval`
     - Interval for scrape metrics.
     - string
     - ``"10s"``
   * - :spelling:ignore:`hubble.metrics.serviceMonitor.labels`
     - Labels to add to ServiceMonitor hubble
     - object
     - ``{}``
   * - :spelling:ignore:`hubble.metrics.serviceMonitor.metricRelabelings`
     - Metrics relabeling configs for the ServiceMonitor hubble
     - string
     - ``nil``
   * - :spelling:ignore:`hubble.metrics.serviceMonitor.relabelings`
     - Relabeling configs for the ServiceMonitor hubble
     - list
     - ``[{"replacement":"${1}","sourceLabels":["__meta_kubernetes_pod_node_name"],"targetLabel":"node"}]``
   * - :spelling:ignore:`hubble.peerService.clusterDomain`
     - The cluster domain to use to query the Hubble Peer service. It should be the local cluster.
     - string
     - ``"cluster.local"``
   * - :spelling:ignore:`hubble.peerService.enabled`
     - Enable a K8s Service for the Peer service, so that it can be accessed by a non-local client. This configuration option is deprecated, the peer service will be non-optional starting Cilium v1.14.
     - bool
     - ``true``
   * - :spelling:ignore:`hubble.peerService.targetPort`
     - Target Port for the Peer service, must match the hubble.listenAddress' port.
     - int
     - ``4244``
   * - :spelling:ignore:`hubble.preferIpv6`
     - Whether Hubble should prefer to announce IPv6 or IPv4 addresses if both are available.
     - bool
     - ``false``
   * - :spelling:ignore:`hubble.relay.affinity`
     - Affinity for hubble-replay
     - object
     - ``{"podAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"k8s-app":"cilium"}},"topologyKey":"kubernetes.io/hostname"}]}}``
   * - :spelling:ignore:`hubble.relay.dialTimeout`
     - Dial timeout to connect to the local hubble instance to receive peer information (e.g. "30s").
     - string
     - ``nil``
   * - :spelling:ignore:`hubble.relay.enabled`
     - Enable Hubble Relay (requires hubble.enabled=true)
     - bool
     - ``false``
   * - :spelling:ignore:`hubble.relay.extraEnv`
     - Additional hubble-relay environment variables.
     - list
     - ``[]``
   * - :spelling:ignore:`hubble.relay.extraVolumeMounts`
     - Additional hubble-relay volumeMounts.
     - list
     - ``[]``
   * - :spelling:ignore:`hubble.relay.extraVolumes`
     - Additional hubble-relay volumes.
     - list
     - ``[]``
   * - :spelling:ignore:`hubble.relay.image`
     - Hubble-relay container image.
     - object
     - ``{"digest":"sha256:220ac4b70ffb5ecf598af1024dc0997affdf86f2e4c1a12f5aa9ede490cd181d","override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/hubble-relay","tag":"v1.13.18","useDigest":true}``
   * - :spelling:ignore:`hubble.relay.listenHost`
     - Host to listen to. Specify an empty string to bind to all the interfaces.
     - string
     - ``""``
   * - :spelling:ignore:`hubble.relay.listenPort`
     - Port to listen to.
     - string
     - ``"4245"``
   * - :spelling:ignore:`hubble.relay.nodeSelector`
     - Node labels for pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector
     - object
     - ``{"kubernetes.io/os":"linux"}``
   * - :spelling:ignore:`hubble.relay.podAnnotations`
     - Annotations to be added to hubble-relay pods
     - object
     - ``{}``
   * - :spelling:ignore:`hubble.relay.podDisruptionBudget.enabled`
     - enable PodDisruptionBudget ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/
     - bool
     - ``false``
   * - :spelling:ignore:`hubble.relay.podDisruptionBudget.maxUnavailable`
     - Maximum number/percentage of pods that may be made unavailable
     - int
     - ``1``
   * - :spelling:ignore:`hubble.relay.podDisruptionBudget.minAvailable`
     - Minimum number/percentage of pods that should remain scheduled. When it's set, maxUnavailable must be disabled by ``maxUnavailable: null``
     - string
     - ``nil``
   * - :spelling:ignore:`hubble.relay.podLabels`
     - Labels to be added to hubble-relay pods
     - object
     - ``{}``
   * - :spelling:ignore:`hubble.relay.pprof.address`
     - Configure pprof listen address for hubble-relay
     - string
     - ``"localhost"``
   * - :spelling:ignore:`hubble.relay.pprof.enabled`
     - Enable pprof for hubble-relay
     - bool
     - ``false``
   * - :spelling:ignore:`hubble.relay.pprof.port`
     - Configure pprof listen port for hubble-relay
     - int
     - ``6062``
   * - :spelling:ignore:`hubble.relay.priorityClassName`
     - The priority class to use for hubble-relay
     - string
     - ``""``
   * - :spelling:ignore:`hubble.relay.prometheus`
     - Enable prometheus metrics for hubble-relay on the configured port at /metrics
     - object
     - ``{"enabled":false,"port":9966,"serviceMonitor":{"annotations":{},"enabled":false,"interval":"10s","labels":{},"metricRelabelings":null,"relabelings":null}}``
   * - :spelling:ignore:`hubble.relay.prometheus.serviceMonitor.annotations`
     - Annotations to add to ServiceMonitor hubble-relay
     - object
     - ``{}``
   * - :spelling:ignore:`hubble.relay.prometheus.serviceMonitor.enabled`
     - Enable service monitors. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml)
     - bool
     - ``false``
   * - :spelling:ignore:`hubble.relay.prometheus.serviceMonitor.interval`
     - Interval for scrape metrics.
     - string
     - ``"10s"``
   * - :spelling:ignore:`hubble.relay.prometheus.serviceMonitor.labels`
     - Labels to add to ServiceMonitor hubble-relay
     - object
     - ``{}``
   * - :spelling:ignore:`hubble.relay.prometheus.serviceMonitor.metricRelabelings`
     - Metrics relabeling configs for the ServiceMonitor hubble-relay
     - string
     - ``nil``
   * - :spelling:ignore:`hubble.relay.prometheus.serviceMonitor.relabelings`
     - Relabeling configs for the ServiceMonitor hubble-relay
     - string
     - ``nil``
   * - :spelling:ignore:`hubble.relay.replicas`
     - Number of replicas run for the hubble-relay deployment.
     - int
     - ``1``
   * - :spelling:ignore:`hubble.relay.resources`
     - Specifies the resources for the hubble-relay pods
     - object
     - ``{}``
   * - :spelling:ignore:`hubble.relay.retryTimeout`
     - Backoff duration to retry connecting to the local hubble instance in case of failure (e.g. "30s").
     - string
     - ``nil``
   * - :spelling:ignore:`hubble.relay.rollOutPods`
     - Roll out Hubble Relay pods automatically when configmap is updated.
     - bool
     - ``false``
   * - :spelling:ignore:`hubble.relay.securityContext`
     - hubble-relay security context
     - object
     - ``{}``
   * - :spelling:ignore:`hubble.relay.service`
     - hubble-relay service configuration.
     - object
     - ``{"nodePort":31234,"type":"ClusterIP"}``
   * - :spelling:ignore:`hubble.relay.service.nodePort`
     - - The port to use when the service type is set to NodePort.
     - int
     - ``31234``
   * - :spelling:ignore:`hubble.relay.service.type`
     - - The type of service used for Hubble Relay access, either ClusterIP or NodePort.
     - string
     - ``"ClusterIP"``
   * - :spelling:ignore:`hubble.relay.sortBufferDrainTimeout`
     - When the per-request flows sort buffer is not full, a flow is drained every time this timeout is reached (only affects requests in follow-mode) (e.g. "1s").
     - string
     - ``nil``
   * - :spelling:ignore:`hubble.relay.sortBufferLenMax`
     - Max number of flows that can be buffered for sorting before being sent to the client (per request) (e.g. 100).
     - string
     - ``nil``
   * - :spelling:ignore:`hubble.relay.terminationGracePeriodSeconds`
     - Configure termination grace period for hubble relay Deployment.
     - int
     - ``1``
   * - :spelling:ignore:`hubble.relay.tls`
     - TLS configuration for Hubble Relay
     - object
     - ``{"client":{"cert":"","key":""},"server":{"cert":"","enabled":false,"extraDnsNames":[],"extraIpAddresses":[],"key":""}}``
   * - :spelling:ignore:`hubble.relay.tls.client`
     - base64 encoded PEM values for the hubble-relay client certificate and private key This keypair is presented to Hubble server instances for mTLS authentication and is required when hubble.tls.enabled is true. These values need to be set manually if hubble.tls.auto.enabled is false.
     - object
     - ``{"cert":"","key":""}``
   * - :spelling:ignore:`hubble.relay.tls.server`
     - base64 encoded PEM values for the hubble-relay server certificate and private key
     - object
     - ``{"cert":"","enabled":false,"extraDnsNames":[],"extraIpAddresses":[],"key":""}``
   * - :spelling:ignore:`hubble.relay.tls.server.extraDnsNames`
     - extra DNS names added to certificate when its auto gen
     - list
     - ``[]``
   * - :spelling:ignore:`hubble.relay.tls.server.extraIpAddresses`
     - extra IP addresses added to certificate when its auto gen
     - list
     - ``[]``
   * - :spelling:ignore:`hubble.relay.tolerations`
     - Node tolerations for pod assignment on nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
     - list
     - ``[]``
   * - :spelling:ignore:`hubble.relay.topologySpreadConstraints`
     - Pod topology spread constraints for hubble-relay
     - list
     - ``[]``
   * - :spelling:ignore:`hubble.relay.updateStrategy`
     - hubble-relay update strategy
     - object
     - ``{"rollingUpdate":{"maxUnavailable":1},"type":"RollingUpdate"}``
   * - :spelling:ignore:`hubble.skipUnknownCGroupIDs`
     - Skip Hubble events with unknown cgroup ids
     - bool
     - ``true``
   * - :spelling:ignore:`hubble.socketPath`
     - Unix domain socket path to listen to when Hubble is enabled.
     - string
     - ``"/var/run/cilium/hubble.sock"``
   * - :spelling:ignore:`hubble.tls`
     - TLS configuration for Hubble
     - object
     - ``{"auto":{"certManagerIssuerRef":{},"certValidityDuration":1095,"enabled":true,"method":"helm","schedule":"0 0 1 */4 *"},"ca":{"cert":"","key":""},"enabled":true,"server":{"cert":"","extraDnsNames":[],"extraIpAddresses":[],"key":""}}``
   * - :spelling:ignore:`hubble.tls.auto`
     - Configure automatic TLS certificates generation.
     - object
     - ``{"certManagerIssuerRef":{},"certValidityDuration":1095,"enabled":true,"method":"helm","schedule":"0 0 1 */4 *"}``
   * - :spelling:ignore:`hubble.tls.auto.certManagerIssuerRef`
     - certmanager issuer used when hubble.tls.auto.method=certmanager.
     - object
     - ``{}``
   * - :spelling:ignore:`hubble.tls.auto.certValidityDuration`
     - Generated certificates validity duration in days.
     - int
     - ``1095``
   * - :spelling:ignore:`hubble.tls.auto.enabled`
     - Auto-generate certificates. When set to true, automatically generate a CA and certificates to enable mTLS between Hubble server and Hubble Relay instances. If set to false, the certs for Hubble server need to be provided by setting appropriate values below.
     - bool
     - ``true``
   * - :spelling:ignore:`hubble.tls.auto.method`
     - Set the method to auto-generate certificates. Supported values: - helm:         This method uses Helm to generate all certificates. - cronJob:      This method uses a Kubernetes CronJob the generate any                 certificates not provided by the user at installation                 time. - certmanager:  This method use cert-manager to generate & rotate certificates.
     - string
     - ``"helm"``
   * - :spelling:ignore:`hubble.tls.auto.schedule`
     - Schedule for certificates regeneration (regardless of their expiration date). Only used if method is "cronJob". If nil, then no recurring job will be created. Instead, only the one-shot job is deployed to generate the certificates at installation time.  Defaults to midnight of the first day of every fourth month. For syntax, see https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/#schedule-syntax
     - string
     - ``"0 0 1 */4 *"``
   * - :spelling:ignore:`hubble.tls.ca`
     - Deprecated in favor of tls.ca. To be removed in 1.13. base64 encoded PEM values for the Hubble CA certificate and private key.
     - object
     - ``{"cert":"","key":""}``
   * - :spelling:ignore:`hubble.tls.ca.cert`
     - Deprecated in favor of tls.ca.cert. To be removed in 1.13.
     - string
     - ``""``
   * - :spelling:ignore:`hubble.tls.ca.key`
     - Deprecated in favor of tls.ca.key. To be removed in 1.13. The CA private key (optional). If it is provided, then it will be used by hubble.tls.auto.method=cronJob to generate all other certificates. Otherwise, a ephemeral CA is generated if hubble.tls.auto.enabled=true.
     - string
     - ``""``
   * - :spelling:ignore:`hubble.tls.enabled`
     - Enable mutual TLS for listenAddress. Setting this value to false is highly discouraged as the Hubble API provides access to potentially sensitive network flow metadata and is exposed on the host network.
     - bool
     - ``true``
   * - :spelling:ignore:`hubble.tls.server`
     - base64 encoded PEM values for the Hubble server certificate and private key
     - object
     - ``{"cert":"","extraDnsNames":[],"extraIpAddresses":[],"key":""}``
   * - :spelling:ignore:`hubble.tls.server.extraDnsNames`
     - Extra DNS names added to certificate when it's auto generated
     - list
     - ``[]``
   * - :spelling:ignore:`hubble.tls.server.extraIpAddresses`
     - Extra IP addresses added to certificate when it's auto generated
     - list
     - ``[]``
   * - :spelling:ignore:`hubble.ui.affinity`
     - Affinity for hubble-ui
     - object
     - ``{}``
   * - :spelling:ignore:`hubble.ui.backend.extraEnv`
     - Additional hubble-ui backend environment variables.
     - list
     - ``[]``
   * - :spelling:ignore:`hubble.ui.backend.extraVolumeMounts`
     - Additional hubble-ui backend volumeMounts.
     - list
     - ``[]``
   * - :spelling:ignore:`hubble.ui.backend.extraVolumes`
     - Additional hubble-ui backend volumes.
     - list
     - ``[]``
   * - :spelling:ignore:`hubble.ui.backend.image`
     - Hubble-ui backend image.
     - object
     - ``{"override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/hubble-ui-backend","tag":"v0.13.1@sha256:0e0eed917653441fded4e7cdb096b7be6a3bddded5a2dd10812a27b1fc6ed95b"}``
   * - :spelling:ignore:`hubble.ui.backend.resources`
     - Resource requests and limits for the 'backend' container of the 'hubble-ui' deployment.
     - object
     - ``{}``
   * - :spelling:ignore:`hubble.ui.backend.securityContext`
     - Hubble-ui backend security context.
     - object
     - ``{}``
   * - :spelling:ignore:`hubble.ui.baseUrl`
     - Defines base url prefix for all hubble-ui http requests. It needs to be changed in case if ingress for hubble-ui is configured under some sub-path. Trailing ``/`` is required for custom path, ex. ``/service-map/``
     - string
     - ``"/"``
   * - :spelling:ignore:`hubble.ui.enabled`
     - Whether to enable the Hubble UI.
     - bool
     - ``false``
   * - :spelling:ignore:`hubble.ui.frontend.extraEnv`
     - Additional hubble-ui frontend environment variables.
     - list
     - ``[]``
   * - :spelling:ignore:`hubble.ui.frontend.extraVolumeMounts`
     - Additional hubble-ui frontend volumeMounts.
     - list
     - ``[]``
   * - :spelling:ignore:`hubble.ui.frontend.extraVolumes`
     - Additional hubble-ui frontend volumes.
     - list
     - ``[]``
   * - :spelling:ignore:`hubble.ui.frontend.image`
     - Hubble-ui frontend image.
     - object
     - ``{"override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/hubble-ui","tag":"v0.13.1@sha256:e2e9313eb7caf64b0061d9da0efbdad59c6c461f6ca1752768942bfeda0796c6"}``
   * - :spelling:ignore:`hubble.ui.frontend.resources`
     - Resource requests and limits for the 'frontend' container of the 'hubble-ui' deployment.
     - object
     - ``{}``
   * - :spelling:ignore:`hubble.ui.frontend.securityContext`
     - Hubble-ui frontend security context.
     - object
     - ``{}``
   * - :spelling:ignore:`hubble.ui.frontend.server.ipv6`
     - Controls server listener for ipv6
     - object
     - ``{"enabled":true}``
   * - :spelling:ignore:`hubble.ui.ingress`
     - hubble-ui ingress configuration.
     - object
     - ``{"annotations":{},"className":"","enabled":false,"hosts":["chart-example.local"],"tls":[]}``
   * - :spelling:ignore:`hubble.ui.nodeSelector`
     - Node labels for pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector
     - object
     - ``{"kubernetes.io/os":"linux"}``
   * - :spelling:ignore:`hubble.ui.podAnnotations`
     - Annotations to be added to hubble-ui pods
     - object
     - ``{}``
   * - :spelling:ignore:`hubble.ui.podDisruptionBudget.enabled`
     - enable PodDisruptionBudget ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/
     - bool
     - ``false``
   * - :spelling:ignore:`hubble.ui.podDisruptionBudget.maxUnavailable`
     - Maximum number/percentage of pods that may be made unavailable
     - int
     - ``1``
   * - :spelling:ignore:`hubble.ui.podDisruptionBudget.minAvailable`
     - Minimum number/percentage of pods that should remain scheduled. When it's set, maxUnavailable must be disabled by ``maxUnavailable: null``
     - string
     - ``nil``
   * - :spelling:ignore:`hubble.ui.podLabels`
     - Labels to be added to hubble-ui pods
     - object
     - ``{}``
   * - :spelling:ignore:`hubble.ui.priorityClassName`
     - The priority class to use for hubble-ui
     - string
     - ``""``
   * - :spelling:ignore:`hubble.ui.replicas`
     - The number of replicas of Hubble UI to deploy.
     - int
     - ``1``
   * - :spelling:ignore:`hubble.ui.rollOutPods`
     - Roll out Hubble-ui pods automatically when configmap is updated.
     - bool
     - ``false``
   * - :spelling:ignore:`hubble.ui.securityContext`
     - Security context to be added to Hubble UI pods
     - object
     - ``{"enabled":true,"fsGroup":1001,"runAsGroup":1001,"runAsUser":1001}``
   * - :spelling:ignore:`hubble.ui.securityContext.enabled`
     - Deprecated in favor of hubble.ui.securityContext. Whether to set the security context on the Hubble UI pods.
     - bool
     - ``true``
   * - :spelling:ignore:`hubble.ui.service`
     - hubble-ui service configuration.
     - object
     - ``{"annotations":{},"nodePort":31235,"type":"ClusterIP"}``
   * - :spelling:ignore:`hubble.ui.service.annotations`
     - Annotations to be added for the Hubble UI service
     - object
     - ``{}``
   * - :spelling:ignore:`hubble.ui.service.nodePort`
     - - The port to use when the service type is set to NodePort.
     - int
     - ``31235``
   * - :spelling:ignore:`hubble.ui.service.type`
     - - The type of service used for Hubble UI access, either ClusterIP or NodePort.
     - string
     - ``"ClusterIP"``
   * - :spelling:ignore:`hubble.ui.standalone.enabled`
     - When true, it will allow installing the Hubble UI only, without checking dependencies. It is useful if a cluster already has cilium and Hubble relay installed and you just want Hubble UI to be deployed. When installed via helm, installing UI should be done via ``helm upgrade`` and when installed via the cilium cli, then ``cilium hubble enable --ui``
     - bool
     - ``false``
   * - :spelling:ignore:`hubble.ui.standalone.tls.certsVolume`
     - When deploying Hubble UI in standalone, with tls enabled for Hubble relay, it is required to provide a volume for mounting the client certificates.
     - object
     - ``{}``
   * - :spelling:ignore:`hubble.ui.tls.client`
     - base64 encoded PEM values used to connect to hubble-relay This keypair is presented to Hubble Relay instances for mTLS authentication and is required when hubble.relay.tls.server.enabled is true. These values need to be set manually if hubble.tls.auto.enabled is false.
     - object
     - ``{"cert":"","key":""}``
   * - :spelling:ignore:`hubble.ui.tolerations`
     - Node tolerations for pod assignment on nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
     - list
     - ``[]``
   * - :spelling:ignore:`hubble.ui.topologySpreadConstraints`
     - Pod topology spread constraints for hubble-ui
     - list
     - ``[]``
   * - :spelling:ignore:`hubble.ui.updateStrategy`
     - hubble-ui update strategy.
     - object
     - ``{"rollingUpdate":{"maxUnavailable":1},"type":"RollingUpdate"}``
   * - :spelling:ignore:`identityAllocationMode`
     - Method to use for identity allocation (\ ``crd`` or ``kvstore``\ ).
     - string
     - ``"crd"``
   * - :spelling:ignore:`identityChangeGracePeriod`
     - Time to wait before using new identity on endpoint identity change.
     - string
     - ``"5s"``
   * - :spelling:ignore:`image`
     - Agent container image.
     - object
     - ``{"digest":"sha256:9dc74ba5321c999e498b5f05202c7e27015360dd19278f19b15a25bee79d22f1","override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/cilium","tag":"v1.13.18","useDigest":true}``
   * - :spelling:ignore:`imagePullSecrets`
     - Configure image pull secrets for pulling container images
     - string
     - ``nil``
   * - :spelling:ignore:`ingressController.enabled`
     - Enable cilium ingress controller This will automatically set enable-envoy-config as well.
     - bool
     - ``false``
   * - :spelling:ignore:`ingressController.enforceHttps`
     - Enforce https for host having matching TLS host in Ingress. Incoming traffic to http listener will return 308 http error code with respective location in header.
     - bool
     - ``true``
   * - :spelling:ignore:`ingressController.ingressLBAnnotationPrefixes`
     - IngressLBAnnotations are the annotation prefixes, which are used to filter annotations to propagate from Ingress to the Load Balancer service
     - list
     - ``["service.beta.kubernetes.io","service.kubernetes.io","cloud.google.com"]``
   * - :spelling:ignore:`ingressController.loadbalancerMode`
     - Default ingress load balancer mode Supported values: shared, dedicated For granular control, use the following annotations on the ingress resource ingress.cilium.io/loadbalancer-mode: shared
     - string
     - ``"dedicated"``
   * - :spelling:ignore:`ingressController.secretsNamespace`
     - SecretsNamespace is the namespace in which envoy SDS will retrieve TLS secrets from.
     - object
     - ``{"create":true,"name":"cilium-secrets","sync":true}``
   * - :spelling:ignore:`ingressController.secretsNamespace.create`
     - Create secrets namespace for Ingress.
     - bool
     - ``true``
   * - :spelling:ignore:`ingressController.secretsNamespace.name`
     - Name of Ingress secret namespace.
     - string
     - ``"cilium-secrets"``
   * - :spelling:ignore:`ingressController.secretsNamespace.sync`
     - Enable secret sync, which will make sure all TLS secrets used by Ingress are synced to secretsNamespace.name. If disabled, TLS secrets must be maintained externally.
     - bool
     - ``true``
   * - :spelling:ignore:`ingressController.service`
     - Load-balancer service in shared mode. This is a single load-balancer service for all Ingress resources.
     - object
     - ``{"allocateLoadBalancerNodePorts":null,"annotations":{},"insecureNodePort":null,"labels":{},"loadBalancerClass":null,"loadBalancerIP":null,"name":"cilium-ingress","secureNodePort":null,"type":"LoadBalancer"}``
   * - :spelling:ignore:`ingressController.service.allocateLoadBalancerNodePorts`
     - Configure if node port allocation is required for LB service ref: https://kubernetes.io/docs/concepts/services-networking/service/#load-balancer-nodeport-allocation
     - string
     - ``nil``
   * - :spelling:ignore:`ingressController.service.annotations`
     - Annotations to be added for the shared LB service
     - object
     - ``{}``
   * - :spelling:ignore:`ingressController.service.insecureNodePort`
     - Configure a specific nodePort for insecure HTTP traffic on the shared LB service
     - string
     - ``nil``
   * - :spelling:ignore:`ingressController.service.labels`
     - Labels to be added for the shared LB service
     - object
     - ``{}``
   * - :spelling:ignore:`ingressController.service.loadBalancerClass`
     - Configure a specific loadBalancerClass on the shared LB service (requires Kubernetes 1.24+)
     - string
     - ``nil``
   * - :spelling:ignore:`ingressController.service.loadBalancerIP`
     - Configure a specific loadBalancerIP on the shared LB service
     - string
     - ``nil``
   * - :spelling:ignore:`ingressController.service.name`
     - Service name
     - string
     - ``"cilium-ingress"``
   * - :spelling:ignore:`ingressController.service.secureNodePort`
     - Configure a specific nodePort for secure HTTPS traffic on the shared LB service
     - string
     - ``nil``
   * - :spelling:ignore:`ingressController.service.type`
     - Service type for the shared LB service
     - string
     - ``"LoadBalancer"``
   * - :spelling:ignore:`initResources`
     - resources & limits for the agent init containers
     - object
     - ``{}``
   * - :spelling:ignore:`installNoConntrackIptablesRules`
     - Install Iptables rules to skip netfilter connection tracking on all pod traffic. This option is only effective when Cilium is running in direct routing and full KPR mode. Moreover, this option cannot be enabled when Cilium is running in a managed Kubernetes environment or in a chained CNI setup.
     - bool
     - ``false``
   * - :spelling:ignore:`ipMasqAgent`
     - Configure the eBPF-based ip-masq-agent
     - object
     - ``{"enabled":false}``
   * - :spelling:ignore:`ipam.mode`
     - Configure IP Address Management mode. ref: https://docs.cilium.io/en/stable/network/concepts/ipam/
     - string
     - ``"cluster-pool"``
   * - :spelling:ignore:`ipam.operator.clusterPoolIPv4MaskSize`
     - IPv4 CIDR mask size to delegate to individual nodes for IPAM.
     - int
     - ``24``
   * - :spelling:ignore:`ipam.operator.clusterPoolIPv4PodCIDR`
     - Deprecated in favor of ipam.operator.clusterPoolIPv4PodCIDRList. IPv4 CIDR range to delegate to individual nodes for IPAM.
     - string
     - ``"10.0.0.0/8"``
   * - :spelling:ignore:`ipam.operator.clusterPoolIPv4PodCIDRList`
     - IPv4 CIDR list range to delegate to individual nodes for IPAM.
     - list
     - ``[]``
   * - :spelling:ignore:`ipam.operator.clusterPoolIPv6MaskSize`
     - IPv6 CIDR mask size to delegate to individual nodes for IPAM.
     - int
     - ``120``
   * - :spelling:ignore:`ipam.operator.clusterPoolIPv6PodCIDR`
     - Deprecated in favor of ipam.operator.clusterPoolIPv6PodCIDRList. IPv6 CIDR range to delegate to individual nodes for IPAM.
     - string
     - ``"fd00::/104"``
   * - :spelling:ignore:`ipam.operator.clusterPoolIPv6PodCIDRList`
     - IPv6 CIDR list range to delegate to individual nodes for IPAM.
     - list
     - ``[]``
   * - :spelling:ignore:`ipam.operator.externalAPILimitBurstSize`
     - The maximum burst size when rate limiting access to external APIs. Also known as the token bucket capacity.
     - string
     - ``20``
   * - :spelling:ignore:`ipam.operator.externalAPILimitQPS`
     - The maximum queries per second when rate limiting access to external APIs. Also known as the bucket refill rate, which is used to refill the bucket up to the burst size capacity.
     - string
     - ``4.0``
   * - :spelling:ignore:`ipv4.enabled`
     - Enable IPv4 support.
     - bool
     - ``true``
   * - :spelling:ignore:`ipv4NativeRoutingCIDR`
     - Allows to explicitly specify the IPv4 CIDR for native routing. When specified, Cilium assumes networking for this CIDR is preconfigured and hands traffic destined for that range to the Linux network stack without applying any SNAT. Generally speaking, specifying a native routing CIDR implies that Cilium can depend on the underlying networking stack to route packets to their destination. To offer a concrete example, if Cilium is configured to use direct routing and the Kubernetes CIDR is included in the native routing CIDR, the user must configure the routes to reach pods, either manually or by setting the auto-direct-node-routes flag.
     - string
     - ``""``
   * - :spelling:ignore:`ipv6.enabled`
     - Enable IPv6 support.
     - bool
     - ``false``
   * - :spelling:ignore:`ipv6NativeRoutingCIDR`
     - Allows to explicitly specify the IPv6 CIDR for native routing. When specified, Cilium assumes networking for this CIDR is preconfigured and hands traffic destined for that range to the Linux network stack without applying any SNAT. Generally speaking, specifying a native routing CIDR implies that Cilium can depend on the underlying networking stack to route packets to their destination. To offer a concrete example, if Cilium is configured to use direct routing and the Kubernetes CIDR is included in the native routing CIDR, the user must configure the routes to reach pods, either manually or by setting the auto-direct-node-routes flag.
     - string
     - ``""``
   * - :spelling:ignore:`k8s`
     - Configure Kubernetes specific configuration
     - object
     - ``{}``
   * - :spelling:ignore:`k8sServiceHost`
     - Kubernetes service host
     - string
     - ``""``
   * - :spelling:ignore:`k8sServicePort`
     - Kubernetes service port
     - string
     - ``""``
   * - :spelling:ignore:`keepDeprecatedLabels`
     - Keep the deprecated selector labels when deploying Cilium DaemonSet.
     - bool
     - ``false``
   * - :spelling:ignore:`keepDeprecatedProbes`
     - Keep the deprecated probes when deploying Cilium DaemonSet
     - bool
     - ``false``
   * - :spelling:ignore:`kubeConfigPath`
     - Kubernetes config path
     - string
     - ``"~/.kube/config"``
   * - :spelling:ignore:`kubeProxyReplacementHealthzBindAddr`
     - healthz server bind address for the kube-proxy replacement. To enable set the value to '0.0.0.0:10256' for all ipv4 addresses and this '[::]:10256' for all ipv6 addresses. By default it is disabled.
     - string
     - ``""``
   * - :spelling:ignore:`l2NeighDiscovery.enabled`
     - Enable L2 neighbor discovery in the agent
     - bool
     - ``true``
   * - :spelling:ignore:`l2NeighDiscovery.refreshPeriod`
     - Override the agent's default neighbor resolution refresh period.
     - string
     - ``"30s"``
   * - :spelling:ignore:`l7Proxy`
     - Enable Layer 7 network policy.
     - bool
     - ``true``
   * - :spelling:ignore:`livenessProbe.failureThreshold`
     - failure threshold of liveness probe
     - int
     - ``10``
   * - :spelling:ignore:`livenessProbe.periodSeconds`
     - interval between checks of the liveness probe
     - int
     - ``30``
   * - :spelling:ignore:`loadBalancer`
     - Configure service load balancing
     - object
     - ``{"l7":{"algorithm":"round_robin","backend":"disabled","ports":[]}}``
   * - :spelling:ignore:`loadBalancer.l7`
     - L7 LoadBalancer
     - object
     - ``{"algorithm":"round_robin","backend":"disabled","ports":[]}``
   * - :spelling:ignore:`loadBalancer.l7.algorithm`
     - Default LB algorithm The default LB algorithm to be used for services, which can be overridden by the service annotation (e.g. service.cilium.io/lb-l7-algorithm) Applicable values: round_robin, least_request, random
     - string
     - ``"round_robin"``
   * - :spelling:ignore:`loadBalancer.l7.backend`
     - Enable L7 service load balancing via envoy proxy. The request to a k8s service, which has specific annotation e.g. service.cilium.io/lb-l7, will be forwarded to the local backend proxy to be load balanced to the service endpoints. Please refer to docs for supported annotations for more configuration.  Applicable values:   - envoy: Enable L7 load balancing via envoy proxy. This will automatically set enable-envoy-config as well.   - disabled: Disable L7 load balancing via service annotation.
     - string
     - ``"disabled"``
   * - :spelling:ignore:`loadBalancer.l7.ports`
     - List of ports from service to be automatically redirected to above backend. Any service exposing one of these ports will be automatically redirected. Fine-grained control can be achieved by using the service annotation.
     - list
     - ``[]``
   * - :spelling:ignore:`localRedirectPolicy`
     - Enable Local Redirect Policy.
     - bool
     - ``false``
   * - :spelling:ignore:`logSystemLoad`
     - Enables periodic logging of system load
     - bool
     - ``false``
   * - :spelling:ignore:`maglev`
     - Configure maglev consistent hashing
     - object
     - ``{}``
   * - :spelling:ignore:`monitor`
     - cilium-monitor sidecar.
     - object
     - ``{"enabled":false}``
   * - :spelling:ignore:`monitor.enabled`
     - Enable the cilium-monitor sidecar.
     - bool
     - ``false``
   * - :spelling:ignore:`name`
     - Agent container name.
     - string
     - ``"cilium"``
   * - :spelling:ignore:`nat46x64Gateway`
     - Configure standalone NAT46/NAT64 gateway
     - object
     - ``{"enabled":false}``
   * - :spelling:ignore:`nat46x64Gateway.enabled`
     - Enable RFC8215-prefixed translation
     - bool
     - ``false``
   * - :spelling:ignore:`nodePort`
     - Configure N-S k8s service loadbalancing
     - object
     - ``{"autoProtectPortRange":true,"bindProtection":true,"enableHealthCheck":true,"enabled":false}``
   * - :spelling:ignore:`nodePort.autoProtectPortRange`
     - Append NodePort range to ip_local_reserved_ports if clash with ephemeral ports is detected.
     - bool
     - ``true``
   * - :spelling:ignore:`nodePort.bindProtection`
     - Set to true to prevent applications binding to service ports.
     - bool
     - ``true``
   * - :spelling:ignore:`nodePort.enableHealthCheck`
     - Enable healthcheck nodePort server for NodePort services
     - bool
     - ``true``
   * - :spelling:ignore:`nodePort.enabled`
     - Enable the Cilium NodePort service implementation.
     - bool
     - ``false``
   * - :spelling:ignore:`nodeSelector`
     - Node selector for cilium-agent.
     - object
     - ``{"kubernetes.io/os":"linux"}``
   * - :spelling:ignore:`nodeinit.affinity`
     - Affinity for cilium-nodeinit
     - object
     - ``{}``
   * - :spelling:ignore:`nodeinit.bootstrapFile`
     - bootstrapFile is the location of the file where the bootstrap timestamp is written by the node-init DaemonSet
     - string
     - ``"/tmp/cilium-bootstrap.d/cilium-bootstrap-time"``
   * - :spelling:ignore:`nodeinit.enabled`
     - Enable the node initialization DaemonSet
     - bool
     - ``false``
   * - :spelling:ignore:`nodeinit.extraEnv`
     - Additional nodeinit environment variables.
     - list
     - ``[]``
   * - :spelling:ignore:`nodeinit.extraVolumeMounts`
     - Additional nodeinit volumeMounts.
     - list
     - ``[]``
   * - :spelling:ignore:`nodeinit.extraVolumes`
     - Additional nodeinit volumes.
     - list
     - ``[]``
   * - :spelling:ignore:`nodeinit.image`
     - node-init image.
     - object
     - ``{"digest":"sha256:8d7b41c4ca45860254b3c19e20210462ef89479bb6331d6760c4e609d651b29c","override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/startup-script","tag":"c54c7edeab7fde4da68e59acd319ab24af242c3f","useDigest":true}``
   * - :spelling:ignore:`nodeinit.nodeSelector`
     - Node labels for nodeinit pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector
     - object
     - ``{"kubernetes.io/os":"linux"}``
   * - :spelling:ignore:`nodeinit.podAnnotations`
     - Annotations to be added to node-init pods.
     - object
     - ``{}``
   * - :spelling:ignore:`nodeinit.podLabels`
     - Labels to be added to node-init pods.
     - object
     - ``{}``
   * - :spelling:ignore:`nodeinit.priorityClassName`
     - The priority class to use for the nodeinit pod.
     - string
     - ``""``
   * - :spelling:ignore:`nodeinit.resources`
     - nodeinit resource limits & requests ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
     - object
     - ``{"requests":{"cpu":"100m","memory":"100Mi"}}``
   * - :spelling:ignore:`nodeinit.securityContext`
     - Security context to be added to nodeinit pods.
     - object
     - ``{"capabilities":{"add":["SYS_MODULE","NET_ADMIN","SYS_ADMIN","SYS_CHROOT","SYS_PTRACE"]},"privileged":false,"seLinuxOptions":{"level":"s0","type":"spc_t"}}``
   * - :spelling:ignore:`nodeinit.tolerations`
     - Node tolerations for nodeinit scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
     - list
     - ``[{"operator":"Exists"}]``
   * - :spelling:ignore:`nodeinit.updateStrategy`
     - node-init update strategy
     - object
     - ``{"type":"RollingUpdate"}``
   * - :spelling:ignore:`operator.affinity`
     - Affinity for cilium-operator
     - object
     - ``{"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"io.cilium/app":"operator"}},"topologyKey":"kubernetes.io/hostname"}]}}``
   * - :spelling:ignore:`operator.dnsPolicy`
     - DNS policy for Cilium operator pods. Ref: https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pod-s-dns-policy
     - string
     - ``""``
   * - :spelling:ignore:`operator.enabled`
     - Enable the cilium-operator component (required).
     - bool
     - ``true``
   * - :spelling:ignore:`operator.endpointGCInterval`
     - Interval for endpoint garbage collection.
     - string
     - ``"5m0s"``
   * - :spelling:ignore:`operator.extraArgs`
     - Additional cilium-operator container arguments.
     - list
     - ``[]``
   * - :spelling:ignore:`operator.extraEnv`
     - Additional cilium-operator environment variables.
     - list
     - ``[]``
   * - :spelling:ignore:`operator.extraHostPathMounts`
     - Additional cilium-operator hostPath mounts.
     - list
     - ``[]``
   * - :spelling:ignore:`operator.extraVolumeMounts`
     - Additional cilium-operator volumeMounts.
     - list
     - ``[]``
   * - :spelling:ignore:`operator.extraVolumes`
     - Additional cilium-operator volumes.
     - list
     - ``[]``
   * - :spelling:ignore:`operator.identityGCInterval`
     - Interval for identity garbage collection.
     - string
     - ``"15m0s"``
   * - :spelling:ignore:`operator.identityHeartbeatTimeout`
     - Timeout for identity heartbeats.
     - string
     - ``"30m0s"``
   * - :spelling:ignore:`operator.image`
     - cilium-operator image.
     - object
     - ``{"alibabacloudDigest":"sha256:27da1054d0aa105970ae150133cd0ed5a17e9696533e055f2f93902d4e4d3359","awsDigest":"sha256:20740ff319ea3169f40593f514887769461167c64f83703c43dcd0ffe3641a95","azureDigest":"sha256:5cc125efdfd2dbdf8d0361c714c4f27699603f47a18e5abad5223ffd7bda9b6c","genericDigest":"sha256:6a6332840d4df6eef48bb81ced12af8d860438aa2974b39b875cd6c234302b69","override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/operator","suffix":"","tag":"v1.13.18","useDigest":true}``
   * - :spelling:ignore:`operator.nodeGCInterval`
     - Interval for cilium node garbage collection.
     - string
     - ``"5m0s"``
   * - :spelling:ignore:`operator.nodeSelector`
     - Node labels for cilium-operator pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector
     - object
     - ``{"kubernetes.io/os":"linux"}``
   * - :spelling:ignore:`operator.podAnnotations`
     - Annotations to be added to cilium-operator pods
     - object
     - ``{}``
   * - :spelling:ignore:`operator.podDisruptionBudget.enabled`
     - enable PodDisruptionBudget ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/
     - bool
     - ``false``
   * - :spelling:ignore:`operator.podDisruptionBudget.maxUnavailable`
     - Maximum number/percentage of pods that may be made unavailable
     - int
     - ``1``
   * - :spelling:ignore:`operator.podDisruptionBudget.minAvailable`
     - Minimum number/percentage of pods that should remain scheduled. When it's set, maxUnavailable must be disabled by ``maxUnavailable: null``
     - string
     - ``nil``
   * - :spelling:ignore:`operator.podLabels`
     - Labels to be added to cilium-operator pods
     - object
     - ``{}``
   * - :spelling:ignore:`operator.podSecurityContext`
     - Security context to be added to cilium-operator pods
     - object
     - ``{}``
   * - :spelling:ignore:`operator.pprof.address`
     - Configure pprof listen address for cilium-operator
     - string
     - ``"localhost"``
   * - :spelling:ignore:`operator.pprof.enabled`
     - Enable pprof for cilium-operator
     - bool
     - ``false``
   * - :spelling:ignore:`operator.pprof.port`
     - Configure pprof listen port for cilium-operator
     - int
     - ``6061``
   * - :spelling:ignore:`operator.priorityClassName`
     - The priority class to use for cilium-operator
     - string
     - ``""``
   * - :spelling:ignore:`operator.prometheus`
     - Enable prometheus metrics for cilium-operator on the configured port at /metrics
     - object
     - ``{"enabled":false,"port":9963,"serviceMonitor":{"annotations":{},"enabled":false,"interval":"10s","labels":{},"metricRelabelings":null,"relabelings":null}}``
   * - :spelling:ignore:`operator.prometheus.serviceMonitor.annotations`
     - Annotations to add to ServiceMonitor cilium-operator
     - object
     - ``{}``
   * - :spelling:ignore:`operator.prometheus.serviceMonitor.enabled`
     - Enable service monitors. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml)
     - bool
     - ``false``
   * - :spelling:ignore:`operator.prometheus.serviceMonitor.interval`
     - Interval for scrape metrics.
     - string
     - ``"10s"``
   * - :spelling:ignore:`operator.prometheus.serviceMonitor.labels`
     - Labels to add to ServiceMonitor cilium-operator
     - object
     - ``{}``
   * - :spelling:ignore:`operator.prometheus.serviceMonitor.metricRelabelings`
     - Metrics relabeling configs for the ServiceMonitor cilium-operator
     - string
     - ``nil``
   * - :spelling:ignore:`operator.prometheus.serviceMonitor.relabelings`
     - Relabeling configs for the ServiceMonitor cilium-operator
     - string
     - ``nil``
   * - :spelling:ignore:`operator.removeNodeTaints`
     - Remove Cilium node taint from Kubernetes nodes that have a healthy Cilium pod running.
     - bool
     - ``true``
   * - :spelling:ignore:`operator.replicas`
     - Number of replicas to run for the cilium-operator deployment
     - int
     - ``2``
   * - :spelling:ignore:`operator.resources`
     - cilium-operator resource limits & requests ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
     - object
     - ``{}``
   * - :spelling:ignore:`operator.rollOutPods`
     - Roll out cilium-operator pods automatically when configmap is updated.
     - bool
     - ``false``
   * - :spelling:ignore:`operator.securityContext`
     - Security context to be added to cilium-operator pods
     - object
     - ``{}``
   * - :spelling:ignore:`operator.setNodeNetworkStatus`
     - Set Node condition NetworkUnavailable to 'false' with the reason 'CiliumIsUp' for nodes that have a healthy Cilium pod.
     - bool
     - ``true``
   * - :spelling:ignore:`operator.skipCNPStatusStartupClean`
     - Skip CNP node status clean up at operator startup.
     - bool
     - ``false``
   * - :spelling:ignore:`operator.skipCRDCreation`
     - Skip CRDs creation for cilium-operator
     - bool
     - ``false``
   * - :spelling:ignore:`operator.tolerations`
     - Node tolerations for cilium-operator scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
     - list
     - ``[{"operator":"Exists"}]``
   * - :spelling:ignore:`operator.topologySpreadConstraints`
     - Pod topology spread constraints for cilium-operator
     - list
     - ``[]``
   * - :spelling:ignore:`operator.unmanagedPodWatcher.intervalSeconds`
     - Interval, in seconds, to check if there are any pods that are not managed by Cilium.
     - int
     - ``15``
   * - :spelling:ignore:`operator.unmanagedPodWatcher.restart`
     - Restart any pod that are not managed by Cilium.
     - bool
     - ``true``
   * - :spelling:ignore:`operator.updateStrategy`
     - cilium-operator update strategy
     - object
     - ``{"rollingUpdate":{"maxSurge":1,"maxUnavailable":1},"type":"RollingUpdate"}``
   * - :spelling:ignore:`pmtuDiscovery.enabled`
     - Enable path MTU discovery to send ICMP fragmentation-needed replies to the client.
     - bool
     - ``false``
   * - :spelling:ignore:`podAnnotations`
     - Annotations to be added to agent pods
     - object
     - ``{}``
   * - :spelling:ignore:`podLabels`
     - Labels to be added to agent pods
     - object
     - ``{}``
   * - :spelling:ignore:`podSecurityContext`
     - Security Context for cilium-agent pods.
     - object
     - ``{}``
   * - :spelling:ignore:`policyEnforcementMode`
     - The agent can be put into one of the three policy enforcement modes: default, always and never. ref: https://docs.cilium.io/en/stable/security/policy/intro/#policy-enforcement-modes
     - string
     - ``"default"``
   * - :spelling:ignore:`pprof.address`
     - Configure pprof listen address for cilium-agent
     - string
     - ``"localhost"``
   * - :spelling:ignore:`pprof.enabled`
     - Enable pprof for cilium-agent
     - bool
     - ``false``
   * - :spelling:ignore:`pprof.port`
     - Configure pprof listen port for cilium-agent
     - int
     - ``6060``
   * - :spelling:ignore:`preflight.affinity`
     - Affinity for cilium-preflight
     - object
     - ``{"podAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"k8s-app":"cilium"}},"topologyKey":"kubernetes.io/hostname"}]}}``
   * - :spelling:ignore:`preflight.enabled`
     - Enable Cilium pre-flight resources (required for upgrade)
     - bool
     - ``false``
   * - :spelling:ignore:`preflight.extraEnv`
     - Additional preflight environment variables.
     - list
     - ``[]``
   * - :spelling:ignore:`preflight.extraVolumeMounts`
     - Additional preflight volumeMounts.
     - list
     - ``[]``
   * - :spelling:ignore:`preflight.extraVolumes`
     - Additional preflight volumes.
     - list
     - ``[]``
   * - :spelling:ignore:`preflight.image`
     - Cilium pre-flight image.
     - object
     - ``{"digest":"sha256:9dc74ba5321c999e498b5f05202c7e27015360dd19278f19b15a25bee79d22f1","override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/cilium","tag":"v1.13.18","useDigest":true}``
   * - :spelling:ignore:`preflight.nodeSelector`
     - Node labels for preflight pod assignment ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector
     - object
     - ``{"kubernetes.io/os":"linux"}``
   * - :spelling:ignore:`preflight.podAnnotations`
     - Annotations to be added to preflight pods
     - object
     - ``{}``
   * - :spelling:ignore:`preflight.podDisruptionBudget.enabled`
     - enable PodDisruptionBudget ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/
     - bool
     - ``false``
   * - :spelling:ignore:`preflight.podDisruptionBudget.maxUnavailable`
     - Maximum number/percentage of pods that may be made unavailable
     - int
     - ``1``
   * - :spelling:ignore:`preflight.podDisruptionBudget.minAvailable`
     - Minimum number/percentage of pods that should remain scheduled. When it's set, maxUnavailable must be disabled by ``maxUnavailable: null``
     - string
     - ``nil``
   * - :spelling:ignore:`preflight.podLabels`
     - Labels to be added to the preflight pod.
     - object
     - ``{}``
   * - :spelling:ignore:`preflight.podSecurityContext`
     - Security context to be added to preflight pods.
     - object
     - ``{}``
   * - :spelling:ignore:`preflight.priorityClassName`
     - The priority class to use for the preflight pod.
     - string
     - ``""``
   * - :spelling:ignore:`preflight.resources`
     - preflight resource limits & requests ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
     - object
     - ``{}``
   * - :spelling:ignore:`preflight.securityContext`
     - Security context to be added to preflight pods
     - object
     - ``{}``
   * - :spelling:ignore:`preflight.terminationGracePeriodSeconds`
     - Configure termination grace period for preflight Deployment and DaemonSet.
     - int
     - ``1``
   * - :spelling:ignore:`preflight.tofqdnsPreCache`
     - Path to write the ``--tofqdns-pre-cache`` file to.
     - string
     - ``""``
   * - :spelling:ignore:`preflight.tolerations`
     - Node tolerations for preflight scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
     - list
     - ``[{"effect":"NoSchedule","key":"node.kubernetes.io/not-ready"},{"effect":"NoSchedule","key":"node-role.kubernetes.io/master"},{"effect":"NoSchedule","key":"node-role.kubernetes.io/control-plane"},{"effect":"NoSchedule","key":"node.cloudprovider.kubernetes.io/uninitialized","value":"true"},{"key":"CriticalAddonsOnly","operator":"Exists"}]``
   * - :spelling:ignore:`preflight.updateStrategy`
     - preflight update strategy
     - object
     - ``{"type":"RollingUpdate"}``
   * - :spelling:ignore:`preflight.validateCNPs`
     - By default we should always validate the installed CNPs before upgrading Cilium. This will make sure the user will have the policies deployed in the cluster with the right schema.
     - bool
     - ``true``
   * - :spelling:ignore:`priorityClassName`
     - The priority class to use for cilium-agent.
     - string
     - ``""``
   * - :spelling:ignore:`prometheus`
     - Configure prometheus metrics on the configured port at /metrics
     - object
     - ``{"enabled":false,"metrics":null,"port":9962,"serviceMonitor":{"annotations":{},"enabled":false,"interval":"10s","labels":{},"metricRelabelings":null,"relabelings":[{"replacement":"${1}","sourceLabels":["__meta_kubernetes_pod_node_name"],"targetLabel":"node"}],"trustCRDsExist":false}}``
   * - :spelling:ignore:`prometheus.metrics`
     - Metrics that should be enabled or disabled from the default metric list. (+metric_foo to enable metric_foo , -metric_bar to disable metric_bar). ref: https://docs.cilium.io/en/stable/observability/metrics/
     - string
     - ``nil``
   * - :spelling:ignore:`prometheus.serviceMonitor.annotations`
     - Annotations to add to ServiceMonitor cilium-agent
     - object
     - ``{}``
   * - :spelling:ignore:`prometheus.serviceMonitor.enabled`
     - Enable service monitors. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml)
     - bool
     - ``false``
   * - :spelling:ignore:`prometheus.serviceMonitor.interval`
     - Interval for scrape metrics.
     - string
     - ``"10s"``
   * - :spelling:ignore:`prometheus.serviceMonitor.labels`
     - Labels to add to ServiceMonitor cilium-agent
     - object
     - ``{}``
   * - :spelling:ignore:`prometheus.serviceMonitor.metricRelabelings`
     - Metrics relabeling configs for the ServiceMonitor cilium-agent
     - string
     - ``nil``
   * - :spelling:ignore:`prometheus.serviceMonitor.relabelings`
     - Relabeling configs for the ServiceMonitor cilium-agent
     - list
     - ``[{"replacement":"${1}","sourceLabels":["__meta_kubernetes_pod_node_name"],"targetLabel":"node"}]``
   * - :spelling:ignore:`prometheus.serviceMonitor.trustCRDsExist`
     - Set to ``true`` and helm will not check for monitoring.coreos.com/v1 CRDs before deploying
     - bool
     - ``false``
   * - :spelling:ignore:`proxy`
     - Configure Istio proxy options.
     - object
     - ``{"prometheus":{"enabled":true,"port":"9964"},"sidecarImageRegex":"cilium/istio_proxy"}``
   * - :spelling:ignore:`proxy.sidecarImageRegex`
     - Regular expression matching compatible Istio sidecar istio-proxy container image names
     - string
     - ``"cilium/istio_proxy"``
   * - :spelling:ignore:`rbac.create`
     - Enable creation of Resource-Based Access Control configuration.
     - bool
     - ``true``
   * - :spelling:ignore:`readinessProbe.failureThreshold`
     - failure threshold of readiness probe
     - int
     - ``3``
   * - :spelling:ignore:`readinessProbe.periodSeconds`
     - interval between checks of the readiness probe
     - int
     - ``30``
   * - :spelling:ignore:`remoteNodeIdentity`
     - Enable use of the remote node identity. ref: https://docs.cilium.io/en/v1.7/install/upgrade/#configmap-remote-node-identity
     - bool
     - ``true``
   * - :spelling:ignore:`resourceQuotas`
     - Enable resource quotas for priority classes used in the cluster.
     - object
     - ``{"cilium":{"hard":{"pods":"10k"}},"enabled":false,"operator":{"hard":{"pods":"15"}}}``
   * - :spelling:ignore:`resources`
     - Agent resource limits & requests ref: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
     - object
     - ``{}``
   * - :spelling:ignore:`rollOutCiliumPods`
     - Roll out cilium agent pods automatically when configmap is updated.
     - bool
     - ``false``
   * - :spelling:ignore:`sctp`
     - SCTP Configuration Values
     - object
     - ``{"enabled":false}``
   * - :spelling:ignore:`sctp.enabled`
     - Enable SCTP support. NOTE: Currently, SCTP support does not support rewriting ports or multihoming.
     - bool
     - ``false``
   * - :spelling:ignore:`securityContext.capabilities.applySysctlOverwrites`
     - capabilities for the ``apply-sysctl-overwrites`` init container
     - list
     - ``["SYS_ADMIN","SYS_CHROOT","SYS_PTRACE"]``
   * - :spelling:ignore:`securityContext.capabilities.ciliumAgent`
     - Capabilities for the ``cilium-agent`` container
     - list
     - ``["CHOWN","KILL","NET_ADMIN","NET_RAW","IPC_LOCK","SYS_MODULE","SYS_ADMIN","SYS_RESOURCE","DAC_OVERRIDE","FOWNER","SETGID","SETUID"]``
   * - :spelling:ignore:`securityContext.capabilities.cleanCiliumState`
     - Capabilities for the ``clean-cilium-state`` init container
     - list
     - ``["NET_ADMIN","SYS_MODULE","SYS_ADMIN","SYS_RESOURCE"]``
   * - :spelling:ignore:`securityContext.capabilities.mountCgroup`
     - Capabilities for the ``mount-cgroup`` init container
     - list
     - ``["SYS_ADMIN","SYS_CHROOT","SYS_PTRACE"]``
   * - :spelling:ignore:`securityContext.privileged`
     - Run the pod with elevated privileges
     - bool
     - ``false``
   * - :spelling:ignore:`securityContext.seLinuxOptions`
     - SELinux options for the ``cilium-agent`` and init containers
     - object
     - ``{"level":"s0","type":"spc_t"}``
   * - :spelling:ignore:`serviceAccounts`
     - Define serviceAccount names for components.
     - object
     - Component's fully qualified name.
   * - :spelling:ignore:`serviceAccounts.clustermeshcertgen`
     - Clustermeshcertgen is used if clustermesh.apiserver.tls.auto.method=cronJob
     - object
     - ``{"annotations":{},"automount":true,"create":true,"name":"clustermesh-apiserver-generate-certs"}``
   * - :spelling:ignore:`serviceAccounts.hubblecertgen`
     - Hubblecertgen is used if hubble.tls.auto.method=cronJob
     - object
     - ``{"annotations":{},"automount":true,"create":true,"name":"hubble-generate-certs"}``
   * - :spelling:ignore:`serviceAccounts.nodeinit.enabled`
     - Enabled is temporary until https://github.com/cilium/cilium-cli/issues/1396 is implemented. Cilium CLI doesn't create the SAs for node-init, thus the workaround. Helm is not affected by this issue. Name and automount can be configured, if enabled is set to true. Otherwise, they are ignored. Enabled can be removed once the issue is fixed. Cilium-nodeinit DS must also be fixed.
     - bool
     - ``false``
   * - :spelling:ignore:`sleepAfterInit`
     - Do not run Cilium agent when running with clean mode. Useful to completely uninstall Cilium as it will stop Cilium from starting and create artifacts in the node.
     - bool
     - ``false``
   * - :spelling:ignore:`socketLB`
     - Configure socket LB
     - object
     - ``{"enabled":false}``
   * - :spelling:ignore:`socketLB.enabled`
     - Enable socket LB
     - bool
     - ``false``
   * - :spelling:ignore:`sockops`
     - Configure BPF socket operations configuration
     - object
     - ``{"enabled":false}``
   * - :spelling:ignore:`startupProbe.failureThreshold`
     - failure threshold of startup probe. 105 x 2s translates to the old behaviour of the readiness probe (120s delay + 30 x 3s)
     - int
     - ``105``
   * - :spelling:ignore:`startupProbe.periodSeconds`
     - interval between checks of the startup probe
     - int
     - ``2``
   * - :spelling:ignore:`svcSourceRangeCheck`
     - Enable check of service source ranges (currently, only for LoadBalancer).
     - bool
     - ``true``
   * - :spelling:ignore:`synchronizeK8sNodes`
     - Synchronize Kubernetes nodes to kvstore and perform CNP GC.
     - bool
     - ``true``
   * - :spelling:ignore:`terminationGracePeriodSeconds`
     - Configure termination grace period for cilium-agent DaemonSet.
     - int
     - ``1``
   * - :spelling:ignore:`tls`
     - Configure TLS configuration in the agent.
     - object
     - ``{"ca":{"cert":"","certValidityDuration":1095,"key":""},"secretsBackend":"local"}``
   * - :spelling:ignore:`tls.ca`
     - Base64 encoded PEM values for the CA certificate and private key. This can be used as common CA to generate certificates used by hubble and clustermesh components
     - object
     - ``{"cert":"","certValidityDuration":1095,"key":""}``
   * - :spelling:ignore:`tls.ca.cert`
     - Optional CA cert. If it is provided, it will be used by cilium to generate all other certificates. Otherwise, an ephemeral CA is generated.
     - string
     - ``""``
   * - :spelling:ignore:`tls.ca.certValidityDuration`
     - Generated certificates validity duration in days. This will be used for auto generated CA.
     - int
     - ``1095``
   * - :spelling:ignore:`tls.ca.key`
     - Optional CA private key. If it is provided, it will be used by cilium to generate all other certificates. Otherwise, an ephemeral CA is generated.
     - string
     - ``""``
   * - :spelling:ignore:`tls.secretsBackend`
     - This configures how the Cilium agent loads the secrets used TLS-aware CiliumNetworkPolicies (namely the secrets referenced by terminatingTLS and originatingTLS). Possible values:   - local   - k8s
     - string
     - ``"local"``
   * - :spelling:ignore:`tolerations`
     - Node tolerations for agent scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/
     - list
     - ``[{"operator":"Exists"}]``
   * - :spelling:ignore:`tunnel`
     - Configure the encapsulation configuration for communication between nodes. Possible values:   - disabled   - vxlan (default)   - geneve
     - string
     - ``"vxlan"``
   * - :spelling:ignore:`tunnelPort`
     - Configure VXLAN and Geneve tunnel port.
     - int
     - Port 8472 for VXLAN, Port 6081 for Geneve
   * - :spelling:ignore:`updateStrategy`
     - Cilium agent update strategy
     - object
     - ``{"rollingUpdate":{"maxUnavailable":2},"type":"RollingUpdate"}``
   * - :spelling:ignore:`vtep.cidr`
     - A space separated list of VTEP device CIDRs, for example "1.1.1.0/24 1.1.2.0/24"
     - string
     - ``""``
   * - :spelling:ignore:`vtep.enabled`
     - Enables VXLAN Tunnel Endpoint (VTEP) Integration (beta) to allow Cilium-managed pods to talk to third party VTEP devices over Cilium tunnel.
     - bool
     - ``false``
   * - :spelling:ignore:`vtep.endpoint`
     - A space separated list of VTEP device endpoint IPs, for example "1.1.1.1  1.1.2.1"
     - string
     - ``""``
   * - :spelling:ignore:`vtep.mac`
     - A space separated list of VTEP device MAC addresses (VTEP MAC), for example "x:x:x:x:x:x  y:y:y:y:y:y:y"
     - string
     - ``""``
   * - :spelling:ignore:`vtep.mask`
     - VTEP CIDRs Mask that applies to all VTEP CIDRs, for example "255.255.255.0"
     - string
     - ``""``
   * - :spelling:ignore:`waitForKubeProxy`
     - Wait for KUBE-PROXY-CANARY iptables rule to appear in "wait-for-kube-proxy" init container before launching cilium-agent. More context can be found in the commit message of below PR https://github.com/cilium/cilium/pull/20123
     - bool
     - ``false``
   * - :spelling:ignore:`wellKnownIdentities.enabled`
     - Enable the use of well-known identities.
     - bool
     - ``false``
