..
  AUTO-GENERATED. Please DO NOT edit manually.


.. list-table::
   :header-rows: 1

   * - Key
     - Description
     - Type
     - Default
   * - affinity
     - Affinity for cilium-agent.
     - object
     - ``{"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"k8s-app":"cilium"}},"topologyKey":"kubernetes.io/hostname"}]}}``
   * - agent
     - Install the cilium agent resources.
     - bool
     - ``true``
   * - alibabacloud.enabled
     - Enable AlibabaCloud ENI integration
     - bool
     - ``false``
   * - autoDirectNodeRoutes
     - Enable installation of PodCIDR routes between worker nodes if worker nodes share a common L2 network segment.
     - bool
     - ``false``
   * - azure.enabled
     - Enable Azure integration
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
     - This feature set enables virtual BGP routers to be created via  CiliumBGPPeeringPolicy CRDs.
     - object
     - ``{"enabled":false}``
   * - bgpControlPlane.enabled
     - Enables the BGP control plane.
     - bool
     - ``false``
   * - bpf.clockProbe
     - Enable BPF clock source probing for more efficient tick retrieval.
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
   * - certgen
     - Configure certificate generation for Hubble integration. If hubble.tls.auto.method=cronJob, these values are used for the Kubernetes CronJob which will be scheduled regularly to (re)generate any certificates not provided manually.
     - object
     - ``{"image":{"override":null,"pullPolicy":"Always","repository":"quay.io/cilium/certgen","tag":"v0.1.8"},"podLabels":{},"tolerations":[],"ttlSecondsAfterFinished":1800}``
   * - certgen.podLabels
     - Labels to be added to hubble-certgen pods
     - object
     - ``{}``
   * - certgen.tolerations
     - Node tolerations for pod assignment on nodes with taints ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
     - list
     - ``[]``
   * - certgen.ttlSecondsAfterFinished
     - Seconds after which the completed job pod will be deleted
     - int
     - ``1800``
   * - cgroup
     - Configure cgroup related configuration
     - object
     - ``{"autoMount":{"enabled":true},"hostRoot":"/run/cilium/cgroupv2"}``
   * - cgroup.autoMount.enabled
     - Enable auto mount of cgroup2 filesystem. When ``autoMount`` is enabled, cgroup2 filesystem is mounted at ``cgroup.hostRoot`` path on the underlying host and inside the cilium agent pod. If users disable ``autoMount``\ , it's expected that users have mounted cgroup2 filesystem at the specified ``cgroup.hostRoot`` volume, and then the volume will be mounted inside the cilium agent pod at the same path.
     - bool
     - ``true``
   * - cgroup.hostRoot
     - Configure cgroup root where cgroup2 filesystem is mounted on the host (see also: ``cgroup.autoMount``\ )
     - string
     - ``"/run/cilium/cgroupv2"``
   * - cleanBpfState
     - Clean all eBPF datapath state from the initContainer of the cilium-agent DaemonSet. WARNING: Use with care!
     - bool
     - ``false``
   * - cleanState
     - Clean all local Cilium state from the initContainer of the cilium-agent DaemonSet. Implies cleanBpfState: true. WARNING: Use with care!
     - bool
     - ``false``
   * - cluster.id
     - Unique ID of the cluster. Must be unique across all connected clusters and in the range of 1 to 255. Only required for Cluster Mesh.
     - int
     - ``nil``
   * - cluster.name
     - Name of the cluster. Only required for Cluster Mesh.
     - string
     - ``"default"``
   * - clustermesh.apiserver.affinity
     - Affinity for clustermesh.apiserver
     - object
     - ``{"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"k8s-app":"clustermesh-apiserver"}},"topologyKey":"kubernetes.io/hostname"}]}}``
   * - clustermesh.apiserver.etcd.image
     - Clustermesh API server etcd image.
     - object
     - ``{"override":null,"pullPolicy":"Always","repository":"quay.io/coreos/etcd","tag":"v3.5.2@sha256:70fe70b6cdaea99fa9e99d3a16483954eb084c3b32a2475abea4e709a793636c"}``
   * - clustermesh.apiserver.extraEnv
     - Additional clustermesh-apiserver environment variables.
     - list
     - ``[]``
   * - clustermesh.apiserver.image
     - Clustermesh API server image.
     - object
     - ``{"digest":"","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/clustermesh-apiserver","tag":"latest","useDigest":false}``
   * - clustermesh.apiserver.nodeSelector
     - Node labels for pod assignment ref: https://kubernetes.io/docs/user-guide/node-selection/
     - object
     - ``{}``
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
   * - clustermesh.apiserver.service.annotations
     - Annotations for the clustermesh-apiserver For GKE LoadBalancer, use annotation cloud.google.com/load-balancer-type: "Internal" For EKS LoadBalancer, use annotation service.beta.kubernetes.io/aws-load-balancer-internal: 0.0.0.0/0
     - object
     - ``{}``
   * - clustermesh.apiserver.service.nodePort
     - Optional port to use as the node port for apiserver access.
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
   * - clustermesh.apiserver.tls.auto
     - Configure automatic TLS certificates generation. A Kubernetes CronJob is used the generate any certificates not provided by the user at installation time.
     - object
     - ``{"certManagerIssuerRef":{},"certValidityDuration":1095,"enabled":true,"method":"helm"}``
   * - clustermesh.apiserver.tls.auto.certManagerIssuerRef
     - certmanager issuer used when clustermesh.apiserver.tls.auto.method=certmanager. If not specified, a CA issuer will be created.
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
     - base64 encoded PEM values for the ExternalWorkload CA certificate and private key.
     - object
     - ``{"cert":"","key":""}``
   * - clustermesh.apiserver.tls.ca.cert
     - Optional CA cert. If it is provided, it will be used by the 'cronJob' method to generate all other certificates. Otherwise, an ephemeral CA is generated.
     - string
     - ``""``
   * - clustermesh.apiserver.tls.ca.key
     - Optional CA private key. If it is provided, it will be used by the 'cronJob' method to generate all other certificates. Otherwise, an ephemeral CA is generated.
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
     - Node tolerations for pod assignment on nodes with taints ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
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
     - ``"none"``
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
   * - containerRuntime
     - Configure container runtime specific integration.
     - object
     - ``{"integration":"none"}``
   * - containerRuntime.integration
     - Enables specific integrations for container runtimes. Supported values: - containerd - crio - docker - none - auto (automatically detect the container runtime)
     - string
     - ``"none"``
   * - customCalls
     - Tail call hooks for custom eBPF programs.
     - object
     - ``{"enabled":false}``
   * - customCalls.enabled
     - Enable tail call hooks for custom eBPF programs.
     - bool
     - ``false``
   * - daemon.runPath
     - Configure where Cilium runtime state should be stored.
     - string
     - ``"/var/run/cilium"``
   * - datapathMode
     - Configure which datapath mode should be used for configuring container connectivity. Valid options are "veth" or "ipvlan". Deprecated, to be removed in v1.12.
     - string
     - ``"veth"``
   * - debug.enabled
     - Enable debug logging
     - bool
     - ``false``
   * - disableEndpointCRD
     - Disable the usage of CiliumEndpoint CRD.
     - string
     - ``"false"``
   * - egressGateway
     - Enables egress gateway (beta) to redirect and SNAT the traffic that leaves the cluster.
     - object
     - ``{"enabled":false}``
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
   * - enableXTSocketFallback
     - Enables the fallback compatibility solution for when the xt_socket kernel module is missing and it is needed for the datapath L7 redirection to work properly. See documentation for details on when this can be disabled: https://docs.cilium.io/en/stable/operations/system_requirements/#linux-kernel.
     - bool
     - ``true``
   * - encryption.enabled
     - Enable transparent network encryption.
     - bool
     - ``false``
   * - encryption.interface
     - Deprecated in favor of encryption.ipsec.interface. The interface to use for encrypted traffic. This option is only effective when encryption.type is set to ipsec.
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
     - Deprecated in favor of encryption.ipsec.keyFile. Name of the key file inside the Kubernetes secret configured via secretName. This option is only effective when encryption.type is set to ipsec.
     - string
     - ``"keys"``
   * - encryption.mountPath
     - Deprecated in favor of encryption.ipsec.mountPath. Path to mount the secret inside the Cilium pod. This option is only effective when encryption.type is set to ipsec.
     - string
     - ``"/etc/ipsec"``
   * - encryption.nodeEncryption
     - Enable encryption for pure node to node traffic. This option is only effective when encryption.type is set to ipsec.
     - bool
     - ``false``
   * - encryption.secretName
     - Deprecated in favor of encryption.ipsec.secretName. Name of the Kubernetes secret containing the encryption keys. This option is only effective when encryption.type is set to ipsec.
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
     - Enable endpoint status. Status can be: policy, health, controllers, logs and / or state. For 2 or more options use a comma.
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
   * - eni.iamRole
     - If using IAM role for Service Accounts will not try to inject identity values from cilium-aws kubernetes secret. Adds annotation to service account if managed by Helm. See https://github.com/aws/amazon-eks-pod-identity-webhook
     - string
     - ``""``
   * - eni.instanceTagsFilter
     - Filter via AWS EC2 Instance tags (k=v) which will dictate which AWS EC2 Instances are going to be used to create new ENIs
     - string
     - ``""``
   * - eni.subnetIDsFilter
     - Filter via subnet IDs which will dictate which subnets are going to be used to create new ENIs Important note: This requires that each instance has an ENI with a matching subnet attached when Cilium is deployed. If you only want to control subnets for ENIs attached by Cilium, use the CNI configuration file settings (cni.customConf) instead.
     - string
     - ``""``
   * - eni.subnetTagsFilter
     - Filter via tags (k=v) which will dictate which subnets are going to be used to create new ENIs Important note: This requires that each instance has an ENI with a matching subnet attached when Cilium is deployed. If you only want to control subnets for ENIs attached by Cilium, use the CNI configuration file settings (cni.customConf) instead.
     - string
     - ``""``
   * - eni.updateEC2AdapterLimitViaAPI
     - Update ENI Adapter limits from the EC2 API
     - bool
     - ``false``
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
   * - etcd.image
     - cilium-etcd-operator image.
     - object
     - ``{"override":null,"pullPolicy":"Always","repository":"quay.io/cilium/cilium-etcd-operator","tag":"v2.0.7"}``
   * - etcd.k8sService
     - If etcd is behind a k8s service set this option to true so that Cilium does the service translation automatically without requiring a DNS to be running.
     - bool
     - ``false``
   * - etcd.nodeSelector
     - Node labels for cilium-etcd-operator pod assignment ref: https://kubernetes.io/docs/user-guide/node-selection/
     - object
     - ``{}``
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
   * - etcd.priorityClassName
     - The priority class to use for cilium-etcd-operator
     - string
     - ``""``
   * - etcd.resources
     - cilium-etcd-operator resource limits & requests ref: https://kubernetes.io/docs/user-guide/compute-resources/
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
     - Node tolerations for cilium-etcd-operator scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
     - list
     - ``[{"operator":"Exists"}]``
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
     - ``9876``
   * - hostAliases
     - Host aliases for cilium-agent.
     - list
     - ``[]``
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
   * - hostServices
     - Configure ClusterIP service handling in the host namespace (the node).
     - object
     - ``{"enabled":false,"protocols":"tcp,udp"}``
   * - hostServices.enabled
     - Enable host reachable services.
     - bool
     - ``false``
   * - hostServices.protocols
     - Supported list of protocols to apply ClusterIP translation to.
     - string
     - ``"tcp,udp"``
   * - hubble.enabled
     - Enable Hubble (true by default).
     - bool
     - ``true``
   * - hubble.listenAddress
     - An additional address for Hubble to listen to. Set this field ":4244" if you are enabling Hubble Relay, as it assumes that Hubble is listening on port 4244.
     - string
     - ``":4244"``
   * - hubble.metrics
     - Hubble metrics configuration. See https://docs.cilium.io/en/stable/operations/metrics/#hubble-metrics for more comprehensive documentation about Hubble metrics.
     - object
     - ``{"enabled":null,"port":9091,"serviceAnnotations":{},"serviceMonitor":{"annotations":{},"enabled":false,"labels":{}}}``
   * - hubble.metrics.enabled
     - Configures the list of metrics to collect. If empty or null, metrics are disabled. Example:   enabled:   - dns:query;ignoreAAAA   - drop   - tcp   - flow   - icmp   - http You can specify the list of metrics from the helm CLI:   --set metrics.enabled="{dns:query;ignoreAAAA,drop,tcp,flow,icmp,http}"
     - string
     - ``nil``
   * - hubble.metrics.port
     - Configure the port the hubble metric server listens on.
     - int
     - ``9091``
   * - hubble.metrics.serviceAnnotations
     - Annotations to be added to hubble-metrics service.
     - object
     - ``{}``
   * - hubble.metrics.serviceMonitor.annotations
     - Annotations to add to ServiceMonitor hubble
     - object
     - ``{}``
   * - hubble.metrics.serviceMonitor.enabled
     - Create ServiceMonitor resources for Prometheus Operator. This requires the prometheus CRDs to be available. ref: https://github.com/prometheus-operator/prometheus-operator/blob/master/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml)
     - bool
     - ``false``
   * - hubble.metrics.serviceMonitor.labels
     - Labels to add to ServiceMonitor hubble
     - object
     - ``{}``
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
   * - hubble.relay.image
     - Hubble-relay container image.
     - object
     - ``{"digest":"","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/hubble-relay","tag":"latest","useDigest":false}``
   * - hubble.relay.listenHost
     - Host to listen to. Specify an empty string to bind to all the interfaces.
     - string
     - ``""``
   * - hubble.relay.listenPort
     - Port to listen to.
     - string
     - ``"4245"``
   * - hubble.relay.nodeSelector
     - Node labels for pod assignment ref: https://kubernetes.io/docs/user-guide/node-selection/
     - object
     - ``{}``
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
   * - hubble.relay.priorityClassName
     - The priority class to use for hubble-relay
     - string
     - ``""``
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
     - hubble-relay security context
     - object
     - ``{}``
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
     - Node tolerations for pod assignment on nodes with taints ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
     - list
     - ``[]``
   * - hubble.relay.updateStrategy
     - hubble-relay update strategy
     - object
     - ``{"rollingUpdate":{"maxUnavailable":1},"type":"RollingUpdate"}``
   * - hubble.socketPath
     - Unix domain socket path to listen to when Hubble is enabled.
     - string
     - ``"/var/run/cilium/hubble.sock"``
   * - hubble.tls
     - TLS configuration for Hubble
     - object
     - ``{"auto":{"certManagerIssuerRef":{},"certValidityDuration":1095,"enabled":true,"method":"helm","schedule":"0 0 1 */4 *"},"ca":{"cert":"","key":""},"enabled":true,"server":{"cert":"","extraDnsNames":[],"extraIpAddresses":[],"key":""}}``
   * - hubble.tls.auto
     - Configure automatic TLS certificates generation.
     - object
     - ``{"certManagerIssuerRef":{},"certValidityDuration":1095,"enabled":true,"method":"helm","schedule":"0 0 1 */4 *"}``
   * - hubble.tls.auto.certManagerIssuerRef
     - certmanager issuer used when hubble.tls.auto.method=certmanager. If not specified, a CA issuer will be created.
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
     - Schedule for certificates regeneration (regardless of their expiration date). Only used if method is "cronJob". If nil, then no recurring job will be created. Instead, only the one-shot job is deployed to generate the certificates at installation time. Defaults to midnight of the first day of every fourth month. For syntax, see https://kubernetes.io/docs/tasks/job/automated-tasks-with-cron-jobs/#schedule
     - string
     - ``"0 0 1 */4 *"``
   * - hubble.tls.ca
     - Deprecated in favor of tls.ca. To be removed in 1.13. base64 encoded PEM values for the Hubble CA certificate and private key.
     - object
     - ``{"cert":"","key":""}``
   * - hubble.tls.ca.cert
     - Deprecated in favor of tls.ca.cert. To be removed in 1.13.
     - string
     - ``""``
   * - hubble.tls.ca.key
     - Deprecated in favor of tls.ca.key. To be removed in 1.13. The CA private key (optional). If it is provided, then it will be used by hubble.tls.auto.method=cronJob to generate all other certificates. Otherwise, a ephemeral CA is generated if hubble.tls.auto.enabled=true.
     - string
     - ``""``
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
   * - hubble.ui.backend.image
     - Hubble-ui backend image.
     - object
     - ``{"override":null,"pullPolicy":"Always","repository":"quay.io/cilium/hubble-ui-backend","tag":"latest"}``
   * - hubble.ui.backend.resources
     - Resource requests and limits for the 'backend' container of the 'hubble-ui' deployment.
     - object
     - ``{}``
   * - hubble.ui.enabled
     - Whether to enable the Hubble UI.
     - bool
     - ``false``
   * - hubble.ui.frontend.extraEnv
     - Additional hubble-ui frontend environment variables.
     - list
     - ``[]``
   * - hubble.ui.frontend.image
     - Hubble-ui frontend image.
     - object
     - ``{"override":null,"pullPolicy":"Always","repository":"quay.io/cilium/hubble-ui","tag":"latest"}``
   * - hubble.ui.frontend.resources
     - Resource requests and limits for the 'frontend' container of the 'hubble-ui' deployment.
     - object
     - ``{}``
   * - hubble.ui.ingress
     - hubble-ui ingress configuration.
     - object
     - ``{"annotations":{},"className":"","enabled":false,"hosts":["chart-example.local"],"tls":[]}``
   * - hubble.ui.nodeSelector
     - Node labels for pod assignment ref: https://kubernetes.io/docs/user-guide/node-selection/
     - object
     - ``{}``
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
   * - hubble.ui.proxy.extraEnv
     - Additional hubble-ui proxy environment variables.
     - list
     - ``[]``
   * - hubble.ui.proxy.image
     - Hubble-ui ingress proxy image.
     - object
     - ``{"override":null,"pullPolicy":"Always","repository":"docker.io/envoyproxy/envoy","tag":"v1.20.2@sha256:eb7d88d5186648049f0a80062120bd45e7557bdff3f6a30e1fc92cbb50916868"}``
   * - hubble.ui.proxy.resources
     - Resource requests and limits for the 'proxy' container of the 'hubble-ui' deployment.
     - object
     - ``{}``
   * - hubble.ui.replicas
     - The number of replicas of Hubble UI to deploy.
     - int
     - ``1``
   * - hubble.ui.rollOutPods
     - Roll out Hubble-ui pods automatically when configmap is updated.
     - bool
     - ``false``
   * - hubble.ui.securityContext.enabled
     - Whether to set the security context on the Hubble UI pods.
     - bool
     - ``true``
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
     - Node tolerations for pod assignment on nodes with taints ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
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
   * - image
     - Agent container image.
     - object
     - ``{"digest":"","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/cilium","tag":"latest","useDigest":false}``
   * - imagePullSecrets
     - Configure image pull secrets for pulling container images
     - string
     - ``nil``
   * - ingressController.enabled
     - Enable cilium ingress controller This will automatically set enable-envoy-config as well.
     - bool
     - ``false``
   * - ingressController.enforceHttps
     - Enforce https for host having matching TLS host in Ingress. Incoming traffic to http listener will return 308 http error code with respective location in header.
     - bool
     - ``true``
   * - installIptablesRules
     - Configure whether to install iptables rules to allow for TPROXY (L7 proxy injection), iptables-based masquerading and compatibility with kube-proxy.
     - bool
     - ``true``
   * - installNoConntrackIptablesRules
     - Install Iptables rules to skip netfilter connection tracking on all pod traffic. This option is only effective when Cilium is running in direct routing and full KPR mode. Moreover, this option cannot be enabled when Cilium is running in a managed Kubernetes environment or in a chained CNI setup.
     - bool
     - ``false``
   * - ipMasqAgent
     - Configure the eBPF-based ip-masq-agent
     - object
     - ``{"enabled":false}``
   * - ipam.mode
     - Configure IP Address Management mode. ref: https://docs.cilium.io/en/stable/concepts/networking/ipam/
     - string
     - ``"cluster-pool"``
   * - ipam.operator.clusterPoolIPv4MaskSize
     - IPv4 CIDR mask size to delegate to individual nodes for IPAM.
     - int
     - ``24``
   * - ipam.operator.clusterPoolIPv4PodCIDR
     - Deprecated in favor of ipam.operator.clusterPoolIPv4PodCIDRList. IPv4 CIDR range to delegate to individual nodes for IPAM.
     - string
     - ``"10.0.0.0/8"``
   * - ipam.operator.clusterPoolIPv4PodCIDRList
     - IPv4 CIDR list range to delegate to individual nodes for IPAM.
     - list
     - ``[]``
   * - ipam.operator.clusterPoolIPv6MaskSize
     - IPv6 CIDR mask size to delegate to individual nodes for IPAM.
     - int
     - ``120``
   * - ipam.operator.clusterPoolIPv6PodCIDR
     - Deprecated in favor of ipam.operator.clusterPoolIPv6PodCIDRList. IPv6 CIDR range to delegate to individual nodes for IPAM.
     - string
     - ``"fd00::/104"``
   * - ipam.operator.clusterPoolIPv6PodCIDRList
     - IPv6 CIDR list range to delegate to individual nodes for IPAM.
     - list
     - ``[]``
   * - ipv4.enabled
     - Enable IPv4 support.
     - bool
     - ``true``
   * - ipv6.enabled
     - Enable IPv6 support.
     - bool
     - ``false``
   * - ipvlan.enabled
     - Enable the IPVLAN datapath (deprecated)
     - bool
     - ``false``
   * - k8s
     - Configure Kubernetes specific configuration
     - object
     - ``{}``
   * - keepDeprecatedLabels
     - Keep the deprecated selector labels when deploying Cilium DaemonSet.
     - bool
     - ``false``
   * - keepDeprecatedProbes
     - Keep the deprecated probes when deploying Cilium DaemonSet
     - bool
     - ``false``
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
   * - nodeinit.image
     - node-init image.
     - object
     - ``{"override":null,"pullPolicy":"Always","repository":"quay.io/cilium/startup-script","tag":"d69851597ea019af980891a4628fb36b7880ec26"}``
   * - nodeinit.nodeSelector
     - Node labels for nodeinit pod assignment ref: https://kubernetes.io/docs/user-guide/node-selection/
     - object
     - ``{}``
   * - nodeinit.podAnnotations
     - Annotations to be added to node-init pods.
     - object
     - ``{}``
   * - nodeinit.podLabels
     - Labels to be added to node-init pods.
     - object
     - ``{}``
   * - nodeinit.priorityClassName
     - The priority class to use for the nodeinit pod.
     - string
     - ``""``
   * - nodeinit.resources
     - nodeinit resource limits & requests ref: https://kubernetes.io/docs/user-guide/compute-resources/
     - object
     - ``{"requests":{"cpu":"100m","memory":"100Mi"}}``
   * - nodeinit.securityContext
     - Security context to be added to nodeinit pods.
     - object
     - ``{"privileged":true}``
   * - nodeinit.tolerations
     - Node tolerations for nodeinit scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
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
     - ``{"alibabacloudDigest":"","awsDigest":"","azureDigest":"","genericDigest":"","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/operator","suffix":"","tag":"latest","useDigest":false}``
   * - operator.nodeSelector
     - Node labels for cilium-operator pod assignment ref: https://kubernetes.io/docs/user-guide/node-selection/
     - object
     - ``{}``
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
   * - operator.priorityClassName
     - The priority class to use for cilium-operator
     - string
     - ``""``
   * - operator.prometheus
     - Enable prometheus metrics for cilium-operator on the configured port at /metrics
     - object
     - ``{"enabled":false,"port":6942,"serviceMonitor":{"annotations":{},"enabled":false,"labels":{}}}``
   * - operator.prometheus.serviceMonitor.annotations
     - Annotations to add to ServiceMonitor cilium-operator
     - object
     - ``{}``
   * - operator.prometheus.serviceMonitor.enabled
     - Enable service monitors. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/master/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml)
     - bool
     - ``false``
   * - operator.prometheus.serviceMonitor.labels
     - Labels to add to ServiceMonitor cilium-operator
     - object
     - ``{}``
   * - operator.replicas
     - Number of replicas to run for the cilium-operator deployment
     - int
     - ``2``
   * - operator.resources
     - cilium-operator resource limits & requests ref: https://kubernetes.io/docs/user-guide/compute-resources/
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
   * - operator.skipCRDCreation
     - Skip CRDs creation for cilium-operator
     - bool
     - ``false``
   * - operator.tolerations
     - Node tolerations for cilium-operator scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
     - list
     - ``[{"operator":"Exists"}]``
   * - operator.updateStrategy
     - cilium-operator update strategy
     - object
     - ``{"rollingUpdate":{"maxSurge":1,"maxUnavailable":1},"type":"RollingUpdate"}``
   * - podAnnotations
     - Annotations to be added to agent pods
     - object
     - ``{}``
   * - podLabels
     - Labels to be added to agent pods
     - object
     - ``{}``
   * - policyEnforcementMode
     - The agent can be put into one of the three policy enforcement modes: default, always and never. ref: https://docs.cilium.io/en/stable/policy/intro/#policy-enforcement-modes
     - string
     - ``"default"``
   * - pprof.enabled
     - Enable Go pprof debugging
     - bool
     - ``false``
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
   * - preflight.image
     - Cilium pre-flight image.
     - object
     - ``{"digest":"","override":null,"pullPolicy":"Always","repository":"quay.io/cilium/cilium","tag":"latest","useDigest":false}``
   * - preflight.nodeSelector
     - Node labels for preflight pod assignment ref: https://kubernetes.io/docs/user-guide/node-selection/
     - object
     - ``{}``
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
   * - preflight.priorityClassName
     - The priority class to use for the preflight pod.
     - string
     - ``""``
   * - preflight.resources
     - preflight resource limits & requests ref: https://kubernetes.io/docs/user-guide/compute-resources/
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
     - Node tolerations for preflight scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
     - list
     - ``[{"effect":"NoSchedule","key":"node.kubernetes.io/not-ready"},{"effect":"NoSchedule","key":"node-role.kubernetes.io/master"},{"effect":"NoSchedule","key":"node.cloudprovider.kubernetes.io/uninitialized","value":"true"},{"key":"CriticalAddonsOnly","operator":"Exists"}]``
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
     - ``{"enabled":false,"metrics":null,"port":9090,"serviceMonitor":{"annotations":{},"enabled":false,"labels":{}}}``
   * - prometheus.metrics
     - Metrics that should be enabled or disabled from the default metric list. (+metric_foo to enable metric_foo , -metric_bar to disable metric_bar). ref: https://docs.cilium.io/en/stable/operations/metrics/#exported-metrics
     - string
     - ``nil``
   * - prometheus.serviceMonitor.annotations
     - Annotations to add to ServiceMonitor cilium-agent
     - object
     - ``{}``
   * - prometheus.serviceMonitor.enabled
     - Enable service monitors. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/master/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml)
     - bool
     - ``false``
   * - prometheus.serviceMonitor.labels
     - Labels to add to ServiceMonitor cilium-agent
     - object
     - ``{}``
   * - proxy
     - Configure Istio proxy options.
     - object
     - ``{"prometheus":{"enabled":true,"port":"9095"},"sidecarImageRegex":"cilium/istio_proxy"}``
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
     - Agent resource limits & requests ref: https://kubernetes.io/docs/user-guide/compute-resources/
     - object
     - ``{}``
   * - rollOutCiliumPods
     - Roll out cilium agent pods automatically when configmap is updated.
     - bool
     - ``false``
   * - securityContext
     - Security context to be added to agent pods
     - object
     - ``{"privileged":false}``
   * - serviceAccounts
     - Define serviceAccount names for components.
     - object
     - Component's fully qualified name.
   * - serviceAccounts.clustermeshcertgen
     - Clustermeshcertgen is used if clustermesh.apiserver.tls.auto.method=cronJob
     - object
     - ``{"annotations":{},"create":true,"name":"clustermesh-apiserver-generate-certs"}``
   * - serviceAccounts.hubblecertgen
     - Hubblecertgen is used if hubble.tls.auto.method=cronJob
     - object
     - ``{"annotations":{},"create":true,"name":"hubble-generate-certs"}``
   * - sleepAfterInit
     - Do not run Cilium agent when running with clean mode. Useful to completely uninstall Cilium as it will stop Cilium from starting and create artifacts in the node.
     - bool
     - ``false``
   * - sockops
     - Configure BPF socket operations configuration
     - object
     - ``{"enabled":false}``
   * - startupProbe.failureThreshold
     - failure threshold of startup probe. 105 x 2s translates to the old behaviour of the readiness probe (120s delay + 30 x 3s)
     - int
     - ``105``
   * - startupProbe.periodSeconds
     - interval between checks of the startup probe
     - int
     - ``2``
   * - terminationGracePeriodSeconds
     - Configure termination grace period for cilium-agent DaemonSet.
     - int
     - ``1``
   * - tls
     - Configure TLS configuration in the agent.
     - object
     - ``{"ca":{"cert":"","certValidityDuration":1095,"key":""},"secretsBackend":"local"}``
   * - tls.ca
     - Base64 encoded PEM values for the CA certificate and private key. This can be used as common CA to generate certificates used by hubble and clustermesh components
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
   * - tls.secretsBackend
     - This configures how the Cilium agent loads the secrets used TLS-aware CiliumNetworkPolicies (namely the secrets referenced by terminatingTLS and originatingTLS). Possible values:   - local   - k8s
     - string
     - ``"local"``
   * - tolerations
     - Node tolerations for agent scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
     - list
     - ``[{"operator":"Exists"}]``
   * - tunnel
     - Configure the encapsulation configuration for communication between nodes. Possible values:   - disabled   - vxlan (default)   - geneve
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
   * - wellKnownIdentities.enabled
     - Enable the use of well-known identities.
     - bool
     - ``false``
