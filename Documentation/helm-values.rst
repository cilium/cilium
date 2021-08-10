..
  AUTO-GENERATED. Please DO NOT edit manually.


.. list-table::
   :header-rows: 1

   * - Key
     - Description
     - Type
     - Default
   * - affinity
     - Pod affinity for cilium-agent.
     - object
     - ``{"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"kubernetes.io/os","operator":"In","values":["linux"]}]},{"matchExpressions":[{"key":"beta.kubernetes.io/os","operator":"In","values":["linux"]}]}]}},"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchExpressions":[{"key":"k8s-app","operator":"In","values":["cilium"]}]},"topologyKey":"kubernetes.io/hostname"}]}}``
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
     - Optimize TCP and UDP workloads and enable rate-limiting traffic from individual Pods with EDT (Earliest Departure Time) through the "kubernetes.io/egress-bandwidth" Pod annotation.
     - bool
     - ``false``
   * - bgp
     - Configure BGP
     - object
     - ``{"announce":{"loadbalancerIP":false},"enabled":false}``
   * - bgp.announce.loadbalancerIP
     - Enable allocation and announcement of service LoadBalancer IPs
     - bool
     - ``false``
   * - bgp.enabled
     - Enable BGP support inside Cilium; embeds a new ConfigMap for BGP inside cilium-agent and cilium-operator
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
   * - certgen
     - Configure certificate generation for Hubble integration. If hubble.tls.auto.method=cronJob, these values are used for the Kubernetes CronJob which will be scheduled regularly to (re)generate any certificates not provided manually.
     - object
     - ``{"image":{"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/certgen","tag":"v0.1.5"},"podLabels":{},"ttlSecondsAfterFinished":1800}``
   * - certgen.podLabels
     - Labels to be added to hubble-certgen pods
     - object
     - ``{}``
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
   * - clustermesh.apiserver.etcd.image
     - Clustermesh API server etcd image.
     - object
     - ``{"pullPolicy":"IfNotPresent","repository":"quay.io/coreos/etcd","tag":"v3.4.13"}``
   * - clustermesh.apiserver.image
     - Clustermesh API server image.
     - object
     - ``{"digest":"sha256:44f1e4bcfafcf58784c418520fb0387f8d817ebe75cced493ef4f492a1199f2d","pullPolicy":"IfNotPresent","repository":"quay.io/cilium/clustermesh-apiserver","tag":"v1.10.3","useDigest":true}``
   * - clustermesh.apiserver.nodeSelector
     - Node labels for pod assignment ref: https://kubernetes.io/docs/user-guide/node-selection/
     - object
     - ``{}``
   * - clustermesh.apiserver.podAnnotations
     - Annotations to be added to clustermesh-apiserver pods
     - object
     - ``{}``
   * - clustermesh.apiserver.podLabels
     - Labels to be added to clustermesh-apiserver pods
     - object
     - ``{}``
   * - clustermesh.apiserver.replicas
     - Number of replicas run for the clustermesh-apiserver deployment.
     - int
     - ``1``
   * - clustermesh.apiserver.resources
     - Resource requests and limits for the clustermesh-apiserver container of the clustermesh-apiserver deployment, such as     resources:       limits:         cpu: 1000m         memory: 1024M       requests:         cpu: 100m         memory: 64Mi
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
     - ``{"certValidityDuration":1095,"enabled":true,"method":"helm"}``
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
     - ``{"cert":"","key":""}``
   * - clustermesh.apiserver.tolerations
     - Node tolerations for pod assignment on nodes with taints ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
     - list
     - ``[]``
   * - clustermesh.apiserver.updateStrategy
     - clustermesh-apiserver update strategy
     - object
     - ``{"rollingUpdate":{"maxUnavailable":1},"type":"RollingUpdate"}``
   * - clustermesh.useAPIServer
     - Deploy clustermesh-apiserver for clustermesh
     - bool
     - ``false``
   * - cni.binPath
     - Configure the path to the CNI binary directory on the host.
     - string
     - ``"/opt/cni/bin"``
   * - cni.chainingMode
     - Configure chaining on top of other CNI plugins. Possible values:  - none  - generic-veth  - aws-cni  - portmap
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
     - Configure which datapath mode should be used for configuring container connectivity. Valid options are "veth" or "ipvlan".
     - string
     - ``"veth"``
   * - debug.enabled
     - Enable debug logging
     - bool
     - ``false``
   * - egressGateway
     - Enables egress gateway (beta) to redirect and SNAT the traffic that leaves the cluster.
     - object
     - ``{"enabled":false}``
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
   * - enableXTSocketFallback
     - Enables the fallback compatibility solution for when the xt_socket kernel module is missing and it is needed for the datapath L7 redirection to work properly. See documentation for details on when this can be disabled: http://docs.cilium.io/en/stable/install/system_requirements/#admin-kernel-version.
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
   * - eni.subnetIDsFilter
     - Filter via subnet IDs which will dictate which subnets are going to be used to create new ENIs
     - string
     - ``""``
   * - eni.subnetTagsFilter
     - Filter via tags (k=v) which will dictate which subnets are going to be used to create new ENIs
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
   * - etcd.extraConfigmapMounts
     - Additional cilium-etcd-operator ConfigMap mounts.
     - list
     - ``[]``
   * - etcd.extraHostPathMounts
     - Additional cilium-etcd-operator hostPath mounts.
     - list
     - ``[]``
   * - etcd.extraInitContainers
     - Additional InitContainers to initialize the pod.
     - list
     - ``[]``
   * - etcd.image
     - cilium-etcd-operator image.
     - object
     - ``{"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/cilium-etcd-operator","tag":"v2.0.7"}``
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
   * - etcd.podDisruptionBudget
     - PodDisruptionBudget settings ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/
     - object
     - ``{"enabled":true,"maxUnavailable":2}``
   * - etcd.podLabels
     - Labels to be added to cilium-etcd-operator pods
     - object
     - ``{}``
   * - etcd.priorityClassName
     - cilium-etcd-operator priorityClassName
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
   * - extraConfigmapMounts
     - Additional agent ConfigMap mounts.
     - list
     - ``[]``
   * - extraEnv
     - Additional agent container environment variables.
     - object
     - ``{}``
   * - extraHostPathMounts
     - Additional agent hostPath mounts.
     - list
     - ``[]``
   * - extraInitContainers
     - Additional InitContainers to initialize the pod.
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
   * - hostFirewall
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
     - Hubble metrics configuration. See https://docs.cilium.io/en/stable/configuration/metrics/#hubble-metrics for more comprehensive documentation about Hubble metrics.
     - object
     - ``{"enabled":null,"port":9091,"serviceMonitor":{"enabled":false}}``
   * - hubble.metrics.enabled
     - Configures the list of metrics to collect. If empty or null, metrics are disabled. Example:   enabled:   - dns:query;ignoreAAAA   - drop   - tcp   - flow   - icmp   - http You can specify the list of metrics from the helm CLI:   --set metrics.enabled="{dns:query;ignoreAAAA,drop,tcp,flow,icmp,http}"
     - string
     - ``nil``
   * - hubble.metrics.port
     - Configure the port the hubble metric server listens on.
     - int
     - ``9091``
   * - hubble.metrics.serviceMonitor.enabled
     - Create ServiceMonitor resources for Prometheus Operator. This requires the prometheus CRDs to be available. ref: https://github.com/prometheus-operator/prometheus-operator/blob/master/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml)
     - bool
     - ``false``
   * - hubble.relay.dialTimeout
     - Dial timeout to connect to the local hubble instance to receive peer information (e.g. "30s").
     - string
     - ``nil``
   * - hubble.relay.enabled
     - Enable Hubble Relay (requires hubble.enabled=true)
     - bool
     - ``false``
   * - hubble.relay.image
     - Hubble-relay container image.
     - object
     - ``{"digest":"sha256:af8ff09fe374c307356a85b0e0c158359a2e7299f93280151301b7f2fac27339","pullPolicy":"IfNotPresent","repository":"quay.io/cilium/hubble-relay","tag":"v1.10.3","useDigest":true}``
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
   * - hubble.relay.podLabels
     - Labels to be added to hubble-relay pods
     - object
     - ``{}``
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
   * - hubble.relay.sortBufferDrainTimeout
     - When the per-request flows sort buffer is not full, a flow is drained every time this timeout is reached (only affects requests in follow-mode) (e.g. "1s").
     - string
     - ``nil``
   * - hubble.relay.sortBufferLenMax
     - Max number of flows that can be buffered for sorting before being sent to the client (per request) (e.g. 100).
     - string
     - ``nil``
   * - hubble.relay.tls
     - TLS configuration for Hubble Relay
     - object
     - ``{"client":{"cert":"","key":""},"server":{"cert":"","enabled":false,"key":""}}``
   * - hubble.relay.tls.client
     - base64 encoded PEM values for the hubble-relay client certificate and private key This keypair is presented to Hubble server instances for mTLS authentication and is required when hubble.tls.enabled is true. These values need to be set manually if hubble.tls.auto.enabled is false.
     - object
     - ``{"cert":"","key":""}``
   * - hubble.relay.tls.server
     - base64 encoded PEM values for the hubble-relay server certificate and private key
     - object
     - ``{"cert":"","enabled":false,"key":""}``
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
     - ``{"auto":{"certValidityDuration":1095,"enabled":true,"method":"helm","schedule":"0 0 1 */4 *"},"ca":{"cert":"","key":""},"enabled":true,"server":{"cert":"","key":""}}``
   * - hubble.tls.auto
     - Configure automatic TLS certificates generation.
     - object
     - ``{"certValidityDuration":1095,"enabled":true,"method":"helm","schedule":"0 0 1 */4 *"}``
   * - hubble.tls.auto.certValidityDuration
     - Generated certificates validity duration in days.
     - int
     - ``1095``
   * - hubble.tls.auto.enabled
     - Auto-generate certificates. When set to true, automatically generate a CA and certificates to enable mTLS between Hubble server and Hubble Relay instances. If set to false, the certs for Hubble server need to be provided by setting appropriate values below.
     - bool
     - ``true``
   * - hubble.tls.auto.method
     - Set the method to auto-generate certificates. Supported values: - helm:      This method uses Helm to generate all certificates. - cronJob:   This method uses a Kubernetes CronJob the generate any              certificates not provided by the user at installation              time.
     - string
     - ``"helm"``
   * - hubble.tls.auto.schedule
     - Schedule for certificates regeneration (regardless of their expiration date). Only used if method is "cronJob". If nil, then no recurring job will be created. Instead, only the one-shot job is deployed to generate the certificates at installation time. Defaults to midnight of the first day of every fourth month. For syntax, see https://kubernetes.io/docs/tasks/job/automated-tasks-with-cron-jobs/#schedule
     - string
     - ``"0 0 1 */4 *"``
   * - hubble.tls.ca
     - base64 encoded PEM values for the Hubble CA certificate and private key.
     - object
     - ``{"cert":"","key":""}``
   * - hubble.tls.ca.key
     - The CA private key (optional). If it is provided, then it will be used by hubble.tls.auto.method=cronJob to generate all other certificates. Otherwise, a ephemeral CA is generated if hubble.tls.auto.enabled=true.
     - string
     - ``""``
   * - hubble.tls.enabled
     - Enable mutual TLS for listenAddress. Setting this value to false is highly discouraged as the Hubble API provides access to potentially sensitive network flow metadata and is exposed on the host network.
     - bool
     - ``true``
   * - hubble.tls.server
     - base64 encoded PEM values for the Hubble server certificate and private key
     - object
     - ``{"cert":"","key":""}``
   * - hubble.ui.backend.image
     - Hubble-ui backend image.
     - object
     - ``{"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/hubble-ui-backend","tag":"v0.7.9@sha256:632c938ef6ff30e3a080c59b734afb1fb7493689275443faa1435f7141aabe76"}``
   * - hubble.ui.backend.resources
     - Resource requests and limits for the 'backend' container of the 'hubble-ui' deployment.
     - object
     - ``{}``
   * - hubble.ui.enabled
     - Whether to enable the Hubble UI.
     - bool
     - ``false``
   * - hubble.ui.frontend.image
     - Hubble-ui frontend image.
     - object
     - ``{"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/hubble-ui","tag":"v0.7.9@sha256:e0e461c680ccd083ac24fe4f9e19e675422485f04d8720635ec41f2ba9e5562c"}``
   * - hubble.ui.frontend.resources
     - Resource requests and limits for the 'frontend' container of the 'hubble-ui' deployment.
     - object
     - ``{}``
   * - hubble.ui.ingress
     - hubble-ui ingress configuration.
     - object
     - ``{"annotations":{},"enabled":false,"hosts":["chart-example.local"],"tls":[]}``
   * - hubble.ui.nodeSelector
     - Node labels for pod assignment ref: https://kubernetes.io/docs/user-guide/node-selection/
     - object
     - ``{}``
   * - hubble.ui.podAnnotations
     - Annotations to be added to hubble-ui pods
     - object
     - ``{}``
   * - hubble.ui.podLabels
     - Labels to be added to hubble-ui pods
     - object
     - ``{}``
   * - hubble.ui.proxy.image
     - Hubble-ui ingress proxy image.
     - object
     - ``{"pullPolicy":"IfNotPresent","repository":"docker.io/envoyproxy/envoy","tag":"v1.18.2@sha256:e8b37c1d75787dd1e712ff389b0d37337dc8a174a63bed9c34ba73359dc67da7"}``
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
     - ``{"digest":"sha256:8419531c5d3677158802882bdfe2297915c43f2ebe3649551aaac22de9f6d565","pullPolicy":"IfNotPresent","repository":"quay.io/cilium/cilium","tag":"v1.10.3","useDigest":true}``
   * - imagePullSecrets
     - Configure image pull secrets for pulling container images
     - string
     - ``nil``
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
     - IPv4 CIDR range to delegate to individual nodes for IPAM.
     - string
     - ``"10.0.0.0/8"``
   * - ipam.operator.clusterPoolIPv6MaskSize
     - IPv6 CIDR mask size to delegate to individual nodes for IPAM.
     - int
     - ``120``
   * - ipam.operator.clusterPoolIPv6PodCIDR
     - IPv6 CIDR range to delegate to individual nodes for IPAM.
     - string
     - ``"fd00::/104"``
   * - ipv4.enabled
     - Enable IPv4 support.
     - bool
     - ``true``
   * - ipv6.enabled
     - Enable IPv6 support.
     - bool
     - ``false``
   * - ipvlan.enabled
     - Enable the IPVLAN datapath
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
     - Specify the CIDR for native routing (ie to avoid IP masquerade for). This value corresponds to the configured cluster-cidr. nativeRoutingCIDR:
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
   * - nodeinit.bootstrapFile
     - bootstrapFile is the location of the file where the bootstrap timestamp is written by the node-init DaemonSet
     - string
     - ``"/tmp/cilium-bootstrap-time"``
   * - nodeinit.enabled
     - Enable the node initialization DaemonSet
     - bool
     - ``false``
   * - nodeinit.extraConfigmapMounts
     - Additional nodeinit ConfigMap mounts.
     - list
     - ``[]``
   * - nodeinit.extraEnv
     - Additional nodeinit environment variables.
     - object
     - ``{}``
   * - nodeinit.extraHostPathMounts
     - Additional nodeinit host path mounts.
     - list
     - ``[]``
   * - nodeinit.extraInitContainers
     - Additional nodeinit init containers.
     - list
     - ``[]``
   * - nodeinit.image
     - node-init image.
     - object
     - ``{"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/startup-script","tag":"62bfbe88c17778aad7bef9fa57ff9e2d4a9ba0d8"}``
   * - nodeinit.nodeSelector
     - Node labels for nodeinit pod assignment ref: https://kubernetes.io/docs/user-guide/node-selection/
     - object
     - ``{}``
   * - nodeinit.podAnnotations
     - Annotations to be added to node-init pods.
     - object
     - ``{}``
   * - nodeinit.podDisruptionBudget
     - PodDisruptionBudget settings ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/
     - object
     - ``{"enabled":true,"maxUnavailable":2}``
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
     - ``{}``
   * - nodeinit.tolerations
     - Node tolerations for nodeinit scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
     - list
     - ``[{"operator":"Exists"}]``
   * - nodeinit.updateStrategy
     - node-init update strategy
     - object
     - ``{"type":"RollingUpdate"}``
   * - operator.affinity
     - cilium-operator affinity
     - object
     - ``{"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchExpressions":[{"key":"io.cilium/app","operator":"In","values":["operator"]}]},"topologyKey":"kubernetes.io/hostname"}]}}``
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
   * - operator.extraConfigmapMounts
     - Additional cilium-operator ConfigMap mounts.
     - list
     - ``[]``
   * - operator.extraEnv
     - Additional cilium-operator environment variables.
     - object
     - ``{}``
   * - operator.extraHostPathMounts
     - Additional cilium-operator hostPath mounts.
     - list
     - ``[]``
   * - operator.extraInitContainers
     - Additional InitContainers to initialize the pod.
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
     - ``{"alibabacloudDigest":"sha256:291e05fef5c2ebebce785a985903a50075e539804b3e946aab8042fc526262b6","awsDigest":"sha256:d3aed74d90b9326959a33a6a354b16117942dac0017090380b1bc3a1dbe8be2d","azureDigest":"sha256:8cba20e22205d3a9fbcbed8bfc11bdd4d8e2fd5b0ce08f6e0f35f441ddc1de7e","genericDigest":"sha256:337ebf27eae4fbad51cc4baf9110b3ec6753320dd33075bc136e2a1865be5eb5","pullPolicy":"IfNotPresent","repository":"quay.io/cilium/operator","suffix":"","tag":"v1.10.3","useDigest":true}``
   * - operator.nodeSelector
     - Node labels for cilium-operator pod assignment ref: https://kubernetes.io/docs/user-guide/node-selection/
     - object
     - ``{}``
   * - operator.podAnnotations
     - Annotations to be added to cilium-operator pods
     - object
     - ``{}``
   * - operator.podDisruptionBudget
     - PodDisruptionBudget settings ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/
     - object
     - ``{"enabled":false,"maxUnavailable":1}``
   * - operator.podLabels
     - Labels to be added to cilium-operator pods
     - object
     - ``{}``
   * - operator.priorityClassName
     - cilium-operator priorityClassName
     - string
     - ``""``
   * - operator.prometheus
     - Enable prometheus metrics for cilium-operator on the configured port at /metrics
     - object
     - ``{"enabled":false,"port":6942,"serviceMonitor":{"enabled":false}}``
   * - operator.prometheus.serviceMonitor.enabled
     - Enable service monitors. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/master/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml)
     - bool
     - ``false``
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
   * - operator.serviceAccountName
     - For using with an existing serviceAccount.
     - string
     - ``"cilium-operator"``
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
   * - podDisruptionBudget
     - PodDisruptionBudget settings ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/
     - object
     - ``{"enabled":true,"maxUnavailable":2}``
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
   * - preflight.enabled
     - Enable Cilium pre-flight resources (required for upgrade)
     - bool
     - ``false``
   * - preflight.extraConfigmapMounts
     - Additional preflight ConfigMap mounts.
     - list
     - ``[]``
   * - preflight.extraEnv
     - Additional preflight environment variables.
     - object
     - ``{}``
   * - preflight.extraHostPathMounts
     - Additional preflight host path mounts.
     - list
     - ``[]``
   * - preflight.extraInitContainers
     - Additional preflight init containers.
     - list
     - ``[]``
   * - preflight.image
     - Cilium pre-flight image.
     - object
     - ``{"digest":"sha256:8419531c5d3677158802882bdfe2297915c43f2ebe3649551aaac22de9f6d565","pullPolicy":"IfNotPresent","repository":"quay.io/cilium/cilium","tag":"v1.10.3","useDigest":true}``
   * - preflight.nodeSelector
     - Node labels for preflight pod assignment ref: https://kubernetes.io/docs/user-guide/node-selection/
     - object
     - ``{}``
   * - preflight.podAnnotations
     - Annotations to be added to preflight pods
     - object
     - ``{}``
   * - preflight.podDisruptionBudget
     - PodDisruptionBudget settings ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/
     - object
     - ``{"enabled":true,"maxUnavailable":2}``
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
     - ``{"enabled":false,"metrics":null,"port":9090,"serviceMonitor":{"enabled":false}}``
   * - prometheus.metrics
     - Metrics that should be enabled or disabled from the default metric list. (+metric_foo to enable metric_foo , -metric_bar to disable metric_bar). ref: https://docs.cilium.io/en/stable/operations/metrics/#exported-metrics
     - string
     - ``nil``
   * - prometheus.serviceMonitor.enabled
     - Enable service monitors. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/master/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml)
     - bool
     - ``false``
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
     - ``{}``
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
   * - tls
     - Configure TLS configuration in the agent.
     - object
     - ``{"enabled":true,"secretsBackend":"local"}``
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
   * - wellKnownIdentities.enabled
     - Enable the use of well-known identities.
     - bool
     - ``false``
