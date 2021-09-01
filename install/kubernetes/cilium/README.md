# cilium

![Version: 1.10.4](https://img.shields.io/badge/Version-1.10.4-informational?style=flat-square) ![AppVersion: 1.10.4](https://img.shields.io/badge/AppVersion-1.10.4-informational?style=flat-square)

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

![Cilium feature overview](https://raw.githubusercontent.com/cilium/cilium/master/Documentation/images/cilium_overview.png)

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
offer from the [Getting Started Guides page](https://docs.cilium.io/en/latest/gettingstarted/).

## Source Code

* <https://github.com/cilium/cilium>

## Getting Help

The best way to get help if you get stuck is to ask a question on the
[Cilium Slack channel](https://cilium.herokuapp.com/). With Cilium
contributors across the globe, there is almost always someone available to help.

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"kubernetes.io/os","operator":"In","values":["linux"]}]},{"matchExpressions":[{"key":"beta.kubernetes.io/os","operator":"In","values":["linux"]}]}]}},"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchExpressions":[{"key":"k8s-app","operator":"In","values":["cilium"]}]},"topologyKey":"kubernetes.io/hostname"}]}}` | Pod affinity for cilium-agent. |
| agent | bool | `true` | Install the cilium agent resources. |
| alibabacloud.enabled | bool | `false` | Enable AlibabaCloud ENI integration |
| autoDirectNodeRoutes | bool | `false` | Enable installation of PodCIDR routes between worker nodes if worker nodes share a common L2 network segment. |
| azure.enabled | bool | `false` | Enable Azure integration |
| bandwidthManager | bool | `false` | Optimize TCP and UDP workloads and enable rate-limiting traffic from individual Pods with EDT (Earliest Departure Time) through the "kubernetes.io/egress-bandwidth" Pod annotation. |
| bgp | object | `{"announce":{"loadbalancerIP":false},"enabled":false}` | Configure BGP |
| bgp.announce.loadbalancerIP | bool | `false` | Enable allocation and announcement of service LoadBalancer IPs |
| bgp.enabled | bool | `false` | Enable BGP support inside Cilium; embeds a new ConfigMap for BGP inside cilium-agent and cilium-operator |
| bpf.clockProbe | bool | `false` | Enable BPF clock source probing for more efficient tick retrieval. |
| bpf.lbExternalClusterIP | bool | `false` | Allow cluster external access to ClusterIP services. |
| bpf.lbMapMax | int | `65536` | Configure the maximum number of service entries in the load balancer maps. |
| bpf.monitorAggregation | string | `"medium"` | Configure the level of aggregation for monitor notifications. Valid options are none, low, medium, maximum. |
| bpf.monitorFlags | string | `"all"` | Configure which TCP flags trigger notifications when seen for the first time in a connection. |
| bpf.monitorInterval | string | `"5s"` | Configure the typical time between monitor notifications for active connections. |
| bpf.policyMapMax | int | `16384` | Configure the maximum number of entries in endpoint policy map (per endpoint). |
| bpf.preallocateMaps | bool | `false` | Enables pre-allocation of eBPF map values. This increases memory usage but can reduce latency. |
| certgen | object | `{"image":{"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/certgen","tag":"v0.1.4"},"podLabels":{},"ttlSecondsAfterFinished":1800}` | Configure certificate generation for Hubble integration. If hubble.tls.auto.method=cronJob, these values are used for the Kubernetes CronJob which will be scheduled regularly to (re)generate any certificates not provided manually. |
| certgen.podLabels | object | `{}` | Labels to be added to hubble-certgen pods |
| certgen.ttlSecondsAfterFinished | int | `1800` | Seconds after which the completed job pod will be deleted |
| cgroup | object | `{"autoMount":{"enabled":true},"hostRoot":"/run/cilium/cgroupv2"}` | Configure cgroup related configuration |
| cgroup.autoMount.enabled | bool | `true` | Enable auto mount of cgroup2 filesystem. When `autoMount` is enabled, cgroup2 filesystem is mounted at `cgroup.hostRoot` path on the underlying host and inside the cilium agent pod. If users disable `autoMount`, it's expected that users have mounted cgroup2 filesystem at the specified `cgroup.hostRoot` volume, and then the volume will be mounted inside the cilium agent pod at the same path. |
| cgroup.hostRoot | string | `"/run/cilium/cgroupv2"` | Configure cgroup root where cgroup2 filesystem is mounted on the host (see also: `cgroup.autoMount`) |
| cleanBpfState | bool | `false` | Clean all eBPF datapath state from the initContainer of the cilium-agent DaemonSet. WARNING: Use with care! |
| cleanState | bool | `false` | Clean all local Cilium state from the initContainer of the cilium-agent DaemonSet. Implies cleanBpfState: true. WARNING: Use with care! |
| cluster.id | int | `nil` | Unique ID of the cluster. Must be unique across all connected clusters and in the range of 1 to 255. Only required for Cluster Mesh. |
| cluster.name | string | `"default"` | Name of the cluster. Only required for Cluster Mesh. |
| clustermesh.apiserver.etcd.image | object | `{"pullPolicy":"IfNotPresent","repository":"quay.io/coreos/etcd","tag":"v3.4.13"}` | Clustermesh API server etcd image. |
| clustermesh.apiserver.image | object | `{"digest":"","pullPolicy":"IfNotPresent","repository":"quay.io/cilium/clustermesh-apiserver","tag":"v1.10.4","useDigest":false}` | Clustermesh API server image. |
| clustermesh.apiserver.nodeSelector | object | `{}` | Node labels for pod assignment ref: https://kubernetes.io/docs/user-guide/node-selection/ |
| clustermesh.apiserver.podAnnotations | object | `{}` | Annotations to be added to clustermesh-apiserver pods |
| clustermesh.apiserver.podLabels | object | `{}` | Labels to be added to clustermesh-apiserver pods |
| clustermesh.apiserver.replicas | int | `1` | Number of replicas run for the clustermesh-apiserver deployment. |
| clustermesh.apiserver.resources | object | `{}` | Resource requests and limits for the clustermesh-apiserver container of the clustermesh-apiserver deployment, such as     resources:       limits:         cpu: 1000m         memory: 1024M       requests:         cpu: 100m         memory: 64Mi |
| clustermesh.apiserver.service.annotations | object | `{}` | Annotations for the clustermesh-apiserver For GKE LoadBalancer, use annotation cloud.google.com/load-balancer-type: "Internal" For EKS LoadBalancer, use annotation service.beta.kubernetes.io/aws-load-balancer-internal: 0.0.0.0/0 |
| clustermesh.apiserver.service.nodePort | int | `32379` | Optional port to use as the node port for apiserver access. |
| clustermesh.apiserver.service.type | string | `"NodePort"` | The type of service used for apiserver access. |
| clustermesh.apiserver.tls.admin | object | `{"cert":"","key":""}` | base64 encoded PEM values for the clustermesh-apiserver admin certificate and private key. Used if 'auto' is not enabled. |
| clustermesh.apiserver.tls.auto | object | `{"certValidityDuration":1095,"enabled":true,"method":"helm"}` | Configure automatic TLS certificates generation. A Kubernetes CronJob is used the generate any certificates not provided by the user at installation time. |
| clustermesh.apiserver.tls.auto.certValidityDuration | int | `1095` | Generated certificates validity duration in days. |
| clustermesh.apiserver.tls.auto.enabled | bool | `true` | When set to true, automatically generate a CA and certificates to enable mTLS between clustermesh-apiserver and external workload instances. If set to false, the certs to be provided by setting appropriate values below. |
| clustermesh.apiserver.tls.ca | object | `{"cert":"","key":""}` | base64 encoded PEM values for the ExternalWorkload CA certificate and private key. |
| clustermesh.apiserver.tls.ca.cert | string | `""` | Optional CA cert. If it is provided, it will be used by the 'cronJob' method to generate all other certificates. Otherwise, an ephemeral CA is generated. |
| clustermesh.apiserver.tls.ca.key | string | `""` | Optional CA private key. If it is provided, it will be used by the 'cronJob' method to generate all other certificates. Otherwise, an ephemeral CA is generated. |
| clustermesh.apiserver.tls.client | object | `{"cert":"","key":""}` | base64 encoded PEM values for the clustermesh-apiserver client certificate and private key. Used if 'auto' is not enabled. |
| clustermesh.apiserver.tls.remote | object | `{"cert":"","key":""}` | base64 encoded PEM values for the clustermesh-apiserver remote cluster certificate and private key. Used if 'auto' is not enabled. |
| clustermesh.apiserver.tls.server | object | `{"cert":"","key":""}` | base64 encoded PEM values for the clustermesh-apiserver server certificate and private key. Used if 'auto' is not enabled. |
| clustermesh.apiserver.tolerations | list | `[]` | Node tolerations for pod assignment on nodes with taints ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/ |
| clustermesh.apiserver.updateStrategy | object | `{"rollingUpdate":{"maxUnavailable":1},"type":"RollingUpdate"}` | clustermesh-apiserver update strategy |
| clustermesh.useAPIServer | bool | `false` | Deploy clustermesh-apiserver for clustermesh |
| cni.binPath | string | `"/opt/cni/bin"` | Configure the path to the CNI binary directory on the host. |
| cni.chainingMode | string | `"none"` | Configure chaining on top of other CNI plugins. Possible values:  - none  - generic-veth  - aws-cni  - portmap |
| cni.confFileMountPath | string | `"/tmp/cni-configuration"` | Configure the path to where to mount the ConfigMap inside the agent pod. |
| cni.confPath | string | `"/etc/cni/net.d"` | Configure the path to the CNI configuration directory on the host. |
| cni.configMapKey | string | `"cni-config"` | Configure the key in the CNI ConfigMap to read the contents of the CNI configuration from. |
| cni.customConf | bool | `false` | Skip writing of the CNI configuration. This can be used if writing of the CNI configuration is performed by external automation. |
| cni.exclusive | bool | `true` | Make Cilium take ownership over the `/etc/cni/net.d` directory on the node, renaming all non-Cilium CNI configurations to `*.cilium_bak`. This ensures no Pods can be scheduled using other CNI plugins during Cilium agent downtime. |
| cni.hostConfDirMountPath | string | `"/host/etc/cni/net.d"` | Configure the path to where the CNI configuration directory is mounted inside the agent pod. |
| cni.install | bool | `true` | Install the CNI configuration and binary files into the filesystem. |
| containerRuntime | object | `{"integration":"none"}` | Configure container runtime specific integration. |
| containerRuntime.integration | string | `"none"` | Enables specific integrations for container runtimes. Supported values: - containerd - crio - docker - none - auto (automatically detect the container runtime) |
| customCalls | object | `{"enabled":false}` | Tail call hooks for custom eBPF programs. |
| customCalls.enabled | bool | `false` | Enable tail call hooks for custom eBPF programs. |
| daemon.runPath | string | `"/var/run/cilium"` | Configure where Cilium runtime state should be stored. |
| datapathMode | string | `"veth"` | Configure which datapath mode should be used for configuring container connectivity. Valid options are "veth" or "ipvlan". |
| debug.enabled | bool | `false` | Enable debug logging |
| egressGateway | object | `{"enabled":false}` | Enables egress gateway (beta) to redirect and SNAT the traffic that leaves the cluster. |
| enableCnpStatusUpdates | bool | `false` | Whether to enable CNP status updates. |
| enableCriticalPriorityClass | bool | `true` | Explicitly enable or disable priority class. .Capabilities.KubeVersion is unsettable in `helm template` calls, it depends on k8s libraries version that Helm was compiled against. This option allows to explicitly disable setting the priority class, which is useful for rendering charts for gke clusters in advance. |
| enableIPv4Masquerade | bool | `true` | Enables masquerading of IPv4 traffic leaving the node from endpoints. |
| enableIPv6Masquerade | bool | `true` | Enables masquerading of IPv6 traffic leaving the node from endpoints. |
| enableK8sEventHandover | bool | `false` | Configures the use of the KVStore to optimize Kubernetes event handling by mirroring it into the KVstore for reduced overhead in large clusters. |
| enableXTSocketFallback | bool | `true` | Enables the fallback compatibility solution for when the xt_socket kernel module is missing and it is needed for the datapath L7 redirection to work properly. See documentation for details on when this can be disabled: http://docs.cilium.io/en/stable/install/system_requirements/#admin-kernel-version. |
| encryption.enabled | bool | `false` | Enable transparent network encryption. |
| encryption.interface | string | `""` | Deprecated in favor of encryption.ipsec.interface. The interface to use for encrypted traffic. This option is only effective when encryption.type is set to ipsec. |
| encryption.ipsec.interface | string | `""` | The interface to use for encrypted traffic. |
| encryption.ipsec.keyFile | string | `""` | Name of the key file inside the Kubernetes secret configured via secretName. |
| encryption.ipsec.mountPath | string | `""` | Path to mount the secret inside the Cilium pod. |
| encryption.ipsec.secretName | string | `""` | Name of the Kubernetes secret containing the encryption keys. |
| encryption.keyFile | string | `"keys"` | Deprecated in favor of encryption.ipsec.keyFile. Name of the key file inside the Kubernetes secret configured via secretName. This option is only effective when encryption.type is set to ipsec. |
| encryption.mountPath | string | `"/etc/ipsec"` | Deprecated in favor of encryption.ipsec.mountPath. Path to mount the secret inside the Cilium pod. This option is only effective when encryption.type is set to ipsec. |
| encryption.nodeEncryption | bool | `false` | Enable encryption for pure node to node traffic. This option is only effective when encryption.type is set to ipsec. |
| encryption.secretName | string | `"cilium-ipsec-keys"` | Deprecated in favor of encryption.ipsec.secretName. Name of the Kubernetes secret containing the encryption keys. This option is only effective when encryption.type is set to ipsec. |
| encryption.type | string | `"ipsec"` | Encryption method. Can be either ipsec or wireguard. |
| endpointHealthChecking.enabled | bool | `true` | Enable connectivity health checking between virtual endpoints. |
| endpointRoutes.enabled | bool | `false` | Enable use of per endpoint routes instead of routing via the cilium_host interface. |
| endpointStatus | object | `{"enabled":false,"status":""}` | Enable endpoint status. Status can be: policy, health, controllers, logs and / or state. For 2 or more options use a comma. |
| eni.awsReleaseExcessIPs | bool | `false` | Release IPs not used from the ENI |
| eni.ec2APIEndpoint | string | `""` | EC2 API endpoint to use |
| eni.enabled | bool | `false` | Enable Elastic Network Interface (ENI) integration. |
| eni.eniTags | object | `{}` | Tags to apply to the newly created ENIs |
| eni.iamRole | string | `""` | If using IAM role for Service Accounts will not try to inject identity values from cilium-aws kubernetes secret. Adds annotation to service account if managed by Helm. See https://github.com/aws/amazon-eks-pod-identity-webhook |
| eni.subnetIDsFilter | string | `""` | Filter via subnet IDs which will dictate which subnets are going to be used to create new ENIs |
| eni.subnetTagsFilter | string | `""` | Filter via tags (k=v) which will dictate which subnets are going to be used to create new ENIs |
| eni.updateEC2AdapterLimitViaAPI | bool | `false` | Update ENI Adapter limits from the EC2 API |
| etcd.clusterDomain | string | `"cluster.local"` | Cluster domain for cilium-etcd-operator. |
| etcd.enabled | bool | `false` | Enable etcd mode for the agent. |
| etcd.endpoints | list | `["https://CHANGE-ME:2379"]` | List of etcd endpoints (not needed when using managed=true). |
| etcd.extraArgs | list | `[]` | Additional cilium-etcd-operator container arguments. |
| etcd.extraConfigmapMounts | list | `[]` | Additional cilium-etcd-operator ConfigMap mounts. |
| etcd.extraHostPathMounts | list | `[]` | Additional cilium-etcd-operator hostPath mounts. |
| etcd.extraInitContainers | list | `[]` | Additional InitContainers to initialize the pod. |
| etcd.image | object | `{"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/cilium-etcd-operator","tag":"v2.0.7"}` | cilium-etcd-operator image. |
| etcd.k8sService | bool | `false` | If etcd is behind a k8s service set this option to true so that Cilium does the service translation automatically without requiring a DNS to be running. |
| etcd.nodeSelector | object | `{}` | Node labels for cilium-etcd-operator pod assignment ref: https://kubernetes.io/docs/user-guide/node-selection/ |
| etcd.podAnnotations | object | `{}` | Annotations to be added to cilium-etcd-operator pods |
| etcd.podDisruptionBudget | object | `{"enabled":true,"maxUnavailable":2}` | PodDisruptionBudget settings ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/ |
| etcd.podLabels | object | `{}` | Labels to be added to cilium-etcd-operator pods |
| etcd.priorityClassName | string | `""` | cilium-etcd-operator priorityClassName |
| etcd.resources | object | `{}` | cilium-etcd-operator resource limits & requests ref: https://kubernetes.io/docs/user-guide/compute-resources/ |
| etcd.securityContext | object | `{}` | Security context to be added to cilium-etcd-operator pods |
| etcd.ssl | bool | `false` | Enable use of TLS/SSL for connectivity to etcd. (auto-enabled if managed=true) |
| etcd.tolerations | list | `[{"operator":"Exists"}]` | Node tolerations for cilium-etcd-operator scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/ |
| etcd.updateStrategy | object | `{"rollingUpdate":{"maxSurge":1,"maxUnavailable":1},"type":"RollingUpdate"}` | cilium-etcd-operator update strategy |
| externalIPs.enabled | bool | `false` | Enable ExternalIPs service support. |
| externalWorkloads | object | `{"enabled":false}` | Configure external workloads support |
| externalWorkloads.enabled | bool | `false` | Enable support for external workloads, such as VMs (false by default). |
| extraArgs | list | `[]` | Additional agent container arguments. |
| extraConfig | object | `{}` | extraConfig allows you to specify additional configuration parameters to be included in the cilium-config configmap. |
| extraConfigmapMounts | list | `[]` | Additional agent ConfigMap mounts. |
| extraEnv | object | `{}` | Additional agent container environment variables. |
| extraHostPathMounts | list | `[]` | Additional agent hostPath mounts. |
| extraInitContainers | list | `[]` | Additional InitContainers to initialize the pod. |
| gke.enabled | bool | `false` | Enable Google Kubernetes Engine integration |
| healthChecking | bool | `true` | Enable connectivity health checking. |
| healthPort | int | `9876` | TCP port for the agent health API. This is not the port for cilium-health. |
| hostFirewall | bool | `false` | Enables the enforcement of host policies in the eBPF datapath. |
| hostPort.enabled | bool | `false` | Enable hostPort service support. |
| hostServices | object | `{"enabled":false,"protocols":"tcp,udp"}` | Configure ClusterIP service handling in the host namespace (the node). |
| hostServices.enabled | bool | `false` | Enable host reachable services. |
| hostServices.protocols | string | `"tcp,udp"` | Supported list of protocols to apply ClusterIP translation to. |
| hubble.enabled | bool | `true` | Enable Hubble (true by default). |
| hubble.listenAddress | string | `":4244"` | An additional address for Hubble to listen to. Set this field ":4244" if you are enabling Hubble Relay, as it assumes that Hubble is listening on port 4244. |
| hubble.metrics | object | `{"enabled":null,"port":9091,"serviceMonitor":{"enabled":false}}` | Hubble metrics configuration. See https://docs.cilium.io/en/stable/configuration/metrics/#hubble-metrics for more comprehensive documentation about Hubble metrics. |
| hubble.metrics.enabled | string | `nil` | Configures the list of metrics to collect. If empty or null, metrics are disabled. Example:   enabled:   - dns:query;ignoreAAAA   - drop   - tcp   - flow   - icmp   - http You can specify the list of metrics from the helm CLI:   --set metrics.enabled="{dns:query;ignoreAAAA,drop,tcp,flow,icmp,http}" |
| hubble.metrics.port | int | `9091` | Configure the port the hubble metric server listens on. |
| hubble.metrics.serviceMonitor.enabled | bool | `false` | Create ServiceMonitor resources for Prometheus Operator. This requires the prometheus CRDs to be available. ref: https://github.com/prometheus-operator/prometheus-operator/blob/master/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml) |
| hubble.relay.dialTimeout | string | `nil` | Dial timeout to connect to the local hubble instance to receive peer information (e.g. "30s"). |
| hubble.relay.enabled | bool | `false` | Enable Hubble Relay (requires hubble.enabled=true) |
| hubble.relay.image | object | `{"digest":"","pullPolicy":"IfNotPresent","repository":"quay.io/cilium/hubble-relay","tag":"v1.10.4","useDigest":false}` | Hubble-relay container image. |
| hubble.relay.listenHost | string | `""` | Host to listen to. Specify an empty string to bind to all the interfaces. |
| hubble.relay.listenPort | string | `"4245"` | Port to listen to. |
| hubble.relay.nodeSelector | object | `{}` | Node labels for pod assignment ref: https://kubernetes.io/docs/user-guide/node-selection/ |
| hubble.relay.podAnnotations | object | `{}` | Annotations to be added to hubble-relay pods |
| hubble.relay.podLabels | object | `{}` | Labels to be added to hubble-relay pods |
| hubble.relay.replicas | int | `1` | Number of replicas run for the hubble-relay deployment. |
| hubble.relay.resources | object | `{}` | Specifies the resources for the hubble-relay pods |
| hubble.relay.retryTimeout | string | `nil` | Backoff duration to retry connecting to the local hubble instance in case of failure (e.g. "30s"). |
| hubble.relay.rollOutPods | bool | `false` | Roll out Hubble Relay pods automatically when configmap is updated. |
| hubble.relay.sortBufferDrainTimeout | string | `nil` | When the per-request flows sort buffer is not full, a flow is drained every time this timeout is reached (only affects requests in follow-mode) (e.g. "1s"). |
| hubble.relay.sortBufferLenMax | string | `nil` | Max number of flows that can be buffered for sorting before being sent to the client (per request) (e.g. 100). |
| hubble.relay.tls | object | `{"client":{"cert":"","key":""},"server":{"cert":"","enabled":false,"key":""}}` | TLS configuration for Hubble Relay |
| hubble.relay.tls.client | object | `{"cert":"","key":""}` | base64 encoded PEM values for the hubble-relay client certificate and private key This keypair is presented to Hubble server instances for mTLS authentication and is required when hubble.tls.enabled is true. These values need to be set manually if hubble.tls.auto.enabled is false. |
| hubble.relay.tls.server | object | `{"cert":"","enabled":false,"key":""}` | base64 encoded PEM values for the hubble-relay server certificate and private key |
| hubble.relay.tolerations | list | `[]` | Node tolerations for pod assignment on nodes with taints ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/ |
| hubble.relay.updateStrategy | object | `{"rollingUpdate":{"maxUnavailable":1},"type":"RollingUpdate"}` | hubble-relay update strategy |
| hubble.socketPath | string | `"/var/run/cilium/hubble.sock"` | Unix domain socket path to listen to when Hubble is enabled. |
| hubble.tls | object | `{"auto":{"certValidityDuration":1095,"enabled":true,"method":"helm","schedule":"0 0 1 */4 *"},"ca":{"cert":"","key":""},"enabled":true,"server":{"cert":"","key":""}}` | TLS configuration for Hubble |
| hubble.tls.auto | object | `{"certValidityDuration":1095,"enabled":true,"method":"helm","schedule":"0 0 1 */4 *"}` | Configure automatic TLS certificates generation. |
| hubble.tls.auto.certValidityDuration | int | `1095` | Generated certificates validity duration in days. |
| hubble.tls.auto.enabled | bool | `true` | Auto-generate certificates. When set to true, automatically generate a CA and certificates to enable mTLS between Hubble server and Hubble Relay instances. If set to false, the certs for Hubble server need to be provided by setting appropriate values below. |
| hubble.tls.auto.method | string | `"helm"` | Set the method to auto-generate certificates. Supported values: - helm:      This method uses Helm to generate all certificates. - cronJob:   This method uses a Kubernetes CronJob the generate any              certificates not provided by the user at installation              time. |
| hubble.tls.auto.schedule | string | `"0 0 1 */4 *"` | Schedule for certificates regeneration (regardless of their expiration date). Only used if method is "cronJob". If nil, then no recurring job will be created. Instead, only the one-shot job is deployed to generate the certificates at installation time. Defaults to midnight of the first day of every fourth month. For syntax, see https://kubernetes.io/docs/tasks/job/automated-tasks-with-cron-jobs/#schedule |
| hubble.tls.ca | object | `{"cert":"","key":""}` | base64 encoded PEM values for the Hubble CA certificate and private key. |
| hubble.tls.ca.key | string | `""` | The CA private key (optional). If it is provided, then it will be used by hubble.tls.auto.method=cronJob to generate all other certificates. Otherwise, a ephemeral CA is generated if hubble.tls.auto.enabled=true. |
| hubble.tls.enabled | bool | `true` | Enable mutual TLS for listenAddress. Setting this value to false is highly discouraged as the Hubble API provides access to potentially sensitive network flow metadata and is exposed on the host network. |
| hubble.tls.server | object | `{"cert":"","key":""}` | base64 encoded PEM values for the Hubble server certificate and private key |
| hubble.ui.backend.image | object | `{"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/hubble-ui-backend","tag":"v0.7.9@sha256:632c938ef6ff30e3a080c59b734afb1fb7493689275443faa1435f7141aabe76"}` | Hubble-ui backend image. |
| hubble.ui.backend.resources | object | `{}` | Resource requests and limits for the 'backend' container of the 'hubble-ui' deployment. |
| hubble.ui.enabled | bool | `false` | Whether to enable the Hubble UI. |
| hubble.ui.frontend.image | object | `{"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/hubble-ui","tag":"v0.7.9@sha256:e0e461c680ccd083ac24fe4f9e19e675422485f04d8720635ec41f2ba9e5562c"}` | Hubble-ui frontend image. |
| hubble.ui.frontend.resources | object | `{}` | Resource requests and limits for the 'frontend' container of the 'hubble-ui' deployment. |
| hubble.ui.ingress | object | `{"annotations":{},"enabled":false,"hosts":["chart-example.local"],"tls":[]}` | hubble-ui ingress configuration. |
| hubble.ui.nodeSelector | object | `{}` | Node labels for pod assignment ref: https://kubernetes.io/docs/user-guide/node-selection/ |
| hubble.ui.podAnnotations | object | `{}` | Annotations to be added to hubble-ui pods |
| hubble.ui.podLabels | object | `{}` | Labels to be added to hubble-ui pods |
| hubble.ui.proxy.image | object | `{"pullPolicy":"IfNotPresent","repository":"docker.io/envoyproxy/envoy","tag":"v1.18.2@sha256:e8b37c1d75787dd1e712ff389b0d37337dc8a174a63bed9c34ba73359dc67da7"}` | Hubble-ui ingress proxy image. |
| hubble.ui.proxy.resources | object | `{}` | Resource requests and limits for the 'proxy' container of the 'hubble-ui' deployment. |
| hubble.ui.replicas | int | `1` | The number of replicas of Hubble UI to deploy. |
| hubble.ui.rollOutPods | bool | `false` | Roll out Hubble-ui pods automatically when configmap is updated. |
| hubble.ui.securityContext.enabled | bool | `true` | Whether to set the security context on the Hubble UI pods. |
| hubble.ui.tolerations | list | `[]` | Node tolerations for pod assignment on nodes with taints ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/ |
| hubble.ui.updateStrategy | object | `{"rollingUpdate":{"maxUnavailable":1},"type":"RollingUpdate"}` | hubble-ui update strategy. |
| identityAllocationMode | string | `"crd"` | Method to use for identity allocation (`crd` or `kvstore`). |
| image | object | `{"digest":"","pullPolicy":"IfNotPresent","repository":"quay.io/cilium/cilium","tag":"v1.10.4","useDigest":false}` | Agent container image. |
| imagePullSecrets | string | `nil` | Configure image pull secrets for pulling container images |
| installIptablesRules | bool | `true` | Configure whether to install iptables rules to allow for TPROXY (L7 proxy injection), iptables-based masquerading and compatibility with kube-proxy. |
| installNoConntrackIptablesRules | bool | `false` | Install Iptables rules to skip netfilter connection tracking on all pod traffic. This option is only effective when Cilium is running in direct routing and full KPR mode. Moreover, this option cannot be enabled when Cilium is running in a managed Kubernetes environment or in a chained CNI setup. |
| ipMasqAgent | object | `{"enabled":false}` | Configure the eBPF-based ip-masq-agent |
| ipam.mode | string | `"cluster-pool"` | Configure IP Address Management mode. ref: https://docs.cilium.io/en/stable/concepts/networking/ipam/ |
| ipam.operator.clusterPoolIPv4MaskSize | int | `24` | IPv4 CIDR mask size to delegate to individual nodes for IPAM. |
| ipam.operator.clusterPoolIPv4PodCIDR | string | `"10.0.0.0/8"` | IPv4 CIDR range to delegate to individual nodes for IPAM. |
| ipam.operator.clusterPoolIPv6MaskSize | int | `120` | IPv6 CIDR mask size to delegate to individual nodes for IPAM. |
| ipam.operator.clusterPoolIPv6PodCIDR | string | `"fd00::/104"` | IPv6 CIDR range to delegate to individual nodes for IPAM. |
| ipv4.enabled | bool | `true` | Enable IPv4 support. |
| ipv6.enabled | bool | `false` | Enable IPv6 support. |
| ipvlan.enabled | bool | `false` | Enable the IPVLAN datapath |
| k8s | object | `{}` | Configure Kubernetes specific configuration |
| keepDeprecatedLabels | bool | `false` | Keep the deprecated selector labels when deploying Cilium DaemonSet. |
| keepDeprecatedProbes | bool | `false` | Keep the deprecated probes when deploying Cilium DaemonSet |
| kubeProxyReplacementHealthzBindAddr | string | `""` | healthz server bind address for the kube-proxy replacement. To enable set the value to '0.0.0.0:10256' for all ipv4 addresses and this '[::]:10256' for all ipv6 addresses. By default it is disabled. |
| l7Proxy | bool | `true` | Enable Layer 7 network policy. |
| livenessProbe.failureThreshold | int | `10` | failure threshold of liveness probe |
| livenessProbe.periodSeconds | int | `30` | interval between checks of the liveness probe |
| localRedirectPolicy | bool | `false` | Enable Local Redirect Policy. |
| logSystemLoad | bool | `false` | Enables periodic logging of system load |
| maglev | object | `{}` | Configure maglev consistent hashing |
| monitor | object | `{"enabled":false}` | Specify the CIDR for native routing (ie to avoid IP masquerade for). This value corresponds to the configured cluster-cidr. nativeRoutingCIDR: |
| monitor.enabled | bool | `false` | Enable the cilium-monitor sidecar. |
| name | string | `"cilium"` | Agent container name. |
| nodePort | object | `{"autoProtectPortRange":true,"bindProtection":true,"enableHealthCheck":true,"enabled":false}` | Configure N-S k8s service loadbalancing |
| nodePort.autoProtectPortRange | bool | `true` | Append NodePort range to ip_local_reserved_ports if clash with ephemeral ports is detected. |
| nodePort.bindProtection | bool | `true` | Set to true to prevent applications binding to service ports. |
| nodePort.enableHealthCheck | bool | `true` | Enable healthcheck nodePort server for NodePort services |
| nodePort.enabled | bool | `false` | Enable the Cilium NodePort service implementation. |
| nodeinit.bootstrapFile | string | `"/tmp/cilium-bootstrap-time"` | bootstrapFile is the location of the file where the bootstrap timestamp is written by the node-init DaemonSet |
| nodeinit.enabled | bool | `false` | Enable the node initialization DaemonSet |
| nodeinit.extraConfigmapMounts | list | `[]` | Additional nodeinit ConfigMap mounts. |
| nodeinit.extraEnv | object | `{}` | Additional nodeinit environment variables. |
| nodeinit.extraHostPathMounts | list | `[]` | Additional nodeinit host path mounts. |
| nodeinit.extraInitContainers | list | `[]` | Additional nodeinit init containers. |
| nodeinit.image | object | `{"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/startup-script","tag":"62bfbe88c17778aad7bef9fa57ff9e2d4a9ba0d8"}` | node-init image. |
| nodeinit.nodeSelector | object | `{}` | Node labels for nodeinit pod assignment ref: https://kubernetes.io/docs/user-guide/node-selection/ |
| nodeinit.podAnnotations | object | `{}` | Annotations to be added to node-init pods. |
| nodeinit.podDisruptionBudget | object | `{"enabled":true,"maxUnavailable":2}` | PodDisruptionBudget settings ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/ |
| nodeinit.podLabels | object | `{}` | Labels to be added to node-init pods. |
| nodeinit.priorityClassName | string | `""` | The priority class to use for the nodeinit pod. |
| nodeinit.resources | object | `{"requests":{"cpu":"100m","memory":"100Mi"}}` | nodeinit resource limits & requests ref: https://kubernetes.io/docs/user-guide/compute-resources/ |
| nodeinit.securityContext | object | `{}` | Security context to be added to nodeinit pods. |
| nodeinit.tolerations | list | `[{"operator":"Exists"}]` | Node tolerations for nodeinit scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/ |
| nodeinit.updateStrategy | object | `{"type":"RollingUpdate"}` | node-init update strategy |
| operator.affinity | object | `{"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchExpressions":[{"key":"io.cilium/app","operator":"In","values":["operator"]}]},"topologyKey":"kubernetes.io/hostname"}]}}` | cilium-operator affinity |
| operator.enabled | bool | `true` | Enable the cilium-operator component (required). |
| operator.endpointGCInterval | string | `"5m0s"` | Interval for endpoint garbage collection. |
| operator.extraArgs | list | `[]` | Additional cilium-operator container arguments. |
| operator.extraConfigmapMounts | list | `[]` | Additional cilium-operator ConfigMap mounts. |
| operator.extraEnv | object | `{}` | Additional cilium-operator environment variables. |
| operator.extraHostPathMounts | list | `[]` | Additional cilium-operator hostPath mounts. |
| operator.extraInitContainers | list | `[]` | Additional InitContainers to initialize the pod. |
| operator.identityGCInterval | string | `"15m0s"` | Interval for identity garbage collection. |
| operator.identityHeartbeatTimeout | string | `"30m0s"` | Timeout for identity heartbeats. |
| operator.image | object | `{"alibabacloudDigest":"","awsDigest":"","azureDigest":"","genericDigest":"","pullPolicy":"IfNotPresent","repository":"quay.io/cilium/operator","suffix":"","tag":"v1.10.4","useDigest":false}` | cilium-operator image. |
| operator.nodeSelector | object | `{}` | Node labels for cilium-operator pod assignment ref: https://kubernetes.io/docs/user-guide/node-selection/ |
| operator.podAnnotations | object | `{}` | Annotations to be added to cilium-operator pods |
| operator.podDisruptionBudget | object | `{"enabled":false,"maxUnavailable":1}` | PodDisruptionBudget settings ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/ |
| operator.podLabels | object | `{}` | Labels to be added to cilium-operator pods |
| operator.priorityClassName | string | `""` | cilium-operator priorityClassName |
| operator.prometheus | object | `{"enabled":false,"port":6942,"serviceMonitor":{"enabled":false}}` | Enable prometheus metrics for cilium-operator on the configured port at /metrics |
| operator.prometheus.serviceMonitor.enabled | bool | `false` | Enable service monitors. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/master/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml) |
| operator.replicas | int | `2` | Number of replicas to run for the cilium-operator deployment |
| operator.resources | object | `{}` | cilium-operator resource limits & requests ref: https://kubernetes.io/docs/user-guide/compute-resources/ |
| operator.rollOutPods | bool | `false` | Roll out cilium-operator pods automatically when configmap is updated. |
| operator.securityContext | object | `{}` | Security context to be added to cilium-operator pods |
| operator.serviceAccountName | string | `"cilium-operator"` | For using with an existing serviceAccount. |
| operator.skipCRDCreation | bool | `false` | Skip CRDs creation for cilium-operator |
| operator.tolerations | list | `[{"operator":"Exists"}]` | Node tolerations for cilium-operator scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/ |
| operator.updateStrategy | object | `{"rollingUpdate":{"maxSurge":1,"maxUnavailable":1},"type":"RollingUpdate"}` | cilium-operator update strategy |
| podAnnotations | object | `{}` | Annotations to be added to agent pods |
| podDisruptionBudget | object | `{"enabled":true,"maxUnavailable":2}` | PodDisruptionBudget settings ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/ |
| podLabels | object | `{}` | Labels to be added to agent pods |
| policyEnforcementMode | string | `"default"` | The agent can be put into one of the three policy enforcement modes: default, always and never. ref: https://docs.cilium.io/en/stable/policy/intro/#policy-enforcement-modes |
| pprof.enabled | bool | `false` | Enable Go pprof debugging |
| preflight.enabled | bool | `false` | Enable Cilium pre-flight resources (required for upgrade) |
| preflight.extraConfigmapMounts | list | `[]` | Additional preflight ConfigMap mounts. |
| preflight.extraEnv | object | `{}` | Additional preflight environment variables. |
| preflight.extraHostPathMounts | list | `[]` | Additional preflight host path mounts. |
| preflight.extraInitContainers | list | `[]` | Additional preflight init containers. |
| preflight.image | object | `{"digest":"","pullPolicy":"IfNotPresent","repository":"quay.io/cilium/cilium","tag":"v1.10.4","useDigest":false}` | Cilium pre-flight image. |
| preflight.nodeSelector | object | `{}` | Node labels for preflight pod assignment ref: https://kubernetes.io/docs/user-guide/node-selection/ |
| preflight.podAnnotations | object | `{}` | Annotations to be added to preflight pods |
| preflight.podDisruptionBudget | object | `{"enabled":true,"maxUnavailable":2}` | PodDisruptionBudget settings ref: https://kubernetes.io/docs/concepts/workloads/pods/disruptions/ |
| preflight.podLabels | object | `{}` | Labels to be added to the preflight pod. |
| preflight.priorityClassName | string | `""` | The priority class to use for the preflight pod. |
| preflight.resources | object | `{}` | preflight resource limits & requests ref: https://kubernetes.io/docs/user-guide/compute-resources/ |
| preflight.securityContext | object | `{}` | Security context to be added to preflight pods |
| preflight.tofqdnsPreCache | string | `""` | Path to write the `--tofqdns-pre-cache` file to. |
| preflight.tolerations | list | `[{"effect":"NoSchedule","key":"node.kubernetes.io/not-ready"},{"effect":"NoSchedule","key":"node-role.kubernetes.io/master"},{"effect":"NoSchedule","key":"node.cloudprovider.kubernetes.io/uninitialized","value":"true"},{"key":"CriticalAddonsOnly","operator":"Exists"}]` | Node tolerations for preflight scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/ |
| preflight.updateStrategy | object | `{"type":"RollingUpdate"}` | preflight update strategy |
| preflight.validateCNPs | bool | `true` | By default we should always validate the installed CNPs before upgrading Cilium. This will make sure the user will have the policies deployed in the cluster with the right schema. |
| priorityClassName | string | `""` | The priority class to use for cilium-agent. |
| prometheus | object | `{"enabled":false,"metrics":null,"port":9090,"serviceMonitor":{"enabled":false}}` | Configure prometheus metrics on the configured port at /metrics |
| prometheus.metrics | string | `nil` | Metrics that should be enabled or disabled from the default metric list. (+metric_foo to enable metric_foo , -metric_bar to disable metric_bar). ref: https://docs.cilium.io/en/stable/operations/metrics/#exported-metrics |
| prometheus.serviceMonitor.enabled | bool | `false` | Enable service monitors. This requires the prometheus CRDs to be available (see https://github.com/prometheus-operator/prometheus-operator/blob/master/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml) |
| proxy | object | `{"prometheus":{"enabled":true,"port":"9095"},"sidecarImageRegex":"cilium/istio_proxy"}` | Configure Istio proxy options. |
| proxy.sidecarImageRegex | string | `"cilium/istio_proxy"` | Regular expression matching compatible Istio sidecar istio-proxy container image names |
| rbac.create | bool | `true` | Enable creation of Resource-Based Access Control configuration. |
| readinessProbe.failureThreshold | int | `3` | failure threshold of readiness probe |
| readinessProbe.periodSeconds | int | `30` | interval between checks of the readiness probe |
| remoteNodeIdentity | bool | `true` | Enable use of the remote node identity. ref: https://docs.cilium.io/en/v1.7/install/upgrade/#configmap-remote-node-identity |
| resourceQuotas | object | `{"cilium":{"hard":{"pods":"10k"}},"enabled":false,"operator":{"hard":{"pods":"15"}}}` | Enable resource quotas for priority classes used in the cluster. |
| resources | object | `{}` | Agent resource limits & requests ref: https://kubernetes.io/docs/user-guide/compute-resources/ |
| rollOutCiliumPods | bool | `false` | Roll out cilium agent pods automatically when configmap is updated. |
| securityContext | object | `{}` | Security context to be added to agent pods |
| serviceAccounts | object | Component's fully qualified name. | Define serviceAccount names for components. |
| serviceAccounts.clustermeshcertgen | object | `{"annotations":{},"create":true,"name":"clustermesh-apiserver-generate-certs"}` | Clustermeshcertgen is used if clustermesh.apiserver.tls.auto.method=cronJob |
| serviceAccounts.hubblecertgen | object | `{"annotations":{},"create":true,"name":"hubble-generate-certs"}` | Hubblecertgen is used if hubble.tls.auto.method=cronJob |
| sleepAfterInit | bool | `false` | Do not run Cilium agent when running with clean mode. Useful to completely uninstall Cilium as it will stop Cilium from starting and create artifacts in the node. |
| sockops | object | `{"enabled":false}` | Configure BPF socket operations configuration |
| startupProbe.failureThreshold | int | `105` | failure threshold of startup probe. 105 x 2s translates to the old behaviour of the readiness probe (120s delay + 30 x 3s) |
| startupProbe.periodSeconds | int | `2` | interval between checks of the startup probe |
| tls | object | `{"enabled":true,"secretsBackend":"local"}` | Configure TLS configuration in the agent. |
| tolerations | list | `[{"operator":"Exists"}]` | Node tolerations for agent scheduling to nodes with taints ref: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/ |
| tunnel | string | `"vxlan"` | Configure the encapsulation configuration for communication between nodes. Possible values:   - disabled   - vxlan (default)   - geneve |
| updateStrategy | object | `{"rollingUpdate":{"maxUnavailable":2},"type":"RollingUpdate"}` | Cilium agent update strategy |
| wellKnownIdentities.enabled | bool | `false` | Enable the use of well-known identities. |
