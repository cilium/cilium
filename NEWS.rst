******
NEWS
******

v1.5.1
======

::

    André Martins (33):
          pkg/bpf: add DeepCopyMapKey and DeepCopyMapValue
          operator: add ca-certificates to operator
          examples/kubernetes: fix generated files
          kubernetes/node-init: run cilium-node-init on any tainted node
          kubernetes/node-init: run cilium-node-init in hostNetwork
          kubernetes/node-init: do not run script on an already setup node
          kubernetes/node-init: Install cilium cni config before restart kubelet
          kubernetes/node-init: add more aggressive node-init script
          kubernetes/node-init: delete cilium running before kubelet restart
          pkg/k8s: switch AnnotateNode as a controller
          pkg/k8s: patch node status with NetworkUnavailable as false
          examples/kubernetes: add node/status to cilium RBAC
          pkg/metrics: add namespace to fqdn_gc_deletions_total
          pkg/k8s: patch node annotations
          examples/kubernetes: add node to cilium RBAC
          pkg/buildqueue: remove unused package
          pkg/metrics: add CounterVec and GaugeVec interfaces
          pkg/metrics: use interfaces for all metrics
          daemon: use constant SubsystemAgent from pkg/metrics
          pkg/metrics: add no-op implementations for disabled metrics
          pkg/option: add metrics option to enable or disable from default metrics
          pkg/metrics: set subsystems and labels as constants
          common: add MapStringStructToSlice function
          pkg/metrics: set all metrics as a no-op unless they are enabled
          pkg/bpf: only account for bpf syscalls if syscall metric is enabled
          pkg/kvstore: disable metric collection if KVStore metrics are not enabled
          ipcache: print tunnel endpoint for RemoteEndpointInfo
          pkg/{bpf,datapath,maps}: use same MapKey and MapValue in map iterations
          pkg/bpf: add newer LookupElement, GetNextKey and UpdateElement functions
          pkg/bpf: use own binary which does not require to create buffers
          maps/ctmap: add ctmap benchmark
          test/provision: update k8s testing versions to v1.11.10 and v1.12.8
          cilium/cmd: dump bpf lb list if map exists
    
    Dan Wendlandt (1):
          Docs: minor fixes to AWS EKS and AWS Metadata filtering GSGs
    
    Daniel Borkmann (1):
          ginko: adjust timeout to something more appropriate
    
    Ian Vernon (7):
          contrib: fix up check-fmt.sh
          endpoint: do not serialize JSON for EventQueue field
          test: make function provided to WithTimeout run asynchronously
          endpoint: fix comment for GetSecurityIdentity
          policy: add RLockAlive, RUnlock to Endpoint interface
          policy: ensure Endpoint lock held while accessing identity
          policy: add debug log when error from `updateEndpointsCaches` is non-nil
    
    Jimmy Jones (1):
          Typo in encryption algorithm: GMC -> GCM
    
    Joe Stringer (9):
          contrib: Simplify microk8s prepull YAML
          examples: Add YAML generation for microk8s
          examples: Generate microk8s YAMLs
          docs: Document how to get started with MicroK8s
          endpoint: Fix bug with endpoint state metrics
          docs,examples: Fix up custom CNI for microk8s
          datapath/iptables: Warn when ipv6 modules not available
          daemon: Use all labels to restore endpoint identity
          docs: Improve configmap documentation
    
    Martynas Pumputis (12):
          docs: Mention enable-legacy-services flag in upgrade docs
          docs: Add upgrade guide from >=1.4.0 to 1.5
          option: Add BindEnvWithLegacyEnvFallback function
          daemon: Replace viper.BindEnv with option.BindEnvWithLegacyEnvFallback
          docs: Add k8s 1.14 to supported versions for testing
          bpf: Force preallocation for SNAT maps of LRU type
          components: Fix cilium-agent process detection
          cli: Do not cli init when running cilium-agent
          daemon: Set $HOME as dir to look for default config ciliumd.yaml
          daemon: Do not init config when running with --cmdref
          bpf: Set BPF_F_NO_PREALLOC before comparing maps
          test: Do not set enable-legacy-services in v1.4 ConfigMap
    
    Michal Rostecki (1):
          datapath/iptables: Warn when iptables modules are not available
    
    Ray Bejjani (1):
          CI: Wait on create/delete in helpers.SampleContainersAction
    
    Thomas Graf (3):
          operator: Start health API earlier
          operator: Add more logging to see where the operator blocks on startup
          nodediscovery: Try to register node forever
    
    刘群 (1):
          doc: fix up Ubuntu apt-get install command
