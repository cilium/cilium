******
NEWS
******

v1.5.2
======

::

    André Martins (17):
          metrics: add map_ops_total by default
          Dockerfile: update golang to 1.12.5
          docs: fix architecture images' URL
          docs: add missing cilium-operator-sa.yaml for k8s 1.14 upgrade guide
          operator: fix concurrent access of variable in cnp garbage collection
          docs: give better troubleshooting for conntrack-gc-interval
          test: replace guestbook test docker image
          pkg/envoy: use proto.Equal instead comparing strings
          daemon/Makefile: rm -f on make clean for links
          test/provision: bump k8s testing to v1.13.6
          pkg/ipcache: initialize globalmap at import time
          pkg/endpoint: fix assignment in nil map on restore
          test: add v1.15.0-beta.0 to the CI
          add support for k8s 1.14.2
          docs: update well-known-identities documentation
          docs: move well known identities to the concepts section
          pkg/maps: use pointer in receivers for GetKeyPtr and GetValuePtr
    
    Daniel Borkmann (3):
          bpf: do propagate backend, and rev nat to new entry
          bpf: force recreation of regular ct entry upon service collision
          cilium: fix up source address selection for cluster ip
    
    Ian Vernon (1):
          test: fix incorrect deletion statement for policy
    
    Ifeanyi Ubah (1):
          CI: Log at INFO and above for all unit tests
    
    Jarno Rajahalme (3):
          envoy: Do not use deprecated configuration options.
          proxylib: Fix egress enforcement
          envoy: Prevent resending NACKed resources also when there are no ACK observers.
    
    Joe Stringer (2):
          daemon: Make policymap size configurable
          cni: Fix incorrect logging in failure case
    
    John Fastabend (2):
          cilium: IsLocal() needs to compare both Name and Cluster
          cilium: encode table attribute in Route delete
    
    Maciej Kwiek (5):
          Jenkins separate directories for parallel builds
          Bump vagrant box versions for tests
          Bump vagrant box version for tests to 151
          Add jenkins stage for loading vagrant boxes
          Recover from ginkgo fail in WithTimeout helper
    
    Martynas Pumputis (7):
          maps: Remove disabled svc v2 maps
          daemon: Improve logging of service restoration
          daemon: Do not restore service if adding to cache fails
          daemon: Remove stale maps only after restoring all endpoints
          datapath: Redo backend selection if stale CT_SERVICE entry is found
          bpf: Fix dump parsers of encrypt and sockmap maps
          service: Reduce backend ID allocation space
    
    Ray Bejjani (5):
          CI: WaitForNPods uses count of pods
          CI: Consolidate WaitforNPods and WaitForPodsRunning
          fqdn: DNSProxy does not fold similar DNS requests
          CI: Consolidate Vagrant box information into 1 file
          endpoint: Guard against deleted endpoints in regenerate
    
    Thomas Graf (9):
          cni: Fix unexpected end of JSON input on errors
          ctmap: Introduce variable conntrack gc interval
          doc: Adjust documentation with new dynamic gc interval
          Revert "maps/ctmap: add ctmap benchmark"
          Revert "pkg/bpf: use own binary which does not require to create buffers"
          Revert "pkg/bpf: add newer LookupElement, GetNextKey and UpdateElement functions"
          Revert "pkg/{bpf,datapath,maps}: use same MapKey and MapValue in map iterations"
          Revert "pkg/bpf: add DeepCopyMapKey and DeepCopyMapValue"
          bpf: Remove several debug messages
    
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
