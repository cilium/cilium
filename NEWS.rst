******
NEWS
******

v1.5.12
=======

::

   André Martins (8):
         .github: rename github-actions file
         .github: remove github actions integration
         golang: update to 1.12.15
         golang: update to 1.12.16
         garbage collect stale distributed locks
         operator: fix getOldestLeases logic
         kvstore/allocator: fix GCLocks unit tests
         kvstore/allocator: test for stale locks before acquiring lock

   Daniel Borkmann (1):
         identity: require global identity for empty labels

   Michal Rostecki (2):
         sysctl: Add package for managing kernel parameters
         daemon: Enable IP forwarding on start

   Thomas Graf (2):
         ipam: Add ability to release IPs by owner name
         cni: Release IP even when endpoint deletion fails

v1.5.11
=======

::

   André Martins (3):
         .github: add github actions to cilium
         update golang to 1.12.14
         Dockerfile runtime: add python3 dependency

   Jarno Rajahalme (8):
         Envoy: Do not configure policy name
         envoy: Update to the latest API
         Dockerfile: Use latest Envoy image
         envoy: Update image for Envoy CVEs 2019-10-08
         envoy: Update to release 1.12 with Cilium TLS support
         envoy: Update to release 1.12.1
         Dockerfile: Use Envoy image that always resumes NPDS
         envoy: Update to 1.12.2

   Joe Stringer (1):
         node: Fix segfault in node equality check

v1.5.10
=======
::

    André Martins (12):
          go: bump golang to 1.12.12
          update k8s to 1.13.12, 1.14.8 and 1.15.5
          vendor: update k8s dependencies to 1.15.5
          pkg/k8s: consider node taints as part of node equalness
          docs: clarify usage of bpf fs mount
          k8s/endpointsynchronizer: re-fecth CEP in case of update conflict
          golang: update to 1.12.13
          pkg/k8s: fix toServices policy update when service endpoints are modified
          k8s/watcher: refactor code to generate k8s services
          pkg/k8s: fix service update bug fix
          operator: do not rm kube-dns pods if unmanaged-pod-watcher-interval == 0
          test/provision: update k8s test versions to 1.14.9 and 1.15.6

    Daniel Borkmann (1):
          vendor: point vishvananda/netlink back to upstream

    Ian Vernon (1):
          bugtool: add `cilium node list` output

    Joe Stringer (1):
          docs: Fix clustermesh secrets namespace

v1.5.9
======

::

    André Martins (3):
          test: bump k8s testing versions to 1.13.11, 1.14.7 and 1.15.4
          go: bump golang to 1.12.10
          dockerfile.runtime: always run update when building dependencies
    
    Ian Vernon (1):
          loader: remove hash from compileQueue if build fails
    
    Jarno Rajahalme (1):
          envoy: Update image for Envoy CVEs 2019-10-08
    
    John Fastabend (1):
          cilium: encryption, replace Router() IP with CiliumInternal

v1.5.8
======

::

    André Martins (2):
          bump k8s support to 1.15.3
          test: fix k8s upstream test
    
    Daniel Borkmann (3):
          bpf: usr prandom as slave selection in lb
          bpf: add separate ct_service lifetime for tcp/non-tcp
          cilium: make all ct timeouts configurable
    
    Jarno Rajahalme (3):
          istio: Update to 1.2.5
          Dockerfile: Use latest Envoy image
          test: Wait for at least one Istio POD to get ready
    
    Joe Stringer (1):
          docs: Update direct routing policy limitation
    
    Ray Bejjani (1):
          tofqdns: Allow "_" in DNS names to support service discovery schemes
    
v1.5.7
======

::

    Daniel Borkmann (2):
          cilium: fix transient rules to use allocation cidr
          bpf: try to atomically replace filters when possible
    
    John Fastabend (2):
          cilium: encryption, fix getting started guides create secrects command
          cilium: route mtu not set unless route.Spec set MTU
    
    Michal Rostecki (1):
          Revert "[daemon] - Change MTU source for cilium_host (Use the Route one)"
    
    Rajat Jindal (1):
          cilium: update IsEtcdCluster to return true if etcd.operator="true" kv option is set
    
    Thomas Graf (1):
          datapath: Limit host->service IP SNAT to local traffic
    
v1.5.6
======

::

    André Martins (12):
          update golang to 1.12.7 for cilium-{operator,docker-plugin}
          test: update k8s testing versions to v1.12.10, v1.13.8 and v1.14.4
          update to golang 1.12.7
          operator: restart non-managed kube-dns pods before connecting to etcd
          pkg/{kvstore,node}: delay node delete event in kvstore
          pkg/kvstore: wait for node delete delay in unit tests
          Gopkg: update k8s dependencies to v1.15.1
          test: update k8s test version to v1.15.1
          examples/kubernetes: update k8s dev VM to v1.15.1
          daemon: register warning_error metric after parsing CLI options
          Gopkg: update cilium/proxy
          datapath/iptables: wait until acquisition xtables lock is done
    
    Daniel Borkmann (3):
          cilium: remove old probe content before restoring assets
          bpf: fix verifier error due to repulling of skb->data/end
          cilium: install transient rules during agent restart
    
    Ian Vernon (15):
          endpoint: do not log warning for specific state transition
          test: add `ExecMiddle` function
          test: move creation of Istio resources into `It`
          test: misc. runtime policy test fixes
          endpoint: change transition from restore state
          endpoint: fix deadlock when endpoint EventQueue is full
          test: be sure to close SSH client after a given Describe completes
          daemon: get list of frontends from ServiceCache before acquiring BPFMapMu
          eventqueue: use mutex to synchronize access to events channel
          eventqueue: protect against enqueueing same Event twice
          eventqueue: return error if Enqueue fails
          examples/kubernetes: mount xtables.lock
          use iptables-manager to manage iptables executions
          update cilium-docker-plugin, cilium-operator to golang 1.12.8
          dockerfiles: update golang versions to 1.12.8
    
    Jarno Rajahalme (17):
          proxy: Perform dnsproxy Close() in the returned finalizeFunc
          endpoint: Create redirects before bpf map updates.
          proxy: Do not error out if reading of open ports fails.
          CI: Change Kafka runtime tests to use local conntrack maps.
          Dockerfile: Update proxy dependency
          Envoy: Use an image with proxylib injection fix.
          envoy: Use LPM ipcache instead of xDS when available.
          Envoy: Update to the latest proxy build, use latest API
          Dockerfile: Use cilium-envoy with reduced logging.
          istio: Update to 1.1.7
          envoy: Istio 1.2.0 update
          istio: Update to 1.2.2
          test: provide capability for tests to run in their own namespace
          envoy: Add SO_MARK option to listener config
          Dockerfile: Use proxy with legacy fix
          envoy: Use patched image
          Istio: Update to 1.2.4
    
    Joe Stringer (6):
          docs: Fix up unparsed SCM_WEB literals
          test: Specify protocol during policy trace
          docs: Fix warnings
          bpf: Introduce revalidate_data_first()
          bpf: Attempt pulling skb->data if it is not pulled
          endpoint: Fix proxy port leak on endpoint delete
    
    John Fastabend (2):
          cilium: encryption, ensure 0x*d00 and 0x*e00 marks dont cause conflicts
          cilium: add skb_pull_data to bpf_network to avoid revalidate error
    
    Maciej Kwiek (2):
          Add timeout to ginkgo calls
          Fix seds in microk8s docs
    
    Martynas Pumputis (3):
          datapath: Do not fail if route contains gw equal to dst
          daemon: Remove svc from cache in syncLBMapsWithK8s
          daemon: Fix removal of non-existing SVCs in syncLBMapsWithK8s
    
    bob (1):
          [daemon] - Change MTU source for cilium_host (Use the Route one)
    
v1.5.5
======

::

    André Martins (31):
          *.Jenkinsfile: remove leftover failFast
          test: add serial ports to CI VMs
          test: bump k8s 1.13 to 1.13.7
          pkg/kvstore: add new *IfLocked methods to perform txns
          pkg/kvstore: add Comparator() to KVLocker
          kvstore/allocator: make the allocator aware of kvstore lock holding
          pkg/kvstore: implement new *IfLocked methods for etcd
          pkg/kvstore: introduced a dedicated session for locks
          test/provision: upgrade k8s 1.15 to 1.15.0-beta.2
          test: error out if no-spec policies is allowed in k8s >= 1.15
          test: bump to k8s 1.14.3
          daemon: fix endpoint restore when endpoints are not available
          pkg/lock: fix RUnlockIgnoreTime
          .travis: update travis golang to 1.12.5
          pkg/metrics: re-register newStatusCollector function
          vendor: update k8s to v1.15.0
          test: test against 1.15.0
          test: run k8s 1.15.0 by default in all PRs
          docs: update documentation with k8s 1.15 support
          kubernetes-upstream: add seperate stage to run tests
          test: set k8s 1.15 as default k8s version
          pkg/endpointmanager: protecting endpoints against concurrent access
          examples/kubernetes: bump cilium to v1.5.4
          pkg/kvstore: fix nil pointer in error while doing a transaction in etcd
          operator: add warning message if status returns an error
          maps/lbmap: protect service cache refcount with concurrent access
          pkg/k8s: do not parse empty annotations
          pkg/kvstore: add etcd lease information into cilium status
          test: set 1.15 by default in CI Vagrantfile
          pkg/k8s: hold mutex while adding events to the queue
          pkg/k8s: add conversion for DeleteFinalStateUnknown objects
    
    Deepesh Pathak (1):
          cli: fix panic in cilium bpf sha get command
    
    Ian Vernon (12):
          endpoint: make sure `updateRegenerationStatistics` is called within anonymous function
          test: have timeout for `Exec`
          test: create session and run commands asynchronously
          test: use context with timeout to ensure that Cilium log gathering takes <= 5 minutes
          test: add timeout to `waitToDeleteCilium` helper function
          test: make sure that `GetPodNames` times out after 30 seconds
          test: change `GetPodNames` to have a timeout
          test: do not overwrite context in `GetPodNamesContext`
          fqdn: correctly populate Source IP and Port in `notifyOnDNSMsg`
          test: introduce `ExecShort` function
          test: remove unused function
          allocator: fix race condition when allocating local identities upon bootstrap
    
    Ifeanyi Ubah (2):
          test: Enable IPv6 forwarding in test VMs
          pkg/health: Fix IPv6 URL format in HTTP probe
    
    Jarno Rajahalme (1):
          identity: Initialize well-known identities before the policy repository.
    
    Joe Stringer (2):
          docs: Remove architecture target links
          Disable automatic direct node routes test
    
    John Fastabend (1):
          cilium: docker.go ineffectual assignment
    
    Maciej Kwiek (5):
          Preload vagrant boxes in k8s upstream jenkinsfile
          Don't set debug to true in monitor test
          Change nightly CI job label from fixed to baremetal
          Retry provisioning vagrant vms in CI
          retry vm provisioning, increase timeout
    
    Martynas Pumputis (9):
          docs: Clarify about legacy services enabled by default
          mac: Add function to generate a random MAC addr
          vendor: Update vishvananda/netlink
          endpoint: Set random MAC addrs for veth when creating it
          bpf: Set random MAC addrs for cilium interfaces
          daemon: Change loglevel of "ipcache entry owned by kvstore or agent"
          daemon: Do not remove revNAT if removing svc fails
          daemon: Remove svc-v2 maps when restore is disabled
          lbmap: Get rid of bpfService cache lock
    
    Ray Bejjani (5):
          CI: Ensure k8s execs cancel contexts
          CI: Report last seen error in CiliumPreFlightCheck
          CI: Clean VMs and reclaim disk after jobs complete
          CI: Clean workspace when all stages complete
          CI: Clean VMs and reclaim disk in nightly test
    
    Sebastian Wicki (2):
          k8s: Fix policies with multiple From/To selectors
          k8s: Introduce test for multiple From/To selectors
    
    Thomas Graf (2):
          test: Fix NodeCleanMetadata by using --overwrite
          bpf: Remove unneeded debug instructions to stay below instruction limit
    
v1.5.4
======

::

    Thomas Graf (1):
          bpf: Prohibit encapsulation traffic from pod when running in encapsulation mode

v1.5.3
======

::

    André Martins (3):
          Jenkinsfile: backport all Jenkinsfile from master
          pkg/kvstore: do not always UpdateIfDifferent with and without lease
          test/provision: bump k8s 1.12 to 1.12.9
    
    Ian Vernon (2):
          test: provide context which will be cancled to `CiliumExecContext`
          test: do not spawn goroutines to wait for canceled context in `RunCommandContext`
    
    Joe Stringer (2):
          daemon: Refactor individual endpoint restore
          daemon: Don't log endpoint restore if IP alloc fails
    
    Maciej Kwiek (1):
          Don't overwrite minRequired in WaitforNPods
    
    Thomas Graf (3):
          node: Delay handling of node delete events received via kvstore
          kvstore/store: Do not remove local key on sync failure
          node/store: Do not delete node key in kvstore on node registration failure
    
v1.5.2
======

::

        André Martins (29):
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
        pkg/kvstore: Run GetPrefix with limit of 1
        kvstore/allocator: do not re-get slave key on allocation
        kvstore/allocator: release ID from idpool on error
        kvstore/allocator: protect concurrent access of slave keys
        kvstore/allocator: add lookupKey method
        kvstore/allocator: move invalidKey to cache.go
        kvstore/allocator: do not re-allocate localKeys
        pkg/kvstore: store Modified Revision number KeyValuePairs map
        kvstore/allocator: do not immediately delete master keys if unused
        pkg/kvstore: perform update if value or lease are different
        pkg/labels: ignore all labels that match the regex "annotation.*"
        pkg/kvstore: acquire a random initlock

        Daniel Borkmann (5):
        bpf: do propagate backend, and rev nat to new entry
        bpf: force recreation of regular ct entry upon service collision
        cilium: fix up source address selection for cluster ip
        bugtool: add raw dumps of all lb and lb-related maps
        tests, k8s: add monitor dump helper for debugging

        Ian Vernon (2):
        test: fix incorrect deletion statement for policy
        Prepare for release v1.5.2

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

        Maciej Kwiek (6):
        Jenkins separate directories for parallel builds
        Bump vagrant box versions for tests
        Bump vagrant box version for tests to 151
        Add jenkins stage for loading vagrant boxes
        Recover from ginkgo fail in WithTimeout helper
        Add kvstore quorum check to Cilium precheck

        Martynas Pumputis (10):
        maps: Remove disabled svc v2 maps
        daemon: Improve logging of service restoration
        daemon: Do not restore service if adding to cache fails
        daemon: Remove stale maps only after restoring all endpoints
        datapath: Redo backend selection if stale CT_SERVICE entry is found
        bpf: Fix dump parsers of encrypt and sockmap maps
        service: Reduce backend ID allocation space
        examples: Add preflight DaemonSet for svc-v2 removal
        docs: Add note about running preflight-with-rm-svc-v2.yaml
        docs: Add note about keeping enable-legacy-services

        Ray Bejjani (5):
        CI: WaitForNPods uses count of pods
        CI: Consolidate WaitforNPods and WaitForPodsRunning
        fqdn: DNSProxy does not fold similar DNS requests
        CI: Consolidate Vagrant box information into 1 file
        endpoint: Guard against deleted endpoints in regenerate

        Thomas Graf (18):
        cni: Fix unexpected end of JSON input on errors
        ctmap: Introduce variable conntrack gc interval
        doc: Adjust documentation with new dynamic gc interval
        Revert "maps/ctmap: add ctmap benchmark"
        Revert "pkg/bpf: use own binary which does not require to create buffers"
        Revert "pkg/bpf: add newer LookupElement, GetNextKey and UpdateElement functions"
        Revert "pkg/{bpf,datapath,maps}: use same MapKey and MapValue in map iterations"
        Revert "pkg/bpf: add DeepCopyMapKey and DeepCopyMapValue"
        bpf: Remove several debug messages
        allocator: Verify locally allocated key
        allocator: Make GetNoCache() deterministic
        allocator: Fix garbage collector to compare prefix
        allocator: Provide additional info message on key allocation and deletion
        doc: Add EKS node-init DaemonSet to mount BPF filesystem
        operator: Fix health check API
        ipcache: Fix automatic recovery of deleted ipcache entries
        kvstore: Wait for kvstore to reach quorum
        test: Disable unstable K8sDatapathConfig Encapsulation Check connectivity with transparent encryption and VXLAN encapsulation

    
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
