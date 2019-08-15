******
NEWS
******

v1.4.7
======

::

    André Martins (3):
          proxylib: fix go vet warnings
          test: fix go vet warnings
          Makefile: run govet on unit tests
    
    Eloy Coto (1):
          Test/SSH: fix typos
    
    Ian Vernon (4):
          test: move creation of Istio resources into `It`
          test: be sure to close SSH client after a given Describe completes
          dockerfiles: update golang versions to 1.12.8
          update cilium-docker-plugin, cilium-operator to golang 1.12.8
    
    Jarno Rajahalme (20):
          proxy: Do not error out if reading of open ports fails.
          endpoint: Create redirects before bpf map updates.
          bpf: Add dummy bpf_alignchecker.c
          istio: Update to release 1.1.3
          CI: Change Kafka runtime tests to use local conntrack maps.
          envoy: Update to release 1.10
          Dockerfile: Update proxy dependency
          Envoy: Use an image with proxylib injection fix.
          envoy: Use LPM ipcache instead of xDS when available.
          Gopkg: update cilium/proxy
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
    
    Joe Stringer (7:
          Makefile: Add microk8s make target
          alignchecker: Streamline tests
          daemon: Refactor alignchecker datapath refs to datapath/
          alignchecker: Support multiple references to the same structs
          test: Specify protocol during policy trace
          docs: Fix warnings
          endpoint: Fix proxy port leak on endpoint delete
    
    John Fastabend (2):
          cilium: fix Error -> Errorf errors
          cilium: docker.go ineffectual assignment
    
    Maciej Kwiek (1):
          Add timeout to ginkgo calls
    
    Martynas Pumputis (4):
          daemon: Remove svc from cache in syncLBMapsWithK8s
          daemon: Fix removal of non-existing SVCs in syncLBMapsWithK8s
          alignchecker: Refactor C and Go structs alignment checker
          daemon: Make alignment check optional
    
v1.4.6
======

::

    André Martins (18):
          operator: add ca-certificates to operator
          docs: fix architecture images' URL
          test: replace guestbook test docker image
          daemon/Makefile: rm -f on make clean for links
          pkg/endpoint: fix assignment in nil map on restore
          Jenkinsfile: backport all Jenkinsfile from master
          daemon: fix endpoint restore when endpoints are not available
          pkg/lock: fix RUnlockIgnoreTime
          test: bump k8s 1.13 to 1.13.7
          *.Jenkinsfile: remove leftover failFast
          pkg/kvstore: Run GetPrefix with limit of 1
          kvstore/allocator: do not re-get slave key on allocation
          kvstore/allocator: release ID from idpool on error
          kvstore/allocator: protect concurrent access of slave keys
          examples/kubernetes: bump cilium to v1.4.5
          maps/lbmap: protect service cache refcount with concurrent access
          pkg/k8s: hold mutex while adding events to the queue
          kubernetes-upstream: add seperate stage to run tests
    
    Eloy Coto (2):
          Test: Fix timeout on test/PolicyGen
          Test: Add a invalid CNP Test
    
    Ian Vernon (3):
          contrib: fix up check-fmt.sh
          test: make function provided to WithTimeout run asynchronously
          test: provide context which will be cancled to `CiliumExecContext`
    
    Ifeanyi Ubah (2):
          pkg/health: Fix IPv6 URL format in HTTP probe
          test: Enable IPv6 forwarding in test VMs
    
    Jarno Rajahalme (4):
          CI: Enforce sensible timeouts.
          docs: Update urllib3 dependency to address CVE-2019-11324
          proxylib: Fix egress enforcement
          envoy: Prevent resending NACKed resources also when there are no ACK observers.
    
    Joe Stringer (2):
          contrib: Fix cherry-pick script
          endpoint: Fix bug with endpoint state metrics
    
    John Fastabend (1):
          cilium: IsLocal() needs to compare both Name and Cluster
    
    Maciej Kwiek (11):
          Add `dep check` to travis build
          [k8s-upstream-test] Replace deprecated provider
          Add jenkins stage for loading vagrant boxes
          Recover from ginkgo fail in WithTimeout helper
          Jenkins separate directories for parallel builds
          Don't overwrite minRequired in WaitforNPods
          Preload vagrant boxes in k8s upstream jenkinsfile
          Don't set debug to true in monitor test
          Change nightly CI job label from fixed to baremetal
          Retry provisioning vagrant vms in CI
          retry vm provisioning, increase timeout
    
    Martynas Pumputis (14):
          daemon: Panic if executable name does not match cilium{-agent,-node-monitor,}
          contrib: Exit early if no git remote is found
          docs: Add k8s 1.14 to supported versions for testing
          components: Fix cilium-agent process detection
          cli: Do not cli init when running cilium-agent
          daemon: Set $HOME as dir to look for default config ciliumd.yaml
          bpf: Set BPF_F_NO_PREALLOC before comparing maps
          daemon: Remove stale maps only after restoring all endpoints
          mac: Add function to generate a random MAC addr
          vendor: Update vishvananda/netlink
          endpoint: Set random MAC addrs for veth when creating it
          bpf: Set random MAC addrs for cilium interfaces
          daemon: Change loglevel of "ipcache entry owned by kvstore or agent"
          daemon: Do not remove revNAT if removing svc fails
    
    Ray Bejjani (6):
          CI: WaitForNPods uses count of pods
          CI: Consolidate WaitforNPods and WaitForPodsRunning
          CI: Consolidate Vagrant box information into 1 file
          CI: Clean VMs and reclaim disk after jobs complete
          CI: Clean workspace when all stages complete
          CI: Clean VMs and reclaim disk in nightly test
    
    Sebastian Wicki (2):
          k8s: Fix policies with multiple From/To selectors
          k8s: Introduce test for multiple From/To selectors
    
    Thomas Graf (4):
          allocator: Verify locally allocated key
          doc: Add EKS node-init DaemonSet to mount BPF filesystem
          ipcache: Fix automatic recovery of deleted ipcache entries
          bpf: Remove unneeded debug instructions to stay below instruction limit
    
    刘群 (1):
          doc: fix up Ubuntu apt-get install command

v1.4.5
======

::

    Thomas Graf (1):
          bpf: Prohibit encapsulation traffic from pod when running in encapsulation mode


v1.4.4
======

::
    
    André Martins (1):
          test: update k8s test versions to v1.14.1
    
    Eloy Coto (1):
          Change suiteName to not match test folders names.
    
    Jarno Rajahalme (3):
          envoy: Update to enable path normalization
          istio: Update istio proxy to 1.1.3
          test: Update Istio test to 1.1.2 with proxy 1.1.3.
    
    Joe Stringer (2):
          endpoint: Sanitize ep.SecurityIdentity on restore
          endpointmanager: Avoid regenerating restoring endpoints
    
    Maciej Kwiek (4):
          Don't use local remote in backporting scripts
          Fix leftovers in Gopkg.lock
          vendor: update k8s dependencies to 1.14.1
          Fix backporting scripts for https users
    
    Thomas Graf (5):
          cni: Always release created resources on failure of CNI ADD
          endpoint: Delegate IP release on endpoint creation failure
          cni: Fix CNI delete side-effects
          agent: Delete endpoints which failed to restore synchronously
          Doc: Update jinja dependency for documentation building
    
v1.4.3
======

::

    André Martins (23):
          docs: fix gke guide
          test: update k8s version 1.10, 1.11, 1.12 and 1.13
          vendor: update to k8s 1.13.4
          Gopkg: remove leftover files
          k8s: ignore kubectl.kubernetes.io/last-applied-configuration annotation
          operator: do not restart unmanaged hostNetwork pods
          kvstore: forcefully close etcd session on error
          contrib/backporting: print helper message how to install missing library
          contrib/backporting: add direct URL to create github tokens
          kvstore: make session orphan if the leaseID was used on a failed request
          pkg/kvstore: attempt to stop giving LeaseIDs for a closed session
          flannel: forcefully disabling IPv6 mode on flannel
          test: run k8s 1.14.0-rc.1 by default on all PRs
          test: set coredns deployment closer to the upstream version
          k8s: generate code from k8s 1.14.0-rc.1
          vendor: update dependencies to k8s 1.14.0-rc.1
          k8s: add method to create default Cilium K8s Client
          k8s: add protobuf by default for k8s client
          test update k8s to 1.11.9, 1.12.7, 1.13.5 and 1.14.0
          vendor: update github.com/containernetworking/plugins to v0.7.5
          vendor: update github.com/containernetworking/cni to v0.7.0-rc2
          update loopback CNI plugin to v0.7.5 in runtime docker image
          .travis: run travis on all PRs

    Daniel Borkmann (4):
          daemon: fix conntrack map dump wrt addresses
          ipsec, bpf: fix build error when tunneling is disabled
          ipsec, doc: remove note on 1.4.1 release
          ipsec, daemon: reject unsupported config options

    Daniel T. Lee (1):
          docs, bpf: Remove struct padding with aligning members

    Eloy Coto (4):
          Daemon/PolicyAdd lock policyRepo to avoid fqdn races.
          Test: Add Kuberentes 1.14-rc.1 to the build system.
          Examples: Added kubernetes 1.14 manifest
          Documentation: Add Kubernetes 1.14 support.

    Ian Vernon (1):
          fix unit test breakage

    Jarno Rajahalme (4):
          proxylib: Fix unit test flake when counting access log entries
          endpointmanager: IPv6 support.
          proxy: Break GC loop between Redirect and RedirectImplementation
          envoy: Use fixed envoy image

    Joe Stringer (15):
          k8s: Fix node equality function for health IPs
          node: Fix health endpoint IP fetch with IP disable
          test/health: Check that peers are discovered
          Revert "policy: Simplify l7 rule generation for l4-only rules"
          Revert "Revert "policy: Simplify l7 rule generation for l4-only rules""
          daemon/policy: Refactor test endpoint initialization
          daemon/policy: Share labels declarations in tests
          daemon/policy: Consolidate policy testing primitives
          policy: Generate L7 allow-all for L4-only rules
          policy: Simplify l7 rule generation for l4-only rules
          Revert "policy: Simplify l7 rule generation for l4-only rules"
          contrib/backporting: Fix commit order in check-stable
          kvstore: Fix identity override with labels prefix
          kvstore: Add test for GetPrefix()
          kvstore/allocator: Add test for identity clash

    John Fastabend (7):
          cilium: bugtool add xfrm details
          cilium: scrub keys from bugtool xfrm
          cilium: ipsec, add ipsec unit test
          cilium: route, fix deleteRule to include mask and support IPv6
          cilium: ipsec, refactor reading IPSec keys to support io.Reader
          cilium: ipsec, route rules unit tests
          cilium: ipsec, support kernel without ipv6 support

    Maciej Kwiek (1):
          Run operator in dev vm

    Martynas Pumputis (2):
          test: Do not print from Vagrantfile when NETNEXT=true
          docs: Add note about vbox guest additions and net-next

    Nirmoy Das (1):
          mtu: autodetect MTU for IPv6 only network

    Ray Bejjani (2):
          dnsproxy: Return DNS response before cache update
          Revert "dnsproxy: Return DNS response before cache update"

    Thomas Graf (17):
          doc: Fix etcd key paths for external etcd installation
          workloads: Disable periodic runtime sync in Kubernetes modes
          workloads: Fetch labels only after successful endpoint association
          workloads: Only set k8s pod/namespace name if not already set
          endpoint: Pass context into endpoint.UpdateLabels()
          endpoint: Pass context into identityLabelsChanged() via runLabelsResolver()
          identity: Pass context into allocation and release functions
          identity: Allow identity initialization wait to be cancelled via context
          allocator: Allow initial kvstore sync to be cancelled
          allocator: Pass context into Allocate() and Release() functions
          allocator: Cancel allocation retries via context
          kvstore: Pass context into LockPath()
          kvstore: Cancel local lock operation based on parent context
          kvstore: Make kvstore periodic sync interval configurable
          node: Use default kvstore synchronization interval
          ipcache: Allow CIDR ipcache overwrite from all sources
          endpoint: Use IsSet() to check if endpoint IP is set

v1.4.2
======

::

    André Martins (3):
          cilium.io/v2: set DerivativePolicies json to derivativePolicies
          pkg/kvstore: do not use default instance to create new instance module
          pkg/kvstore: add 15 min TTL for the first session lease
    
    Daniel Borkmann (1):
          cilium: fix bailing out on auto-complete when v4/v6 ranges are specified
    
    Ian Vernon (2):
          release: fix uploadrev script to work with changes made after 1.3
          contrib: fix extraction of cilium-docker binary
    
    Joe Stringer (10):
          datapath: Fix nil dereference in logging statement
          ctmap: Print source addresses in ctmap cli
          endpoint: Fix and quieten endpoint revert logs
          check-stable: Sort PRs by merge date
          cherry-pick: Print sha when applying patch.
          contrib: Add new script to auto-fix bpf.sha
          contrib: Update rebase-bindata to use fix-sha.sh
          test: Wait for cilium to start in runtime provision
          api: Return 500 when API handlers panic.
          daemon: Remove old health EP state dirs in restore
    
    John Fastabend (6):
          cilium: sockmap, convert BPF_ANY to BPF_NOEXIST
          cilium: sockmap remove socket.h dependency
          cilium: bpftool included DS reports error on bpf_sockops load
          cilium: populate wildcard src->dst policy for ipsec
          cilium: push decryption up so we can decrypt even if not endpoint
          cilium: ipsec, zero cb[0] to avoid incorrectly encrypting
    
    Martynas Pumputis (8):
          ctmap: Fix order of CtKey{4,6} struct fields
          bpf: Do not account tx for CT_SERVICE
          bpf: Enable pipefail option in init.sh
          test: Test upgrade from v1.3 to master
          test: Get rid of JoinEP flakes
          endpoint: Fix ENABLE_NAT46 endpoint config validation
          contrib: Fix cherry-pick to avoid omitting parts of patch
          contrib: Update backporting README
    
    Michal Rostecki (1):
          policy: Add missing import error metric calls
    
    Ray Bejjani (3):
          fqdn-poller: Ensure monitor events contain all data
          daemon: Track policy implementation delay by source
          endpoints: Add optional callback to WaitForPolicyRevision
    
    Thomas Graf (9):
          doc: Fix delete pod commend in clustermesh guide
          doc: Fix --tofqdns-pre-cache reference
          ipcache: Provide WaitForInitialSync() to wait for kvstore sync
          agent: Wait to regenerate restore endpoints until ipcache has been populated
          workloads: Synchroneous handling of container events
          workloads: Change watcher interval from 30 seconds to 5 minutes
          workloads: Don't spin up receive queue in periodic watcher
          store: Protect from deletion of local key via kvstore event
          ipcache: Protect from delete events for alive IP but mismatching key
    
    hui.kong (1):
          1: fix when have black hole route container pod CIDR can cause postIpAMFailure range is full
    

v1.4.1
======

::

    André Martins (13):
          apis/cilium.io: do not regenerate deepcopy for unnecessary structs
          api/v1: remove requirements of labels in endpoints API
          cilium-docker-plugin: set default CMD to /usr/bin/cilium-docker
          lookup rule for the given IP family
          vendor: fix Gopkg.lock
          policy/api: generate missing deepcopy code
          pkg/kvstore: wait until etcd configuration files are available
          pkg/identity: add well known identity for cilium-etcd-operator
          linux/ipsec: decode ipsec keys from hex
          datapath/linux: log errors for ipsec setup
          docs: re write k8s setup for ipsec
          k8s/utils: make the ControllerSynced fields public
          k8s/utils: wrap kubernetes controller with ControllerSyncer
    
    Arvind Soni (1):
          Update k8s-install-gke.rst
    
    Brian Topping (1):
          Minor disambiguation to 1.4 release/upgrade doc
    
    Daniel Borkmann (1):
          cilium, bpf: only account tx for egress direction
    
    Eloy Coto (1):
          FQDN: Set always a empty ToCIDRSet in case of no entries in cache.
    
    Ian Vernon (1):
          cilium-operator.Dockerfile: set `klog` logging values from cilium-operator
    
    Joe Stringer (3):
          datapath: Fix map cleanup for CT maps
          datapath: Clean up config map on startup
          datapath: Clean up stale ipvlan maps
    
    John Fastabend (4):
          cilium: k8s watcher, push internal Cilium IPs through annotations
          cilium: ipsec, zero CB_SRC_IDENTITY to ensure we don't incorrectly encrypt
          cilium: ipsec, remove bogus mark set
          cilium: ipsec, fix kube-proxy compatability
    
    Maciej Kwiek (1):
          Change endpoint policy status map to regular map
    
    Martynas Pumputis (3):
          examples: Update docker-compose examples
          docs: Add note about triggering builds with net-next
          examples: Fix docker-compose mount points
    
    Ray Bejjani (5):
          cilium preflight container prepares tofqdn-pre-cache
          docs: Move "Obtaining DNS Data" to L7 section
          docs: Small changes to toFQDN and DNS sections
          docs: Add FQDN Poller upgrade impact & instructions
          cilium preflight command for FQDN poller upgrade
    
    Thomas Graf (4):
          identity/cache: Allow using GetIdentityCache() without initializing allocator
          policy: Add unit tests for ResolvePolicy() for L7 + ingress wildcards
          policy: Fix ipcache synchronization on startup
          allocator: Wait until kvstore is connected before allocating global identities
