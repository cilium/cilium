******
NEWS
******

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
