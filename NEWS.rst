******
NEWS
******

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
