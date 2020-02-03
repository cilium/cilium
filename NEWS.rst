******
NEWS
******

v1.6.6
======

::

   André Martins (12):
         .github: rename github-actions file
         .github: remove github actions integration
         golang: update to 1.12.15
         update k8s test versions to 1.14.10, 1.15.7 and 1.16.4
         updating k8s to 1.16.4
         test: fix k8s upstream testing
         golang: update to 1.12.16
         garbage collect stale distributed locks
         operator: fix getOldestLeases logic
         kvstore/allocator: fix GCLocks unit tests
         kvstore/allocator: test for stale locks before acquiring lock
         nodeinit/templates: fix indentation of sys-fs-bpf

   Daniel Borkmann (1):
         identity: require global identity for empty labels

   Joe Stringer (3):
         .github: Update actions to v1.6.6 project
         install: Update the chart versions
         helm: Make nodeinit systemd mountpoint conditional

   Michal Rostecki (1):
         daemon: Enable IP forwarding on start

   Thomas Graf (4):
         cni: Fix noisy warning "Unknown CNI chaining configuration"
         eni: Fix releases of excess IPs
         ipam: Add ability to release IPs by owner name
         cni: Release IP even when endpoint deletion fails

   Vlad Ungureanu (1):
         Add missing words to spelling_wordlist



v1.6.5
======

::

   André Martins (4):
         .github: add github actions to cilium
         pkg/workloads: sleep 500ms before reconnecting to containerd
         update golang to 1.12.14
         Dockerfile runtime: add python3 dependency

   Ifeanyi Ubah (1):
         pkg/endpoint: delete _next directories during restore

   Jarno Rajahalme (4):
         envoy: Update to release 1.12 with Cilium TLS support
         envoy: Update to release 1.12.1
         Dockerfile: Use Envoy image that always resumes NPDS
         envoy: Update to 1.12.2

   John Fastabend (1):
         cilium: encryption bugtool should remove aead, comp and auth-trunk keys

   Maciej Kwiek (4):
         Add ApplyOptions
         add Force to Apply and use it in cilium install
         Move missed kubectl apply calls to `Apply` calls
         Add nil check for init container terminated state

   Martynas Pumputis (2):
         k8s: Use ParseService when comparing two services
         daemon: Decrease log level for svc not found msg

   Sebastian Wicki (1):
         k8s: Fix typo in io.cilium/shared-service annotation

   Thomas Graf (2):
         doc: Fix AKS installation guide
         doc: Disable masquerading in all chaining guides



v1.6.4
======

::

    André Martins (20):
          pkg/k8s: consider node taints as part of node equalness
          go: bump golang to 1.12.12
          update k8s to 1.13.12, 1.14.8, 1.15.5 and 1.16.2
          vendor: update k8s dependencies to 1.16.2
          golang: update to 1.12.13
          pkg/k8s: fix toServices policy update when service endpoints are modified
          docs: clarify usage of bpf fs mount
          pkg/policy: show error if user installs a L7 CNP with L7 proxy disabled
          pkg/endpoint: do not runIPIdentitySync is not running with kvstore
          k8s/endpointsynchronizer: re-fecth CEP in case of update conflict
          pkg/endpoint: start RegenerationFailureHandler after assign epID
          k8s/watcher: refactor code to generate k8s services
          pkg/k8s: fix service update bug fix
          operator: do not rm kube-dns pods if unmanaged-pod-watcher-interval == 0
          aws/eni: do not resync node if semaphore Acquire fails
          test/provision: update k8s test versions to 1.14.9 and 1.15.6
          k8s: update k8s to v1.16.3
          Revert "accesslog: Add support for missing and rejected headers."
          Revert "Envoy: Use CLUSTER_PROVIDED loadbalancer type."
          Revert "envoy: Update to release 1.12 with Cilium TLS support"

    Dan Sexton (1):
          Added chart value for etcd-operator cluster domain

    Daniel Borkmann (31):
          cilium: add OpenOrCreateUnpinned helper for Cilium maps
          cilium: probe and enable LPM map in prefilter
          cilium: add new probe package for BPF kernel feature probes
          cilium: dump warning when using prefilter but without full lpm support
          cilium: add prefilter delete method to openapi
          cilium: re-implement broken delete handler for prefilter
          bpf, probe: add probe for larger insn/complexity limit
          bpf, nat: bump collision retries on newer kernels
          bpf: remove deterministic retries on lru
          bpf: use random offset in port range and walk from there
          bpf: let nat signal potential congestion to cilium agent
          cilium: change CT GC sleep into a wakeup from select timeout
          cilium: add Mute/Unmute function for perf RB
          cilium: add signal package for handling BPF datapath signals
          cilium: one page for signal RB is enough in config
          cilium: log error to agent log when signal RB has timeout
          cilium: swap RegisterChannel with SetupSignalListener
          cilium: change channel type to proper signal.SignalData
          cilium: add metrics collection for signal package
          bpf: remap punt to stack so we properly recircle into bpf_netdev
          bpf: remove optimization to bypass rev-snat as prep for external ip
          bpf: fix tc-index bitfield wrt skipping nodeport
          bpf: merge nat handling ranges for bpf nodeport
          bpf: perform nodeport nat into full port range
          bpf: enable direct bpf_netdev redirect when !netfilter
          bpf: compile out bpf_lxc service lookup when host services enabled
          bpf: remove force_range nat config parameter
          bpf: fix nodeport insns over limit regressions in netdev/overlay progs
          bpf: do not error out when punt to stack return from nat
          bpf: always force egress nat upon nodeport requests
          vendor: point vishvananda/netlink back to upstream

    Deepesh Pathak (1):
          cni: fix cni plugin error formatting when agent is not running

    Ian Vernon (2):
          bugtool: add `cilium node list` output
          endpoint: regeneration controller runs with `RegenerateWithDatapathRewrite`

    Jaff Cheng (2):
          eni: Allow selecting subnet by Name tag
          eni: Allow releasing excess IP addresses via option

    Jarno Rajahalme (11):
          manager: Wait for policy map changes to be done before waiting for the ACK
          logfields: Add tag for cached xDS version.
          envoy: Always use IstioNodeToIP function
          Envoy: Track last ACKed version per proxy node
          xds: Allow endpoints to wait for the current policy version to be acked
          envoy: Do not force Network Policy updates
          policy: Add unit tests
          envoy: Remove 'force' argument from cache operations
          Envoy: Use CLUSTER_PROVIDED loadbalancer type.
          accesslog: Add support for missing and rejected headers.
          policy: Keep cached selector references for L3-dependent L7 rules.

    Jean Raby (1):
          unmanaged kube-dns: Delete one pod per iteration

    Joe Stringer (7):
          docs: Fix clustermesh secrets namespace
          endpoint: Clarify naming for identity resolution
          endpoint: Run labels controller under ep manager
          health: Fix handling of node update events
          health: Fix up IP removal from health prober
          health: Factor out getting the IPs to probe
          health: Add some basic unit tests for adding nodes

    John Fastabend (3):
          cilium: bpf, fix undeclared ENCRYP_IFACE
          cilium: encryption, increase initHealth RunInterval
          cilium: encryption, better error reporting for multiple default routes

    Laurent Bernaille (4):
          Don't add route/xfrm state for internal IPs in subnet mode
          Fix pre-allocate in the ENI documentation
          Support null encrytion/auth
          Add ipsec upsert logs in debug mode

    Maciej Kwiek (1):
          Pin kubectl version in ginkgo vms

    Martynas Pumputis (10):
          test: Add GetCiliumHostIPv4 helper
          test: Extend NodePort BPF tests
          docs: Fix typo
          test: Add test for loopback service connectivity
          datapath: Fix hairpin flow when ENABLE_ROUTING is disabled
          k8s: Provision NodePort services for LoadBalancer
          daemon: Disable L7 proxy with explicit flag
          daemon: Enable FQDN proxy if --enable-l7-proxy is set
          helm: Add global.l7Proxy.enabled param
          docs: Fix ipvlan iptables-free gsg

    Patrick Mahoney (1):
          install: fix label used in ServiceMonitor to select cilium-agent

    Ray Bejjani (4):
          envoy: Update to release 1.12 with Cilium TLS support
          fqdn: DNSCache LookupByRegex functions don't return empty matches
          Docs: tofqdns-pre-cache is optional in preflight templates
          fqdn: L3-aware L7 DNS policy enforcement
          helm: Fix bug to disable health-checks in chaining mode

    Swaminathan Vasudevan (1):
          Fix kafka-v1.yaml file for compatibility

    Thomas Graf (5):
          agent: Add --enable-endpoint-health-checking flag
          helm: Disable endpoint-health-checking when chaining is enabled
          flannel: Disable endpoint connectivity health check
          bpf: Don't perform L3 operation when ENABLE_ROUTING is disabled
          iptables: Fix incorrect SNAT for externalTrafficPolicy=local

v1.6.3
======

::

    André Martins (5):
          go: bump golang to 1.12.10
          dockerfile.runtime: always run update when building dependencies
          docs: update k8s supported versions
          vendor: update to k8s 1.16.1
          Revert "add PR #82410 patch from kubernetes/kubernetes"
    
    Daniel Borkmann (1):
          bpf: fix cilium_host unroutable check
    
    Ian Vernon (1):
          policy: remove checking of CIDR-based fields from `IsLabelBased` checks
    
    Jarno Rajahalme (1):
          envoy: Update image for Envoy CVEs 2019-10-08
    
    Joe Stringer (6):
          health: Configure sysctl when IPv6 is disabled
          docs: Simplify microk8s instructions
          vendor: Bump golang.org/sys/unix library revision
          policy: Fix up selectorcache locking issue
          monitor: Fix reporting the monitor status
          bpf: Fix sockops compile on newer LLVM
    
    Julien Balestra (1):
          kvstore/etcd: always reload keypair
    
    Laurent Bernaille (4):
          Update netlink library (support for output-mark)
          Use output-mark to use table 200 post-encryption and set different MTU for main/200 tables
          Do not add policies/states for subnets
          Fix IP leak on main if
    
    Martynas Pumputis (2):
          sysctl: Get rid of GOOS targets
          sysctl: Add function to write any param value
    
    Michal Rostecki (2):
          sysctl: Add package for managing kernel parameters
          k8s/endpointsynchronizer: Do not delete CEP on empty k8s resource names
    
    Michi Mutsuzaki (1):
          daemon: Populate source and destination ports for DNS records
    
    Vlad Ungureanu (1):
          Change kind of daemonset in microk8s-prepull.yml to apps/v1
    
v1.6.2
======

::

    André Martins (19):
          update to k8s 1.16.0.rc.2
          Makefile: simplify k8s code generation target
          Makefile: avoid go modules when running k8s code generation
          test: test against k8s 1.16 by default
          dev VM: update k8s to v1.16.0-rc.2
          test: disable non-working k8s upstream test
          add PR #82410 patch from kubernetes/kubernetes
          pkg/k8s: create custom dialer function
          use common custom dialer to connect to etcd
          test: bump k8s testing versions to 1.13.11, 1.14.7 and 1.15.4
          charts/managed-etcd: bump cilium-etcd-operator to v2.0.7
          Gopkg.* bump to k8s 1.16.0
          test: test against k8s 1.16.0
          dev VM: update to k8s 1.16.0
          docs: fix aks guide
          docs: fix proper nodeinit.enabled flag
          plugins/cilium-cni: add support for AKS
          docs: add akz and az to list of spelling words
          docs/azure: wait for azure-vnet.json to be created
    
    Boran Car (2):
          Refactor probing to reuse client
          Do not ping during preflight checks
    
    Daniel Borkmann (1):
          iptables: fix cilium_forward chain rules to support openshift
    
    Deepesh Pathak (1):
          daemon: fix container runtime disabled state log
    
    Ian Vernon (6):
          loader: remove hash from compileQueue if build fails
          daemon: check error from `d.init()`
          daemon: move directory setup into `SetUpTest`
          daemon: do not delete directories created by tests if tests fail
          endpoint: use endpoint ID for error message
          endpoint: start a controller to retry regeneration
    
    Jarno Rajahalme (2):
          test: Add L3-dependent L7 test with toFQDN
          endpoint: Update proxy policies when applying policy map changes out-of-band
    
    Joe Stringer (3):
          Dockerfile: Use latest iproute2 image
          daemon: Start controller when pod labels resolution fails
          test: Add a standalone test for validating static pod labels
    
    John Fastabend (1):
          cilium: encryption, replace Router() IP with CiliumInternal
    
    Martynas Pumputis (3):
          Revert "Revert "Remove componentstatus from rbac""
          docs: Update kubeproxy-free guide
          docs: Do not pin cilium image vsn in kubeproxy-free guide
    
    Ray Bejjani (4):
          CI: increase timeouts by 30m to avoid  k8s-1.10 test timeouts
          endpoint: Expose Endpoint.ApplyPolicyMapChanges
          policy: Expose map-update WaitGroup in FQDN update callchains
          FQDN: Wait on policy map update when adding new IPs
    
    Thomas Graf (1):
          bpf: Don't delete conntrack entries on policy deny
    
v1.6.1
======

::

    André Martins (11):
          install/kubernetes: do not add clustermesh documentation by default
          bump k8s support to 1.15.3
          bump manifests apiVersion to apps/v1
          etcd: use ca-file field from etcd option if available
          deps: update etcd to v3.4.0
          Revert "test: wait for k8s external service in [kube|core]-dns"
          Revert "test: add integration tests for k8s services with external IPs"
          Revert "pkg/k8s: add k8s external IPs support"
          Revert "pkg/k8s: test endpoints and service received by events channel"
          Revert "pkg/k8s: add merge method to merge 2 set of endpoints together"
          test: fix k8s upstream test
    
    Boran Car (1):
          Fix connectivity test example probes
    
    Dan Wendlandt (1):
          AKS getting started guide
    
    Daniel Borkmann (16):
          cilium: only start daemon's monitoring agent after base datapath setup
          cilium: assert monitor agent is allowed to expose socket
          docs: clarify nodeport and host-reachable services and 5.0.y kernel situation
          cilium: silence harmless CILIUM_TRANSIENT_FORWARD warning on startup
          cilium: fix restore v6 router ip to not break pod connectivity on restart
          ipam: do not assign v4 addresses for status.IPV6
          ipam: fix v6 address corruption in cilium status dump
          k8s: replace NodePort frontend cilium_host IP with router addr
          bpf: fix asymmetric routing and cilium_host connectivity in v6 tunnel mode
          bpf: fix routing of cilium_host router ip and health in v6 tunnel mode
          docs: fix typo and update kube-proxy free gsg
          doc: minor additional tweaks to kube-proxy free gsg
          bpf: usr prandom as slave selection in lb
          bpf: remove unused args from slave selection code
          bpf: add separate ct_service lifetime for tcp/non-tcp
          cilium: make all ct timeouts configurable
    
    Ian Vernon (1):
          daemon: signal endpoint restore fail when waiting for global identities times out
    
    Jarno Rajahalme (12):
          iptables: Add explicit ACCEPT rules for host proxy traffic
          test: Use global.tag in helm command line
          test: Return the error in CmdRes.GetErr()
          labels: Make Matches private
          k8s: Use api.WildcardEndpointSelector instead of an endpoint label reserved:all
          policy/api: remove Entity matching functions
          policy/api: Add test case for EntityAll
          envoy: Update to the latest API
          datapath: probe socket match support, plumb to Envoy configuration
          istio: Update to 1.2.5
          test: Wait for at least one Istio POD to get ready
          Dockerfile: Use latest Envoy image
    
    Joe Stringer (17):
          cilium: Support user-specified monitor socket
          daemon: Disable BPF routing in endpoint routes mode
          iptables: Refactor proxy socket redirect rule
          iptables: Allow xt_socket match rules to fail
          policy: Allow DNS policy on ports other than 53
          docs: Update direct routing policy limitation
          workloads: Fix disabled status reflection in API
          test: Remove old Cilium versions
          policy/api: Add tests for reserved:unmanaged match
          test: Fix endpoint routes mode test
          test: Add disabled test for tunnel+endpointRoutes
          health: Prefer contacting health EP over IPv4
          health: Fix endpoint routes mode
          bpf: Skip ingress proxy ip rule with endpoint routes
          cni: Fix disabling of routing in chaining mode
          docs: Avoid mentioning deprecated option
          test: Ensure managed etcd test tears down etcd
    
    John Fastabend (8):
          cilium: encryption, if IPv6 is not supported do not throw debug warning
          cilium: pull ConfigureResourceLimits earlier in bootstrapping
          cilium: encryption, throw hard error if map create fails
          cilium: encryption, log MapUpdateContext failures
          cilium: encryption, if encryptNode is disable release routes
          cilium: add interface to neighborLog
          cilium: encryption, delete encrypt-node routes if node is deleted
          cilium: encryption, add host networking routes for encrypt-node
    
    Maciej Kwiek (3):
          Use proper helm value in CI clusters
          Connection readiness of k8s client gets ns
          Remove componentstatus from rbac
    
    Martynas Pumputis (14):
          test: Add SkipContextIf helper
          test: Use SkipContextIf in Tests NodePort BPF
          test: Get rid of unused skipIfDoesNotRunOnNetNext helper
          helm: Add global.kubeConfigPath
          docs: Document how to specify Flannel bridge name
          helm: Allow to specify k8s api-server host and port via env vars
          docs: Add kube-proxy free getting started guide
          Revert "Remove componentstatus from rbac"
          daemon: Lower kernel requirement for TCP host-lb
          daemon: Specify exact kernel version in host-lb fatal log msg
          docs: Update source branch in kube-proxy-free guide
          test: Remove workaround to MASQ traffic from k8s2
          daemon: Improve logging for auto-enabling host-lb
          docs: Improve sysdump collection guide
    
    Rajat Jindal (1):
          cilium: update IsEtcdCluster to return true if etcd.operator="true" kv option is set
    
    Ray Bejjani (4):
          CI: decouple HTTP and DNS testing in K8sPolicyTest
          CI: K8sPolicyTest tests local DNS only
          tofqdns: Allow "_" in DNS names to support service discovery schemes
          operator: Pass identity allocation mode through correctly
    
    Rodrigo Chacon (1):
          eni: update ENI limits mappings
    
    Thomas Graf (6):
          doc: Update minikube requirement to meet TPROXY requirements
          operator: Fix passing kvstore options via arguments
          nodeinit: Change network mode from bridge to transparent on Azure
          k8s: Add initcontainer to wait for nodeinit to complete
          doc: Add Azure CNI to CNI chaining section
          clustermesh: Improve troubleshooting ability
    
    gkontridze (1):
          Docs: minor spelling corrections (Fixes #9127)
