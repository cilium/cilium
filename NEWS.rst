******
NEWS
******

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
