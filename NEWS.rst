******
NEWS
******

1.2.0-rc3
=========

::

    André Martins (3):
          pkg/envoy: update generated files
          pkg/node: add Public Equalness checker
          daemon/k8s_watcher: ignore irrelevant node updates

    Daniel Borkmann (1):
          bpf, doc: rebase bpf doc from master into v1.2

    Eloy Coto (1):
          Test: Upgrade test update stable image to v1.1

    Ian Vernon (6):
          daemon: move restoring of endpoints to start after Kubernetes watcher starts
          daemon: block until initial policy list
          test/k8sT: add more logs to narrate progress of ChaosTest
          test/helpers: change parameters for WaitForKubeDNSEntry
          test: add additional WaitForKubeDNSEntry checks
          test/k8sT: move DNS checks outside of loop

    Joe Stringer (9):
          bpf: Reduce the number of supported prefix lengths
          bpf: Relax verifier in CT lookup drop case
          ipcache: Split prefix length limits by protocol
          bpf: Pack ipv6_ct_tuple to match Golang
          ctmap: Add accessor method for path per endpoint
          daemon: Upgrade CT map properties on startup
          daemon: Refactor health endpoint cleanup code
          daemon: Remove health-ep before deleting its devices
          daemon: Remove health-ep on controller stop

    Ray Bejjani (4):
          daemon: fqdn.DNSPoller interval exposed as a const
          policy: Add runtime tests for ToFQDN rules
          Test: Fixup formatting in ToFQDNs test Expects
          Test: Ensure ToFQDNs test waits for DNS poll

    Romain Lenglet (5):
          kafka: Properly set (non-)nullable arrays in synthesized responses
          test/runtime/kvstore: Wait for Cilium to be ready after restarting
          test: Add a description to every Cilium restart check
          kafka: Update parser to pull "Fix de/serialization of null arrays"
          controller: Log the DoFunc and update times

    Thomas Graf (6):
          node: Fix panic when node store is not initialized yet
          bpf: Report dst identity in drop notifications
          launcher: Wait for process to exit and release resources
          k8s: Use server version instead of ComponentStatus to check health
          agent: Do not replace node routes if they already exist
          route: Fix route replacement logic for IPv6


1.2.0-rc2
=========

::

    Amey Bhide (1):
          Run initContainer in privileged mode for cilium cleanup

    André Martins (6):
          kubernetes/addons: add Cilium development spec file to test etcd-operator
          etcd-operator: add instructions how to install cfssl utilities
          etcd-operator: add developer README to deploy etcd-operator
          pkg/node: re-add k8s node watcher until kvstore is connected
          etcd-operator/tls/certs: do some minor cleanups
          pkg/k8s: set node cluster with the option.Config.ClusterName

    Eloy Coto (2):
          Test: Delete Kube-dns on upgrade test
          Daemon: Update Health endpoints IP on localNode.

    Jarno Rajahalme (1):
          envoy: Sanitize HTTP headers

    Joe Stringer (8):
          daemon: Don't tunnel locally destined traffic
          docs: Fix namespace isolation links
          docs: Fix header indentation for out-of-date link
          docs: Fix contributing guide sphinx warnings
          docs: Fix toctree links
          docs: Fix up broken links
          docs: Fix duplicate links in upgrade page
          client: Add API timeout to endpoint requests

    Nirmoy Das (2):
          allocator: nextCache can hold a nil value for a id/key
          bpf: print map name and errno instead of nil

    Ray Bejjani (4):
          doc: Add toFQDNs documentation and example
          daemon: Correct toFQDNs to update all IPs on change
          pkg/endpoint: Factor out Endpoint.HasLabelsRLocked
          kubernetes: No CEP CRD for cilium-health EP

    Romain Lenglet (6):
          Update to Istio 1.0.0
          envoy: Disable unused ADS protocol support
          envoy: Adapt Envoy route generation to updated HeaderMatcher API
          docs: Update the Istio GSG to Istio 1.0.0
          daemon: Exit synced endpoint creation if in sidecar proxy mode
          docs: Enable mTLS in the Istio GSG

    Thomas Graf (3):
          monitor: Fix spin loop when reading stdout from monitor fails
          bpffs: Cache mountinfo result
          endpoint: Fix locking while calling endpoint.getLogger()

v1.2.0-rc1
==========

::

    André Martins (93):
          examples/kubernetes: use POSIX regex for CILIUM_VERSION checker
          docs: add checklinks target
          docs: fix broken links
          docs: use Documentation context to avoid longer image builds
          docker/Dockerfile: update golang to 1.10.2
          docker/Dockerfile: update base image to ubuntu 18.04
          docker/Dockerfile: update iproute2 to 4.16
          docker/Dockerfile: update loopback cni to 0.6.0
          docker/Dockerfile: add gpg
          Dockerfile: update cilium-runtime with 2018-06-04
          docs: add documentation to upgrade ConfigMap
          docs: typo fix
          docs: fix mesos guide
          daemon: skip health endpoint on restore
          test: increase boot timeout to 600 seconds (#4639)
          Revert "k8s: Updated LastUpdated after waiting for endpoint status"
          pkg/endpoint: set policy revision if there is no datapath changes
          start.sh: set RELOAD=1 if VM already exists
          Dockerfile: update go to 1.10.3
          Dockerfile: update base build images to version 2018-06-21
          examples/kubernetes: add k8s 1.12 deployment files
          test: add k8s 1.12 test framework
          docs: point users to docs.cilium.io in GH docs
          VERSION: bump version to 1.1.90
          test: Use latest stable etcd and consul images
          tests: Update cilium-builder in unit tests to 2018-06-21
          start.sh: fix RELOAD=1 if VM is not created
          daemon: change minimal worker thread to 2
          test: update k8s to 1.8.14, 1.10.4 and 1.11.0
          test: set default CRI socket
          ginkgo.Jenkinsfile: increase timeout by 30 minutes
          ginkgo-kubernetes-all.Jenkinsfile: move k8s 1.10 and 1.12 to same stage
          examples/kubernetes-ingress: update kubernetes options to 1.11.0
          plugins: fix CNI configuration typo
          test: remove policy enforcement in k8s tests
          pkg/k8s: stop logging conflicting errors as errors on update
          vendor: remove k8s-code-generator dependency from the developer requirements
          examples/kubernetes: add "system-node-critical" priorityClass
          pkg/endpoint: check endpoint's state before modifying identity labels
          pkg/endpoint: use "/" for k8s namespace and pod name concatenation
          pkg/comparator: add map string comparator
          k8s: watch for pod label changes
          move pkg/{apierror,apipanic,apisocket} -> pkg/api
          pkg/k8s: add UpdateStatus method to CNP
          k8s: Use UpdateStatus for kubernetes server version >=1.11
          examples/kubernetes: fix default crio mounting path
          pkg/labels: use LabelHealth constant across the code
          examples/kubernetes: fix 1.12 generated daemonset files
          pkg/kvstore: set hard timeout for etcd lock path to 1 minute
          deps: update k8s deps to 1.11.0
          pkg/k8s: update code with new k8s dependencies
          examples/kubernetes: restart kube-dns in the background
          pkg/workloads: check if Client() is nil to avoid nil pointer dereference
          pkg/k8s: enable CRD Status by default
          examples/kubernetes: add RBAC for cilium{networkpolicies,endpoints}/status
          test: update cilium_ds.template with latest RBAC rules
          Revert "bugtool: Include cilium map list --verbose"
          Revert "bpf: Support retries on map sync errors"
          Revert "bpf: Allow maintaining a local cache of BPF maps"
          pkg/endpoint: set state ready if endpoint labels are the same
          pkg/identity: add mutex around reservedIdentities map
          pkg/endpoint: use UpdateLabels instead of SetIdentityLabels
          pkg/identity: add function to add reserved numeric identities
          pkg/identity: add function to add reserved identities
          daemon: add fixed-identity-mapping option
          contrib: add fixed-identity-mapping to cilium options
          add cilium-host IP to k8s node's annotation
          k8s: Create ipcache entries for CiliumIP announce via node annotations
          daemon: GC ipcache for entries created by KVStore and/or agent-local
          pkg/node: Register node on the background
          kvstore/store: set listTimeoutDefault to 3 minutes
          examples/kubernetes: add etcd-operator deployment files
          daemon: on restore, run identity allocation in the background
          kvstore/allocator: start watcher without waiting
          pkg/kvstore: deleteLegacyPrefixes in the background
          pkg/kvstore: allow cilium to run without a etcd connection for 3 minutes
          pkg/endpointmanager: remove useless endpoint RLock
          examples/kubernetes: add missing generated spec for k8s 1.7
          pkg/kvstore: fix high-cpu usage when Cilium loses Consul connectivity
          pkg/endpoint: add UpdateStatus functionality for CEP
          Revert "Revert "test: update k8s to 1.8.14, 1.10.4 and 1.11.0""
          Revert "Revert "ginkgo-kubernetes-all.Jenkinsfile: move k8s 1.10 and 1.12 to same stage""
          test: update k8s to 1.9.9 and 1.10.5
          tests: disable k8s 1.12-alpha.0 tests
          k8s: watch for namespace label changes
          pkg/kvstore: fix literal copies lock value from
          docs: explicitly set kube-system namespace when applying new ConfigMap
          pkg/endpoint: fix endpoint.logger race condition
          pkg/endpoint: annotate pod with numeric identity
          daemon: always re-add CNP when receiving an update from Kubernetes
          examples/kubernetes: remove execution permission of Makefile
          kubernetes: set maxUnavailable to pods to 2 on upgrade
          k8s: watch for namespace changes
    
    Arvind Soni (4):
          expanded install guide for kops with complete steps from scratch
          Added example for the policy trace Added kubectl exec ... part to the cilium monitor command
          Fixed a reference that was to localhost Changed the clustername to include a username to avoid stepping on multiple clusters
          Change the prometheus yaml to deploy in monitoring namespace
    
    Cynthia Thomas (2):
          policy doc updates
          kops guide edits
    
    Daniel Borkmann (1):
          bpf: add cocci script to find wrong null checks
    
    Eloy Coto (100):
          Endpoint: Log policyRevision on endpoint log.
          Test: Kube-DNS use kubeadm deploy parameters
          apipanic: Log stack as string
          Test:Guestbook wait for pods to be ready
          Bugtool: dmesg with iso date format.
          Daemon: Fix endpoint log
          Test: CiliumReport delete check deadlocks
          Test: Add kubelet output per node.
          Vagrant: Update dev servers to cilium/ubuntu-dev box.
          Documentation: Update docs to minimun 4.9.17 kernel version
          Docs: Update minikube GSG.
          Test: Validate that endpoints are ready after Cilium restart
          Contrib: Backport script to use different versions
          Endpoint: Add more logs on endpoint creation
          CNI: return err if interface cannot be renamed
          Test: Cleanup runtime installation
          Test: Print test finished time
          Test: Avoid duplicating data on failures.
          Test: Upgrade wait until endpoints are ready
          Test: Wait until all pods are ready
          Test: Increate ssh sessions on VMS
          Test: SSH Execute set CMDRes.exitcode to 1 if command failed.
          Jenkins: Adjust Timeouts - Set global timeouts bigger - Set the limits per stage
          CI: Delete bugtool files correctly
          Test: MicroscopeStart return callback if error.
          Test: Microscope waiting until pods terminates.
          Test: Update Vagrant box to version 91
          Test: Refactor health test
          Test: Add CiliumExecAll on kubectl
          Test: Refactor k8st/Policies.go to use CEP resource
          Test: Refactor service to use CEP resource
          Test: Demos refactor to make it simple.
          Test: Delete WaitCiliumEndpointReady
          Test: Delete CiliumEndpointsListByLabel helper function
          Test: Delete WaitUntilEndpointUpdates helper function
          Test: remove kubectl.GetPolicyStatus
          Test: Cleanup unused kubectl helpers.
          Test: Precheck use the same docker-compose image
          Test: added WriteOrAppendToFile helper function
          Test: Microscope append the output to the file
          Test: Add microscope on Upgrade test
          Test: delete monitor.log if the test is successful
          Test: Refactor K8sValidatedPolicyTestAcrossNamespaces test.
          Test: WithTimeout executed on start
          Test: Chaos waiting until all Pods terminate
          Test: Set Curl timeout to 1 second.
          Test: Waiting all pods to terminate on K8st/Policies.go
          Test: Update cilium stable image to v1.0.4
          Test: Add microscope with timestamps
          Test: Upgrade test, delete kube-dns pods before install.
          TEST: Update kube-dns manifest for 1.11 and bigger versions.
          Test: add top and ps axu on report failed.
          Test: Removed CreateNewRuntimeHelper
          Test: Extends cmd.Filter to have helpers options
          Test: Added Pre flight checks on ExpectCiliumReady
          CI: Archive artifacts with the stage name.
          DOC: Contributing update missed ENV variables
          DOC: Update missexpelled words
          DOC: Fix contributing warnings messages
          DOC: Fix warnings on kube-router guide
          DOC: Fix warnings on troubleshooting guide
          CI: Disable fail-fast on Jenkins if no label.
          CI: Import Ginkgo Junit reporter to the project
          CI: Custom junit reporter
          Test: Fix Deadlock check
          Test: Add Checks output on Jenkins CI XML.
          Test: Add Check results on Deadlock helper
          Test: Add CiliumCheckReport on failed test.
          Test: Added the number of issues on report.
          Test: Fix lint issues
          Test: K8s/Tunnels wait until all pods terminate
          Test: Fix top command
          Test: Gomega enable the use of Stringer representation
          Test: Add SSHMetaError type
          Test: Upgrade test wait until pods are terminated.
          Test: Add Background process for kubernetes test.
          Vagrant: Bump K8S_VERSION to 1.11
          Test: Validate on Fail, added test panicked.
          Test: Added a quietMode in res.SendToLog()
          Test: Wait for Pods ensure that no deleted pods
          Test: Core-dns fix log issues
          Jenkins: Nightly run the conditional with env variable
          Test: Update policies names with the file name
          Test: Add the cilium.TestScope option
          Endpoint: Added logs for BPF compilation time
          Test: Dump Cilium Logs for the test in a separate file.
          Test: Added Kubernetes Netperf test
          Test: Delete the log.WithFields per each test case
          Test: no longer use Validated test
          Test: Use BeforeAll instead sync.Once
          Test: Services use GetPodNames helper instead Filter
          Test: K8st/Services refactor to use custom helpers.
          Test: Install always DNS deployments
          Test: CoreDNS using only one replicaset
          Test: Fix GRPC issue on Kubernetes
          Test: Kafka wait until all endpoints are ready.
          Test: Upgrade from version 1.1.1
          CI: Run netperf test on master
          Test: Provide more information on pre-flight check
          Jenkins: Update timeout on Nightly builds
    
    Ian Vernon (21):
          pkg/endpoint: access policy enforcement configuration directly in computeDesiredL3PolicyMapEntries
          daemon: check conf. options for policy enforcement within endpoint
          pkg/policy: take into account To / FromRequires when computing L4 policy
          daemon: fix minimum number of work threads unit test
          daemon: check if dry mode is enabled for misc. BPF map-related operations
          pkg/endpoint: remove ProxyWaitGroup field from Endpoint
          pkg/endpoint: refactor endpoint conf. update logic
          envoy: use local_resources parameter during bazel build
          pkg/endpoint: lock endpoint Status indexMU in logStatusLocked
          pkg/endpoint: use logStatusLocked in writeHeaderfile
          test: update Vagrantfiles to use box version 97
          pkg/policy/api: allow ToPorts coupled with ToServices
          pkg/policy/api: handle multiple CIDRs in CIDRSlice when adding reserved:world EndpointSelector
          test: add microscope YAML to manifests directory
          test/k8sT: wait for DNS to be ready in Kafka pods
          test/k8sT: disable microscope test temporarily
          Documentation: add misc. release instructions enhancements
          add consistent usage of logfields.LogSubsys
          daemon: refactor updating of CNP Node Status
          pkg/endpoint: rename LabelsMap to prevIdentityCache
          CODEOWNERS: modify CODEOWNERS for 1.2 release
    
    Jarno Rajahalme (8):
          vendor: Update golang/protobuf
          envoy: Update API location.
          envoy: Remove go_package options.
          envoy: Rebase to get gRPC timeout support.
          envoy: Update generated go protobufs
          Docs: Troubleshooting updates.
          Docs: Remove CoreOS Installation Guide
          envoy: Update Envoy dependency to release 1.7.0
    
    Joe Stringer (55):
          metrics: Add datapath management metrics
          ctmap: Add metrics for conntrack dump resets
          utils: Refactor EndpointSelector construction
          utils: Refactor reaching into EndpointSelector
          k8s: Use comparator.DeepEquals.Check in NP test
          k8s: Simplify EndpointSelector creation in tests
          k8s: Add test for rule translator
          k8s: Fix index error in CiliumRule parsing
          k8s: Refactor namespace checking in ParseToCiliumRule
          k8s: Fix auto-generated deepycopy functions
          ipcache: Split into multiple files
          ipcache: Set logging subsys to 'ipcache'
          ipcache: Count references to ipcache mappings
          daemon: Release ipcache entries on policy add failure
          daemon: Release identities in failure condition
          daemon: Refactor ipcache CIDR allocations to ipcache
          policy: Refactor getting CIDR prefixes from CIDR strings
          k8s: Allocate ipcache mappings for service backends
          ipcache: Improve comments for reference counter
          treewide: Avoid go build `-i`
          metricsmap: Fix index out of range error
          LICENSE: Update copyright column
          docs: Improve MTU upgrade notes to use mtu-update
          docs: Map stable RTD version to VERSION
          api: Add microbenchmarks for matching labels
          api: Cache Selector in EndpointSelector on create
          daemon: Mark all traffic from host with magic bits
          endpoint: Rename Opts -> Options
          option: Refactor BoolOptions into IntOptions
          bpf: Add MonitorAggregation option
          examples: Add MONITOR_AGGREGATION_LEVEL option
          bpf: Rename CILIUM_CALL_IPV[4]6 -> \*_FROM_LXC
          bpf: Refactor ingress trace/redirect to handlers
          bpf: Split ingress L3 handlers into tail calls
          bpf: Shift ingress ipcache source lookup to netdev
          daemon: Fix env bind for MONITOR_AGGREGATION_LEVEL
          Properly prefix aggregation level env variable name
          bpf: Ignore ipcache identity for cluster.
          policy: Update identity_is_reserved
          counter: Add new counter package
          daemon: Track prefix lengths in use in policy
          endpoint: Factor out generating IPCache prefix macro
          daemon: Generate IPCache prefixes for netdev program
          maps/ipcache: Fix max limit for LPM prefix lengths
          endpoint: Always serialize the old options field
          README: Point the docs image to docs.cilium.io
          README: Point docs deep links into the stable docs
          bpf: Don't rely on IPCache to identify host traffic
          daemon: Fix prefix length tracking on policy failure
          bpf: Track tcp_flags seen in conntrack
          bpf: Track rx,tx trace time in conntrack
          bpf: Extend trace to optionally avoid monitoring
          bpf: Document ct entry flags/timestamp race conditions
          option: Add Medium MonitorAggregationLevel
          Policies: Check external access before test
    
    John Fastabend (2):
          cilium: bpf: remove unused sectx in conntrack
          cilium: bpf: use conntrack for service backend tracking in lxc
    
    Maciej Kwiek (14):
          Terminate microscope in CI properly
          Microscope test fix
          Fix `go vet` issue
          Adjust installation from source guide
          Push nightly image to dockerhub
          Add docs for nightly image
          CmdRes.Unmarshal silent fail for non-pointer fix
          Move Nightly-Docker-Image stage to front
          Use microscope CI image in ginkgo tests
          Fix nightly branch condition
          Add label script for backporting
          Add label script docs to backporting process
          Add client timeout for Cilium API
          Increase timeout on endpoint generations
    
    Manali Bhutiyani (15):
          daemon: Delete deprecated code to remove older cilium-envoy.log at startup
          test/manifest: Remove automatic topic creation on container start
          test/runtime:  Remove hardcoded timeouts in the kafka runtime test
          test/runtime: Change check from listTopics to createTopics to check if Kafka broker is up.
          test/K8s: Wait for kafka broker to be up correctly.
          test/k8s: Increase kafka-zookeeper session/connection timeout to 60 sec
          test/runtime: Increase kafka-zookeeper session/connection timeout to 60 sec
          docs/examples: Increase kafka-zookeeper session/connection timeout to 60 sec
          daemon: Fix endpoint restore log regarding health endpoint
          metrics: Expose endpoint and policy computation time metrics
          docs: Expose endpoint and policy computation time metrics
          docs: Add the endpoint state count metrics to docs
          docs: Deprecate EndpointCountRegenerating in favor of EndpointStateCount
          metrics: Add metrics to report count of current endpoints tagged by states.
          metrics: Deprecate EndpointCountRegenerating in favor of EndpointStateCount
    
    Mark deVilliers (1):
          Check for nil before accessing Status
    
    Michal Rostecki (4):
          pidfile: Fix error message formatting
          cmd: Detect BPF map root properly
          test: Change CPU environment variable to CPUS
          cilium-health: Fix logging initialization
    
    Nirmoy Das (6):
          daemon: add configuration option for the GC collection interval
          cilium-health: accept only positive interval
          doc: add opensuse to Distribution Compatibility Matrix
          contrib: add sysconfig file headers
          cilium-docker: fix gatewayIPv4 assignment
          bpf: fix gcc-8 warnings
    
    Ray Bejjani (12):
          doc: better text in basic-rules k8s link
          backport: use the same url for all searches
          backport: Only check merged PRs
          policy: Add ToFQDNs to CiliumNetworkPolicy API
          policy: Support ToFQDN rules via DNS poller
          policy: DNS Poller initializes error map on poll
          codeowners: Update CODEOWNERS
          contrib: jenkins-failures.sh takes start time
          doc: Triage guide has more tooling and examples
          CI: Different random seed on each run
          daemon: Remove unused pipexec package
          daemon: Remove unused syncbytes package
    
    Romain Lenglet (23):
          xds: Add Kafka rules into NPDS
          docs: Update required Bazel version in the contributing section
          docs: Add missing spelling words
          docs: Remove sidecar-http-proxy config from upgrade instructions
          envoy: Parse and log Envoy log messages at their actual level
          controller: Fix controller update
          bpf: Set the proxy port in policy map entries
          bpf: Remove CFG_L3L4_INGRESS/CFG_L3L4_EGRESS generation and lookup
          bpf: Only define IPCACHE4/6_PREFIXES macros if LPM is not supported
          cli: Output proxy port in "cilium bpf policy get"
          tests: Remove tracing test cases from KafkaPolicies
          tests: Fix 10-proxy.sh to wait for all endpoints to get an ID
          endpoint: Fix sidecar proxy deadlock during BPF generation
          daemon: Add sidecar-istio-proxy-image flag
          examples/kubernetes: Add sidecar-istio-proxy-image config map setting
          envoy: Include the redirect port into each Envoy listener name
          ipcache: Fix handling of endpoint IP events
          ipcache: Maintain IP to host IP cache
          makefile: Run go tool vet on the api and pkg subdirs
          tests: Use gocheck in pkg/workloads tests
          bpf: Re-add bpf map diff debug logging into Map.MetadataDiff
          doc: Support BSD sed in Istio GSG
          doc: Disable unused Istio services in Istio GSG
    
    Shantanu Deshpande (1):
          Fix nesting for Upgrade notes for 1.1
    
    Thomas Graf (94):
          doc: Provide egress example to kube-dns across namespaces
          doc: Document k8s troubleshooting scripts
          doc: Restructure troubleshooting section
          test: Use latest stable etcd and consul images
          allocator: benchmark: Reserve ID space for reserved identities
          trigger: New trigger package
          identity: Process identity events in batches
          identity: Fix allocator init with more than pre-existing 1024 keys
          allocator: Avoid scanning sequentual list when allocating
          cni: Change default configuration filename to 00-cilium.conf
          allocator: Re-use randomly generated ID sequence between allocations
          identity: Move CIDR identity code into pkg/identity/cidr
          k8s: Remove dependency on k8s.io/kubernetes/pkg/kubelet/types
          k8s: Move annotation constants to pkg/k8s/apis/cilium.io
          labels: Move models dependent code into pkg/labels/model
          labels: Move PathDelimiter definition to pkg/labels
          common: Remove unused constants
          agent: Require go 1.10 for safe namespace operations
          kubernetes: Simple connectivity check demo app
          Documentation: Re-work the contributor guide
          Doc: Fix service account policy example
          kvstore: Fix unintentional info message
          agent: Remove unused GetTunnelMode()
          endpoint: Fix misleading debug log
          endpoint: Remove erroneous err check
          agent: Record elapsed time after finishing bootstrapping
          endpoint: Fix restored endpoints not showing up in ipcache
          service: Move service ID handling to pkg/service
          servive: Rename service ID management functions
          service: Introduce local service ID allocation
          node: Add kvstore based node discovery
          node: Provide `cilium node list` command
          mtu: Introduce device MTU concept
          mtu: Automatically detect MTU of underlying network
          doc: Remove obsolete MTU sections
          Revert "ginkgo-kubernetes-all.Jenkinsfile: move k8s 1.10 and 1.12 to same stage"
          Revert "test: update k8s to 1.8.14, 1.10.4 and 1.11.0"
          Split plugin logic into pkg/datapath/(link|route) and pkg/endpoint/connector
          agent: Add support for--tunnel=disabled option
          kubernetes: Configure tunnel mode via ConfigMap
          bpf: Remove existing encapsulation devices when tunneling is disabled
          agent: Reject combination of --tunnel=disabled and --single-cluster-route
          node: Simplify code by using viper directly
          node: Do not install node routes when tunneling is disabled
          doc: Provide guide on how to install Cilium + kube-router
          agent: Adjust SNAT conditions for direct routing mode
          bpf: Add ipcache based fallback to derive ingress source identity
          mtu: Don't account for encapsulation overhead if tunneling is disabled
          Move common/colors.go into pkg/color
          service: Fix local service ID restore
          kvstore: Support creation of multiple clients
          testutils: Add WaitUntil
          bpf: Fix ipcache lookup for kernels with HAVE_LPM_MAP_TYPE
          store: Make kvstore backend configurable
          ipcache: Allow providing kvstore client to watcher
          bpf: If available, use ipcache for encapsulation
          ipcache: Populate ipcache based on Pod events
          ipache: Skip Upsert() if IP is already mapped to given identity
          bpf: Fix ipcache lookup for kernels with HAVE_LPM_MAP_TYPE again
          bpf: Support fall back to routing layer for overlay ingress
          test: Increase connect timeout to 3 seconds
          bugtool: Collect ps auxfww instead of just ps
          endpoint: Fix deadlock and missing lock during syncPolicyMap()
          bpf: Allow maintaining a local cache of BPF maps
          bpf: Support retries on map sync errors
          bugtool: Include cilium map list --verbose
          cni: Check if directories exist before creating them
          bpf: Allow to use 24 bits for security identities
          bpf: Remove unused code to skip policy going to the stack
          bpf: Allow maintaining a local cache of BPF maps
          bpf: Support retries on map sync errors
          bugtool: Include cilium map list --verbose
          k8s: Update HostIP even if identity is unchanged
          doc: Add example how to enforce Kubernetes namespace boundaries
          bpf: Fix ipcache lookup in bpf_netdev
          ipcache: Fall back to update based delete
          envoy: Do not exit agent if NPHDS entry cannot be found
          bpf: Remove misleading MaxIdentity const
          kvstore: Tag log messages with subsys field
          etcd: Cache status in etcd client structure instead of global variables
          allocator: Support watching allocations in arbitrary kvstore connections
          agent: Add --cluster-name option
          node: Support associating nodes with a cluster
          k8s: Represent cluster name as label io.cilium.k8s.policy.cluster in identity
          node: Initialize clusterConf early
          etcd: Fix and relax during recreate watcher loop
          CI: Prefix etcd address with http://
          CI: Be more verbose in unit tests output
          kubernetes: Add CILIUM_MONITOR_AGGREGATION_LEVEL to crio-o DaemonSet
          consul: Add timeout to List() in Watch() to detect watcher stop
          kvstore: Wait for kvstore watcher to exit
          Inter cluster connectivity (ClusterMesh)
          clustermesh: Update DaemonSet and ConfigMap templates
          clustermesh: Add getting started guide
          AUTHORS: Update to latest list
    
    Tony Lambiris (1):
          Use Fedora 28 base and update spec file
    
    Zinin D.A (1):
          Python yamllint friendly
    
    andrewsykim (1):
          add external peer configuration to cilum + kube-router docs
    
    ifeanyi (1):
          option: Add unit tests
    
    
v1.0.0-rc9
==========

:date: 2018-04-01
:commit: f1d4144ddb62003ccf58e016c523f323ad82c3a1

Major Changes
-------------

* envoy: Make 403 message configurable. (3430_, @jrajahalme)
* Add support label-dependent L4 egress policy (3372_, @ianvernon)

Bugfixes Changes
----------------

* Fix entity dependent L4 enforcement (3451_, @tgraf)
* cli: Fix cilium bpf policy get (3446_, @tgraf)
* Fix CIDR ingress lookup (3406_, @joestringer)
* xds: Handle NACKs of initial versions of resources (3405_, @rlenglet)
* datapath: fix egress to world entity traffic, add e2e test  (3386_, @ianvernon)
* bug: Fix panic in health server logs if /healthz didn't respond before checking status (3378_, @nebril)
* pkg/policy: remove fromEntities and toEntities from rule type (3375_, @ianvernon)
* Fix IPv4 CIDR lookup on older kernels (3366_, @joestringer)
* Fix egress CIDR policy enforcement (3348_, @tgraf)
* envoy: Fix concurrency issues in Cilium xDS server (3341_, @rlenglet)
* Fix bug where policies associated with stale identities remain in BPF policy maps, which could lead to "Argument list too long" errors while regenerating endpoints (3321_, @joestringer)
* Update CI and docs : kafka zookeeper connection timeout to 20 sec (3308_, @manalibhutiyani)
* Reject CiliumNetworkPolicy rules which do not have EndpointSelector field (3275_, @ianvernon)
* Envoy: delete proxymap on connection close (3271_, @jrajahalme)
* Fix nested cmdref links in documentation (3265_, @joestringer)
* completion: Fix race condition that can cause panic (3256_, @rlenglet)
* Additional NetworkPolicy tests and egress wildcard fix (3246_, @tgraf)
* Add timeout for getting etcd session (3228_, @nebril)
* conntrack: Cleanup egress entries and distinguish redirects per endpoint (3221_, @rlenglet)
* Silence warnings during endpoint restore (3216_, @tgraf)
* Fix MTU connectivity issue with external services (3205_, @joestringer)
* endpoint: Don't fail with fatal on l4 policy application (3199_, @tgraf)
* Add new Kafka Role to the docs (3186_, @manalibhutiyani)
* Fix log records for Kafka responses (3127_, @tgraf)

Other Changes
-------------

* Refactor /endpoint/{id}/config for API 1.0 stabilit (3448_, @tgraf)
* envoy: Add host identity (nphds) gRPC client (3407_, @jrajahalme)
* Increase capacity of BPF maps (3391_, @tgraf)
* daemon: Merge Envoy logs with cilium logs by default. (3364_, @jrajahalme)
* docs: Fix the Kafka policy to use the new role in the GSG (3350_, @manalibhutiyani)
* CI / GSG : make Kafka service headless (3320_, @manalibhutiyani)
* Use alpine as base image for Docs container (3301_, @iamShantanu101)
* Update kafka zookeeper session timeout to 20 sec in CI tests and docs (3298_, @manalibhutiyani)
* Support access log from sidecar and per-endpoint redirect stats (3278_, @rlenglet)
* Improve sanity checking in endpoint PATCH API (3274_, @joestringer)
* Update Kafka GSG policy and docs to use the new "roles" (3269_, @manalibhutiyani)
* maps: allow for migration when map properties change (3267_, @borkmann)
* bpf: Retire CT entries quickly for unreplied connections  (3238_, @joestringer)
* CMD: Add json output on endpoint config (3234_, @eloycoto)
* Plumb the contents of the ip-identity cache to a BPF map for lookup in the datapath. (3037_, @ianvernon)


v1.0.0-rc8
==========

:date: 2018-03-19
:commit: bb11ad1a15907feb9304f55a26a95bed77291f1d

Major Changes
-------------

* Bump kubernetes minimal version supported to 1.7 (3102_, @aanm)
* Add Kafka roles to simplify policy specification language (2997_, @manalibhutiyani)
* Add support for label-based policies on egress (2878_, @ianvernon)
* Add mapping of endpoint IPs to security identities in the key-value store. Watch the key-value store for updates and cache them locally per agent. (2875_, @ianvernon)
* Cilium exports CiliumEndpoint objects to kubernetes clusters. (2772_, @raybejjani)

Bugfixes Changes
----------------

* pkg/ipcache: check if event type is EventTypeListDone before unmarshal of value (3193_, @ianvernon)
* proxy: envoy: use url.Parse() to generate URL field (3188_, @tgraf)
* Fix bug where IPv6 proxy map entries were never garbage collected (3181_, @joestringer)
    * Log failure to insert into proxymap as its own monitor drop log
    * Lower timeout for bpf proxy map entries (now 5 minutes)
* Kafka CI: Add a WaitKafkaBroker to wait for Kafka broker to be up before produce/consume (3156_, @manalibhutiyani)
* GinkgoRuntime CI: Avoid possible race between Kafka consume and produce (3153_, @manalibhutiyani)
* Documentation: Fix generated links when documentation is built from tags (3128_, @tgraf)
* create new identity when endpoint labels change and re assign identity based on all endpoint labels when restoring (3104_, @aanm)
* Fix cilium status of k8s CRD watcher when unable to set up k8s client (3103_, @aanm)
* examples/mesos: Change ubuntu VB to be correct version (3094_, @jMuzsik)
* cilium status: Fix exit code when components are disabled (3069_, @tgraf)
* Fix L4-only policy enforcement on ingress without `fromEndpoints` selector (2992_, @joestringer)
* Add compatibility for kubernetes 1.11  (2966_, @aanm)
* Remove proxymap entry after closing connection (3190_, @tgraf)

Other Changes
-------------

* examples: Provide simple etcd standalone deployment example (3167_, @tgraf)
* Report policy revision implemented by the proxy in Endpoint model (3151_, @joestringer)
* Ginkgo: Add a option to run test in different vms (3120_, @eloycoto)
* Support a larger number of CIDR prefixes when running on older kernels. Now limited by the number of unique prefix lengths in the policies for an endpoint, which should be less than forty.  (3119_, @joestringer)
* Only expose cilium-health API over unix socket by default (3096_, @joestringer)
* Reject policies that contain rules with more than one L3 match in a single rule (3015_, @joestringer)


v1.0.0-rc7
==========

:date: 2018-03-08
:commit: 9412a28332cd0d7afe489f6efd37edc8668f3a81

Bugfixes Changes
----------------

* add "update" verb for customresourcedefinitions in cilium DaemonSet spec file (3052_, @aanm)
* bpf: Move calls map to temporary location and remove after filter replacement (3049_, @tgraf)
* bpf: Remove policy maps of programs loaded in init.sh (3042_, @tgraf)
* agent: Fix manual endpoint regeneration (3040_, @tgraf)
* Fix cilium CRD update in case schema validation changes (3029_, @aanm)
* examples/getting-started: Fix failure to install docker (3020_, @tgraf)
* bpf: Retry opening map after initial error (3018_, @tgraf)
* consul: Report modified keys even if previously not known (3013_, @tgraf)
* Restore error behaviour of endpoint config updates (3054_, @ianvernon)

Other Changes
-------------

* Delete obsolete cilium-envoy.log on startup (3047_, @manalibhutiyani)
* Introduce `DebugLB` option in endpoint config (3036_, @joestringer)
* Support log rotation for envoy log (3034_, @manalibhutiyani)


v1.0.0-rc6
==========

:date: 2018-03-02
:commit: 5e90ac8271773a8d4cceca8b61511062489e845d

Bugfixes Changes
----------------

* Envoy: add NACK processing (2991_ @jrajahalme)
* envoy: Use downstream HTTP protocol for upstream connections. (2970_ @jrajahalme)

Other Changes
-------------

* Removed action field from BPF policy map entries (2918_ @joestringer)


Version 1.0-rc5
===============

:date: 2018-02-27
:commit: 0c269fc0212ce789c28e068137c6a963411e6df4

Bugfixes Changes
----------------

* Fix BPF policy map specification inconsistency between BPF programs (2953_ @joestringer)
* k8s: Do not attempt to sync headless services to datapath (2937_ @tgraf)
* identity cache: Support looking up reserved identities (2922_ @tgraf)
* Fix IPv4 L4 egress policy enforcement with service port mapping (2912_ @joestringer)
* Fix kubernetes default deny policy for kubernetes 1.7 (2887_ @aanm)
* Log Kafka responses (2881_ @tgraf)
* Several fixes to support long-lived persistent connections (2855_ @tgraf)
* Clean endpoint BPF map on daemon start (2814_ @mrostecki)

Other Changes
-------------

* Add documentation on how to retrieve overall health of cluster (2944_ @tgraf)
* monitor: Introduce channel to buffer notifications and listeners (2933_ @tgraf)
* bpf: Warn if another program is using a VXLAN device (2929_ @tgraf)
* Make Kafka K8s GSG CI tests work on multinode setup (2926_ @manalibhutiyani)
* Add proxy status to cilium status (2894_ @tgraf)
* contrib: Add script to run cilium monitor on all k8s nodes (2867_ @tgraf)
* Update example cilium-ds.yaml files to support rolling updates. (2865_ @ashwinp)
* Add cluster health summary to `cilium status` (2858_ @joestringer)
* Consistently use `-o json` as the CLI arguments for printing JSON output across all commands that support JSON output (2852_ @joestringer)
* Simplify output of `cilium status` by default, add new `--verbose`, `--brief` options (2821_ @joestringer)
* Ginkgo : Support K8s CI Coverage for Kafka GSG (2806_ @manalibhutiyani)


Version 1.0-rc4
===============

:date: 2018-02-15
:commit: 95a2c8aeae18c2c62e1f969e02dff15913cdf267

Major Changes
-------------

* api: Introduce & expose endpoint controller statuses (2720_, @tgraf)
* More scalable kvstore interaction layer (2708_, @tgraf)
* Add agent notifications & access log records to monitor (2667_, @tgraf)
* Remove oxyproxy and make Envoy the default proxy (2625_, @jrajahalme)
* New controller pattern for async operations that can fail (2597_, @tgraf)
* Add cilium-health endpoints for datapath connectivity probing (2315_, @joestringer)

Bugfixes Changes
----------------

* Avoid concurrent access of rand.Rand (2823_, @tgraf)
* kafka: Use policy identity cache to lookup identity for L3 dependant rules (2813_, @manalibhutiyani)
* envoy: Set source identity correctly in access log. (2807_, @jrajahalme)
* replaced sysctl invocation with echo redirects (2789_, @aanm)
* Set up the k8s watchers based on the kube-apiserver version 2731 (#2735_, @aanm)
* bpf: Use upper 16 bits of mark for identity (2719_, @tgraf)
* bpf: Generate BPF header in order after generating policy (2718_, @tgraf)
* Kubernetes NetworkPolicyPeer allows for PodSelector and NamespaceSelector fields to be optional. (2699_, @ianvernon)
    * Gracefully handle when these objects are nil when we are parsing NetworkPolicy.
* Enforce policy update immediately on ongoing connections 2569 #2408 (#2684_, @aanm)
* envoy: fix rule regex matching by host (2649_, @aanm)
* Kafka: Correctly check msgSize in ReadResp before discarding. (2637_, @manalibhutiyani)
* Fix envoy deadlock after first crash (2633_, @aanm)
* kafka: Reject requests on empty rule set (2619_, @tgraf)
* CNP CRD schema versioning (2614_, @nebril)
* Fix race while updating L7 proxy redirect in L4PolicyMap (2607_, @joestringer)
* Don't allow API users to modify reserved labels for endpoints. (2595_, @joestringer)


Version 1.0-rc3
===============

:date: 2018-01-18
:commit: nil

Changes
-------

* Multi stage Docker builds to use prebuilt Envoy dependencies. (2452_, @jrajahalme)
* clusterdebug tool to help identify the most commonly encountered (2348_, @ashwinp)
* Document how pull-request builds work with Cilium's Jenkins setup (2521_, @ianvernon)
* cli: Add "cilium bpf proxy list" command (2504_, @mrostecki)
* Document multi node connectivity troubleshooting (2499_, @tgraf)
* Added option to allow running cilium-agent on a node with no container runtime (2490_, @aanm)
* cli: Add JSON formatting in "cilium config" (2489_, @mrostecki)
* Update version cmd output to json (2453_, @stevenceuppens)
* Envoy: Reflect cilium log level to Envoy. (2436_, @jrajahalme)
* Fix Ginkgo Kafka tests to initialize config for policy enforcement to default (2432_, @manalibhutiyani)
* Use version 2.7 of developer box, which contains commonly-used Docker images for tests pre-packaged (2404_, @ianvernon)
* monitor: add gops (2393_, @scanf)
* Tl/fix rpm package build (2386_, @tonylambiris)
* Reduce the readinessProbe delay to mark the pod as ready earlier (2377_, @tgraf)
* Correctly report destination identity in datapath traces for packets to host, world, and cluster (2359_, @manalibhutiyani)
* Allow for empty endpoint selector. This enables defining policy which applies to all endpoints. (2358_, @tgraf)
* docs: Cluster-wide debugging tool documentation (2356_, @ashwinp)
* Add CRD validation for CNP in kubernetes (2304_, @aanm)
* Use DNS names in getting started guides (2254_, @techcet)
* use cilium/connectivity-container in nightly tests (2247_, @ianvernon)
* fail all stages in build if any stage fails in Jenkins (2246_, @ianvernon)
* Enabled policy enforcement on cilium network policy from any namespace (2235_, @aanm)

Bugfixes
--------

* agent: Increase timeout when executing commands (2512_, @tgraf)
* Fix too small timeout causing containers not to show up as endpoints under heavy system load (2508_, @tgraf)
* Correct a bug that rejected IPv4 backend headless services from k8s (2502_, @raybejjani)
* Endpoint: Fix panic when trying to delete on restore. (2478_, @eloycoto)
* Fix an issue where cilium would crash if two endpoint disconnect endpoints for the same endpoint occurred in quick succession. (2396_, @joestringer)
* cni: Create destination directory if it does not exist (2382_, @tgraf)
* Allow for empty endpoint selector. This enables defining policy which applies to all endpoints. (2358_, @tgraf)
* Fix nil pointer when v6 CIDR was not set by kubernetes. (2355_, @aanm)
* Fix for allowing Cilium to run with BPF interpreter instead of JIT when JIT is compiled out. (2350_, @borkmann)
* Fix bug which was causing incorrect policy enforcement after restarting cilium (2340_, @aanm)
* Fix nil pointer access when unable to reach the KVStore (2325_, @aanm)
* Fix stuck "restoring" state while restoring the endpoints 2167 (2324_, @aanm_)
* Enable multiple policies with the same name but on different namespaces to be enforced 1938 (2313_, @aanm_)
* Fix logging setup for submodules (2299_, @aanm)
* Fix `cilium bpf policy list` to print l4 ports (2271_, @joestringer)
* Kafka: producing messages denied by policy crashes Cilium agent (2265_, @manalibhutiyani)
* Fix bug when endpoint does not get out of WaitingForIdentity state (2237_, @tgraf)
* Enforcing policy after loading policy when endpoints where in "default" policy enforcement mode. (2219_, @aanm)

Version 1.0-rc2
===============

:date: 2017-12-04
:commit: nil

Major Changes
-------------

* Tech preview of Envoy as Cilium HTTP proxy, adding HTTP2 and gRPC support. (1580_, @jrajahalme)
* Introduce "cilium-health", a new tool for investigating cluster connectivity issues. (2052_, @joestringer)
* cilium-agent collects and serves prometheus metrics (2127_, @raybejjani)
* bugtool and debuginfo (2044_, @scanf)
* Add nightly test infrastructure (2212_, @ianvernon)
* Separate ingress and egress default deny modes with better control (2156_, @manalibhutiyani)
* k8s: add support for IPBlock and Egress Rules with IPBlock (2096_, @ianvernon)
* Kafka: Support access logging for Kafka requests/responses (1870_, @manalibhutiyani)
* Added cilium endpoint log command that returns the endpoint's status log (2060_, @raybejjani)
* Routes connecting the host to the Cilium IP space is now implemented as
  individual route for each node in the cluster. This allows to assign IPs
  which are part of the cluster CIDR to endpoints outside of the cluster
  as long as the IPs are never used as node CIDRs. (1888_, @tgraf)
* Standardized structured logging (1801_, 1828_, 1836_, 1826_, 1833_, 1834_, 1827_, 1829_, 1832_, 1835_, @raybejjani_)

Bugfixes Changes
----------------

* Fix L4Filter JSON marshalling (1871_, @joestringer)
* Fix swapped src dst IPs on Conntrack related messages on the monitor's output (2228_, @aanm)
* Fix output of cilium endpoint list for endpoints using multiple labels. (2225_, @aanm)
* bpf: fix verifier error in dameon debug mode with newer LLVM versions (2181_, @borkmann)
* pkg/kvstore: fixed race in internal mutex map (2179_, @aanm)
* Proxy ingress policy fix for LLVM 4.0 and greater. Resolves return code 500 'Internal Error' seen with some policies and traffic patterns. (2162_, @jrfastab)
* Printing patch clang and kernel patch versions when starting cilium. (2137_, @aanm)
* Clean up Connection Tracking entries when a new policy no longer allows it. 1667, 1823 (#2136_, @aanm_)
* k8s: fix data race in d.loadBalancer.K8sEndpoints (2129_, @aanm)
* Add internal queue for k8s watcher updates 1966 (2123_, @aanm_)
* k8s: fix missing deep copy when updating status (2115_, @aanm)
* Accept traffic to Cilium in FORWARD chain (2112_, @tgraf)
* Fix SNAT issue in combination with kube-proxy, when masquerade rule installed by kube-proxy takes precedence over rule installed by Cilium. (2108_, @tgraf)
* Fixed infinite loop when importing CNP to kubernetes with an empty kafka version (2090_, @aanm)
* Mark cilium pod as CriticalPod in the DaemonSet (2024_, @manalibhutiyani)
* proxy: Provide identities { host | world | cluster } in SourceEndpoint (2022_, @manalibhutiyani)
* In kubernetes mode, fixed bug that was allowing cilium to start up even if the kubernetes api-server was not reachable 1973 (2014_, @aanm_)
* Support policy with EndpointSelector missing (1987_, @raybejjani)
* Implemented deep copy functionality when receiving events from kubernetes watcher 1885 (1986_, @aanm_)
* pkg/labels: Filter out pod-template-generation label (1979_, @michi-covalent)
* bpf: Double timeout on building BPF programs (1949_, @raybejjani)
* policy: add PolicyTrace msg to AllowsRLocked() when L4 policies not evaluated (1939_, @gnahckire)
* Handle Kafka responses correctly (1924_, @manalibhutiyani)
* bpf: Avoid excessive proxymap updates (2210_, @joestringer)
* cilium-agent correctly restarts listening for CiliumNetworkPolicy changes when it sees decoding errors (1899_, @raybejjani)

Other Changes
-------------

* Automatically generate command reference of agent (2223_, @tgraf)
* Access log rotation support with backup compression and automatic deletion support. (1995_, @manalibhutiyani)
* kubernetes examples support prometheus metrics scraping (along with sample prometheus configuration) (2192_, @raybejjani)
* Start serving the cilium API almost immediately while restoring endpoints on the background. (2116_, @aanm)
* Added cilium endpoint healthz command that returns a summary of the endpoint's health (2099_, @raybejjani)
* Documentation: add a CLI reference section (2079_, @scanf)
* Documentation: add support for tabs via plugin (2078_, @scanf)
* Feature Request: Add option to disable loadbalancing  (2048_, @manalibhutiyani)
* monitor: reduce overhead (2037_, @scanf)
* Use auto-generated client to communicate with kube-apiserver (2007_, @aanm)
* Documented kubernetes API Group usage in docs (1989_, @raybejjani)
* doc: Add Kafka policy documentation (1970_, @tgraf)
* Add Pull request and issue template (1951_, @tgraf)
* Update Vagrant images to ubuntu 17.04 for the getting started guides (1917_, @aanm)
* Add CONTRIBUTING.md (1898_, @tgraf)
* Introduction of release notes gathering script in use by the Kubernetes project (1893_, @tgraf)
* node: Install individual per node routes (1888_, @tgraf)
* Add CLI for dumping BPF endpoint map (lxcmap) (1854_, @joestringer)
* add command for resetting agent state (1678_, @scanf)
* Improved CI testing infrastructure and fixed several test flakes (1848_, 1865_)
* Foundation of new Ginkgo build-driven-development framework for CI (1733_)

Version 0.12
============

:date: 2017-10-26
:commit: nil

Bug Fixes
---------
* Various bugfixes around mounting of the BPF filesystem (1379_, 1473_)
* Fixed issue where L4 policy trace would incorrectly determine that traffic
  would be rejected when the L4 policy specifies the protocol (1587_)
* Provided workaround for minikube when running in unencrypted mode (1492_)
* Synchronization of compilation of base and endpoint programs (1440_)
* Provide backwards compatibility to iproute2-4.8.0 (1474_)
* Multiple memory leak fixes in cgo usage (1508_)
* Various fixes around load-balancer synchronization (1352_)
* Improved readability of BPF compatibility check on startup (1505_, 1548_)
* Fixed maintainer label in Dockerfile (1513_)
* Correctly set the transport protocol in proxy flows (1511_)
* Fix group ownership of monitoring unix domain socket to allow running
  ``cilium monitor`` without root privileges if correct group associated is
  provided (1532_)
* Fixed quoting of API socket path in error message (1531_)
* Fixed a bug in the k8s informer/watcher where a parse error in client-go
  would never recover (1545_)
* Use an IPv6 site local address as the IPv6 host address if no IPv6 address
  is configured on the node. This prevents from accidentally enabling unwanted
  IPv6 DNS resolution on the system. (1555_)
* Configure automatically generated host IPs as link scope to avoid them being
  selected as source IP for traffic exiting the node (1575_, 1614_)
* Fixed a bug where endpoint identities could run out of sync with the kvstore
  (1558_)
* Fixed a bug in the ability to perform policy simulation for L4 flows (1569_)
* Masquerade traffic from host into local cilium endpoints with the ExternalIP
  to allow for such packets to be routed other nodes (1570_)
* Fixed policy trace with tcp/udp protocol filter (1596_, 1599_)
* Bail out gracefully if running compatibility mode with limited CIDR filter
  capacity (1507_)
* Fixed incorrect double backslash in CoreOS unit file example (1605_)
* Fixed concurrent access issue of bytes.Buffer use (1623_)
* Made node monitor thread safe (1622_)
* Use specific version of cilium images instead of stable in getting started
  guide (1642_)
* Fix to guarantee to always handle events for a particular container in order
  (1677_)
* Fix endpoint build deadlock (1777_)
* containerd watcher resyncs on missed events better (1691_)
* Free up allocated memory for state on poll false positives (1821_)
* Fix deadlock when running ``cilium endpoint list -l <label>`` (1858_)
* Fall back to host networking on overlay non-match (1847_)

Features
--------

* Initial code to start supporting Kafka policy enforcement (1634_, 1757_)
* New ``json`` and ``jsonpath`` output modes for the cilium CLI command.
  (1484_)
* New simplified policy model to express connectivity to special entities
  "world" (outside of the cluster) and "host" (system on which endpoint is
  running on) (1651_, 1665_)
* XDP based early filtering of hostile source IP prefixes as well as
  enforcement of destination IPs to correspond to a known local endpoint and to
  host IPs. (1675_)
* L7 logging records now include as much information about the identity of the
  source and destination endpoint as possible. This includes the labels of the
  identity if known to the local agent as well as additional information about
  the identity of the destination when outside of the cluster (1550_, 1615_)
* Much reduced time required to rebuild endpoint programs (1638_)
* Initial support to allow running multiple user space proxies (1661_)
* New ``--auto-ipv6-node-routes`` agent flag which automatically populates IPv6
  routes for all other nodes in the cluster. This provides a minimalistic routing
  control plane for IPv6 native networks (1479_)
* Support L3-dependent L4 policies on ingress (1599_, 1496_, 1217_, 1064_, 789_)
* Add bash code completion (1597_, 1643_)
* New RPM build process (1528_)
* Default policy enforcement behavior for non-Kubernetes environments is now
  the same as for Kubernetes environments; traffic is allowed by default until
  a rule selects an endpoint (1464_)
* The default policy enforcement logic is now in line with Kubernetes behaviour
  to avoid confusion (1464_)
* Extended ``cilium identity list`` and ``cilium identity get`` to provide a
  cluster wide picture of allocated security identities (1462_, 1568_)
* New improved datapath tracing functionality with better indication of
  forwarding decision (1466_, 1490_, 1512_)

Kubernetes
----------

* Tested with Kubernetes 1.8 release
* New improved DaemonSet file which automatically derives configuration on how
  to access the Kubernetes API server without requiring the user to specify a
  kubeconfig file (1683_, 1381_)
* Support specifying parameters such as etcd endpoints as ConfigMap (1683_)
* Add new fields to Ingress and Egress rules for CiliumNetworkPolicy called
  FromCIDR and ToCIDR. These are lists of CIDR prefixes to whitelist along with
  a list of CIDR prefixes for each CIDR prefix to blacklist. (1663_) 
* Improved status section of CiliumNetworkPolicy rules (1574_)
* Improved logic involved to Kubernetes node annotations with IPv6 pod CIDR
  (1563_)
* Refactor pod annotation logic (1468_)
* Give preference to Kubernetes IP allocation (1767_)
* Re-wrote CRD client to fix "no kind Status" warning (1817_)

Documentation
-------------

* Policy enforcement mode documentation (1464_)
* Updated L3 CIDR policy documentation (1663_)
* New BPF developer debugging manual (1548_)
* Added instructions on kube-proxy installation and integration (1585_)
* Added more developer focused documentation (1601_)
* Added instructions on how to configure MTU and other parameters in
  combination with CNI (1612_)
* API stability guarantees (1628_)
* Make GitHub URLs depend on the current branch (1764_)
* Document assurances if Cilium or its dependencies get into a bad state (1713_)
* Bump supported minikube version (1816_)
* Update policy examples (1837_)

CI
__
* Improved CI testing infrastructure and fixed several test flakes (1632_,
  1624_, 1455_, 1441_, 1435_, 1542_, 1776_)
* New builtin deadlock detection for developers. Enable this in Makefile.defs. (1648_)

Other
-----
* Add new --pprof flag to serve the pprof API (1646_)
* Updated go to 1.9 (1519_)
* Updated go dependencies (1519_, 1535_)
* go-openapi, go-swagger (0.12.0), 
* Update Sirupsen/logrus to sirupsen/logrus (1573_)
* Fixed several BPF lint warnings (1666_)
* Silence errors in 'clean-tags' Make target (1793_)

Version 0.11
=============

:date: 2017-09-07
:commit: 6725f0c4bed2b499ca5651d7ae1746908e018afc

Bug Fixes
---------

* Fixed an issue where service IDs were leaked in etcd/consul. Services have
  been moved to a new prefix in the kvstore. Old, leaked service IDs are
  automatically removed when a fixed cilium-agent is started. (1182_, 1195_)
* Fixed accuracy of policy revision field. The policy revision field was bumped
  after policy for an endpoint was recalculated. The policy revision field is
  now bumped *after* complete synchronization with the datapath has occurred
  (1196_)
* Fixed graceful connection closure where final ACK after FIN+ACK was dropped
  (1186_)
* Fixed several bugs in endpoint restore functionality where endpoints were not
  correctly recovered after agent restart (1140_, 1242_, 1330_, 1338_)
* Fixed unnecessary consumer map deletion attempt which resulted in confusion
  due to warning log messages (1206_)
* Fixed stateful connection recognition of reply|related packets from an
  endpoint to the host. This resulted in reply packets getting dropped if the
  path from endpoint to host was restricted by policy but a connection from
  the host to the endpoint was permitted (1211_)
* Fixed debian packages build process (1153_)
* Fixed a typo in the getting started guide examples section (1213_)
* Fixed Kubernetes CI test to use locally built container image (1188_)
* Fixed logic which picks up Kubernetes log files on failed CI testruns (1169_)
* Agent now fails during bootup if kvstore cannot be reached (1266_)
* Fixed the L7 redirection logic to only report the new PolicyRevision after
  the proxy has started listening on the port. This resolves a race condition
  when deploying both policy and workload at the same time and the proxy is not
  up yet. (1286_)
* Fixed a bug in cilium monitor memory allocation with regard to handling data
  from the perf ring buffer (1304_)
* Correctly ignore policy resources with an empty ruleset (1296_, 1297_)
* Ignore the controller-revision-hash label to derive security identity (1320_)
* Removed `ip:` field name for CIDR policy rules, CIDR rules are now a slice of
  strings describing prefixes (1322_)
* Ignore Kubernetes annotations done by cilium which show up as labels on the
  container when deriving security identity (1338_)
* Increased the `ReadTimeout` of the HTTP proxy to 120 seconds (1349_)
* Fixed use of node address when running with IPv4 disabled (1260_)
* Several fixes around when an endpoint should go into policy enforcement for
  Kubernetes and non-Kubernetes environments (1328_)
* When creating the Kubernetes client, wait for Kubernetes cluster to be in
  ready state (1350_)
* Fixed drop notifications to include as much metadata as possible (1427_, 1444_)
* Fixed a bug where the compilation of the base programs and writing of header
  files could occur in parallel with compilation of programs for endpoints which
  could lead to temporary compilation errors (1440_)
* Fail gracefully when configuring more than the maximum supported L4 ports in
  the policy (1406_)
* Fixed a bug where not all policy rules were JSON validated before sending it
  to the agent (1406_)
* Fixed a bug in the SHA256 calculation (1454_)
* Fixed the datapath to differentiate the packets from a regular local process
  and packets originating from the proxy (previously redirected to by the
  datapath). (1459_)

Features
--------

* The monitor now supports multiple readers, you can run `cilium monitor`
  multiple times in parallel. All monitors will see all events. (1288_)
* `cilium policy trace` can now trace policy decisions based on Kubernetes pod
  names, security identities, endpoint IDs and Kubernetes YAML resources
  [Deployments, ReplicaSets, ReplicationControllers, Pods ](1124_)
* It is now possible to reach the local host on IPs which are within the
  overall cluster prefix (1394_)
* The `cilium identity get` CLI and API can now resolve global identities with
  the help of the kvstore (1313_)
* Use new probe functionality of LLVM to automatically use new BPF compare
  instructions if supported by both LLVM and the kernel (1356_)
* CIDR network policy is now visible in `cilium endpoint get` (1328_)
* Set minimum amount of compilation workers to 4 (1227_)
* Removed local backend (1235_)
* Reduced use of cgo in in bpf packages (1275_)
* Do sparse checks during BPF compilation (1175_)
* New `cilium bpf lb list` command (1317_)
* New optimized kvstore interaction code (1365_, 1397_, 1370_)
* The access log now includes a SHA hash for each reported label to allow for
  validation with the kvstore (1425_)

CI
--

* Improved CI testing infrastructure (1262_, 1207_, 1380_, 1373_, 1390_, 1385_, 1410_)
* Upgraded to kubeadm 1.7.0 (1179_)


Documentation
-------------

* Multi networking documentation (1244_)
* Documentation of the policy specification (1344_)
* New improved top level structuring of the sections (1344_)
* Example for etcd configuration file (1268_)
* Tutorial on how to use cilium monitor for troubleshooting (1451_)

Mesos
-----

* Getting started guide with L7 policy example (1301_, 1246_)

Kubernetes
----------

* Added support for Custom Resource Definition (CRD). Be aware that parallel
  usage of CRD and Third party Resources (TPR) leads to unexpected behaviour.
  See cilium.link/migrate-tpr for more details. Upgrade your
  CiliumNetworkPolicy resources to cilium.io/v2 in order to use CRD. Keep them
  at cilium.io/v1 to stay on TPR. (1169_, 1219_)
* The CiliumNetworkPolicy resource now has a status field which contains the
  status of each node enforcing the policy (1354_)
* Added RBAC rules for v1/NetworkPolicy (1188_)
* Upgraded Kubernetes example to 1.7.0 (1180_)
* Delay pod healthcheck for 180 seconds to account for endpoint restore (1271_)
* Added tolerations to DaemonSet to schedule Cilium onto master nodes as well (1426_)


Version 0.10
===============

:date: 2017-07-14
:commit: 270ed8fc16184d2558b0da2a0c626567aca1efd9

Major features
--------------

* CIDR based filter for ingress and egress (886_)
* New simplified encapsulation mode. No longer requires any network
  configuration, the IP of the VM/host is automatically used as tunnel
  endpoint across the mesh. There is no longer a need to configure any routes
  for the container prefixes in the cloud network or the underlying fabric.
  The node prefix to node ip mapping is automatically derived from the
  Kubernetes PodCIDR (1020_, 1013_, 1039_)
* When accessing external networks, outgoing traffic is automatically
  masqueraded without requiring to install a masquerade rule manually.
  This behaviour can be disabled with --masquerade=false (1020_)
* Support to handle arbitrary IPv4 cluster prefix sizes. This was previously
  required to be a /8 prefix. It can now be specified with
  --ipv4-cluster-cidr-mask-size (1094_)
* Cilium monitor has been enabled with a neat one-liner mode which is on by
  default. It is similar to tcpdump but provides high level metadata such as
  container IDs, endpoint IDs, security identities (1112_)
* The agent policy repository now includes a revision which is returned after each
  change of the policy. A new command cilium policy wait and be used to wait
  until all endpoints have been updated to enforce the new policy revision
  (1115_)
* ``cilium endpoint get`` now supports ``get -l <set of labels>`` and ``get
  <endpointID | pod-name:namespace:k8s-pod | container-name:name>`` (1139_)
* Improve label source concept. Users can now match the source of a
  particular label (e.g. k8s:app=foo, container:app=foo) or match on any
  source (e.g. app=foo, any:app=foo) (905_)

Documentation
-------------

* CoreOS installation guide

Mesos
-----

* Add support for CNI 0.2.x spec (1036_)
* Initial support for Mesos labels (1126_)

Kubernetes
----------

* Drop support for extensions/v1beta1/NetworkPolicy and support
  networking.k8s.io/v1/NetworkPolicy (1150_)
* Allow fine grained inter namespace policy control. It is now possible to
  specify policy rules which allow individual pods from another namespace to
  access a pod (1103_)
* The CiliumNetworkPolicy ThirdPartyResource now supports carrying a list of
  rules to update atomically (1055_)
* The example DaemonSet now schedules Cilium pods onto nodes which are not
  ready to allow deploying Cilium on a cluster with a non functional CNI
  configuration. The Cilium pod will automatically configure CNI properly.
  (1075_)
* Automatically derive node address prefix from Kubernetes (PodCIDR) (1026_)
* Automatically install CNI loopback driver if required (860_)
* Do not overwrite existing 10-cilium.conf CNI configuration if it already
  exists (871_)
* Full RBAC support (873_, 875_)
* Correctly implement ClusterIP portion of k8s service types LoadBalancer and
  NodePort (1098_)
* The cilium and consul pod in the example DaemonSet now have health checks
  (925_, 938_)
* Correctly ignore headless services without a warning in the log (932_)
* Derive node-name automatically (1090_)
* Labels are now attached to endpoints instead of containers. This will allow
  to support labels attached to things other than containers (1121_)

CI
--

* Added Kubernetes getting started guide to CI test suite (894_)
* L7 stress tests (1108_)
* Automatically verify links documentation (896_)
* Kubernetes multi node testing environment (980_)
* Massively reduced build&test time (982_)
* Gather logfiles on failure (1017_, 1045_)
* Guarantee isolation in between VMs for separate PRs CI runs (1075_)

More features
-------------

* Cilium load balancer can now encapsulate packets and carry the service-ID in
  the packet (912_)
* The filtering mechanism which decides which labels should be used for
  security identity determination now supports regular expressions (918_)
* Extended logging information of L7 requests in proxy (964_, 973_, 991_,
  998_, 1002_)
* Improved rendering of cilium service list (934_)
* Upgraded to etcd 3.2.1 (959_)
* More factoring out of agent into separate packages (975_, 985_)
* Reduced cgo usage (1003_, 1018_)
* Improve logging of BPF generation errors (990_)
* cilium policy trace now supports verbose output (1080_)
* Include ``bpf-map`` tool in cilium container image (1088_)
* Carrying of security identities across the proxy (1114_)

Fixes
-------

* Fixed use of IPv6 node addresses which are already configured on the
  systme (#819)
* Enforce minimal etcd and consul versions (911_)
* Connection tracking entries now get automatically  cleaned if new policy no
  longer allows the connection (794_)
* Report status message in ``cilium status`` if a component is in error state
  (874_)
* Create L7 access log file if it does not exist (881_)
* Report kernel/clang versions on compilation issues (888_)
* Check that cilium binary is installed when agent starts up (892_)
* Fix checksum error in service + proxy redirection (1011_)
* Stricter connection tracking connection creation criteria (1027_)
* Cleanup of leftover veth if endpoint setup failed midway (1122_)
* Remove stale ids also from policy map (1135_)

Version 0.09
===============

:date: 2017-05-23
:commit: 1bfb6303f6fba25c4d22fbe4b7c35450055296b6

Features
--------

- Core

  - New simplified policy language (670_)
  - Option to choose between a global (default) and per endpoint connection tracking table (659_)
  - Parallel endpoint BPF program & policy builds (424_, 587_)
  - Fluentd logging integration (758_)
  - IPv6 proxy redirection support (818_)
  - Transparent ingress proxy redirection (773_)
  - Consider all labels for identity except dynamic k8s state labels (849_)
  - Reduced size of cilium binary from 27M to 17M (554_)
  - Add filtering support to ``cilium monitor`` (673_)
  - Allow rule now supports matching multiple labels (638_)
  - Separate runtime state and template directory for security reasons (537_)
  - Ability to specify L4 destination port in policy trace (650_)
  - Improved log readability (499_)
  - Optimized connection tracking map updates per packet (829_)
  - New ``--kvstore`` and ``--kvstore-opt`` flag (Replaces ``--consul, --etcd, --local`` flags)  (767_)
  - Configurable clang path (620_)
  - Updated CNI to 5.2.0 (529_)
  - Updated Golang to 1.8.3 (853_)
  - Bump k8s client to v3.0.0-beta.0 (646_)

- Kubernetes

  - Support L4 filtering with v1beta1.NetworkPolicyPort (638_)
  - ThirdPartyResources support for L3-L7 policies (795_, 814_)
  - Per pod policy enablement based on policy selection (815_)
  - Support for full LabelSelector (753_)
  - Option to always allow localhost to reach endpoints (auto on with k8s) (754_)
  - RBAC ClusterRole, ServiceAccount and bindings (850_)
  - Scripts to install and uninstall CNI configuration (745_)

- Documentation

  - Getting started guide for minikube (734_)
  - Kubernetes installation guide using DaemonSet (800_)
  - Rework of the administrator guide (850_)
  - New simplified vagrant box to get started (549_)
  - API reference documentation (512_)
  - BPF & XDP documentation (546_)

Fixes
------

- Core

  - Endpoints are displayed in ascending order (474_)
  - Warn about insufficient kernel version when starting up (505_)
  - Work around Docker <17.05 disabling IPv6 in init namespace (544_)
  - Fixed a connection tracking expiry a bug (828_)
  - Only generate human readable ASM output if DEBUG is enabled (599_)
  - Switch from package syscall to x/sys/unix (588_)
  - Remove tail call map on endpoint leave (736_)
  - Fixed ICMPv6 to service IP with LB back to own IP (764_)
  - Respond to ARP also when temporary drop all policy is applied. (724_)
  - Fixed several BPF resource leakages (634_, 684_, 732_)
  - Fixed several L7 parser policy bugs (512_)
  - Fixed tc call to specify prio and handle for replace (611_)
  - Fixed off by one in consul connection retries (610_)
  - Fixed lots of documentation typos
  - Fix addition/deletion order when updating endpoint labels (647_)
  - Graceful exit if lack of privileges (694_)
  - use same tuple struct for both global and local CT (822_)
  - bpf/init.sh: More robust deletion of routes. (719_)
  - lxc endianess & src validation fixes (747_)

- Kubernetes

  - Correctly handle k8s NetworkPolicy matchLabels (638_)
  - Allow all sources if []NetworkPolicyPeer is empty or missing (638_)
  - Fix if k8s API server returns nil label (567_)
  - Do not error out if k8s node does not have a CIDR assigned (628_)
  - Only attempt to resolve CIDR from k8s API if client is available (608_)
  - Log error if invalid k8s NetworkPolicy objects are received (617_)


.. _424: https://github.com/cilium/cilium/pull/424
.. _474: https://github.com/cilium/cilium/pull/474
.. _499: https://github.com/cilium/cilium/pull/499
.. _505: https://github.com/cilium/cilium/pull/505
.. _512: https://github.com/cilium/cilium/pull/512
.. _529: https://github.com/cilium/cilium/pull/529
.. _537: https://github.com/cilium/cilium/pull/537
.. _544: https://github.com/cilium/cilium/pull/544
.. _546: https://github.com/cilium/cilium/pull/546
.. _549: https://github.com/cilium/cilium/pull/549
.. _554: https://github.com/cilium/cilium/pull/554
.. _567: https://github.com/cilium/cilium/pull/567
.. _587: https://github.com/cilium/cilium/pull/587
.. _588: https://github.com/cilium/cilium/pull/588
.. _599: https://github.com/cilium/cilium/pull/599
.. _608: https://github.com/cilium/cilium/pull/608
.. _610: https://github.com/cilium/cilium/pull/610
.. _611: https://github.com/cilium/cilium/pull/611
.. _617: https://github.com/cilium/cilium/pull/617
.. _620: https://github.com/cilium/cilium/pull/620
.. _628: https://github.com/cilium/cilium/pull/628
.. _634: https://github.com/cilium/cilium/pull/634
.. _638: https://github.com/cilium/cilium/pull/638
.. _646: https://github.com/cilium/cilium/pull/646
.. _647: https://github.com/cilium/cilium/pull/647
.. _650: https://github.com/cilium/cilium/pull/650
.. _659: https://github.com/cilium/cilium/pull/659
.. _670: https://github.com/cilium/cilium/pull/670
.. _673: https://github.com/cilium/cilium/pull/673
.. _684: https://github.com/cilium/cilium/pull/684
.. _694: https://github.com/cilium/cilium/pull/694
.. _719: https://github.com/cilium/cilium/pull/719
.. _724: https://github.com/cilium/cilium/pull/724
.. _732: https://github.com/cilium/cilium/pull/732
.. _734: https://github.com/cilium/cilium/pull/734
.. _736: https://github.com/cilium/cilium/pull/736
.. _745: https://github.com/cilium/cilium/pull/745
.. _747: https://github.com/cilium/cilium/pull/747
.. _753: https://github.com/cilium/cilium/pull/753
.. _754: https://github.com/cilium/cilium/pull/754
.. _758: https://github.com/cilium/cilium/pull/758
.. _764: https://github.com/cilium/cilium/pull/764
.. _767: https://github.com/cilium/cilium/pull/767
.. _773: https://github.com/cilium/cilium/pull/773
.. _794: https://github.com/cilium/cilium/pull/794
.. _795: https://github.com/cilium/cilium/pull/795
.. _800: https://github.com/cilium/cilium/pull/800
.. _814: https://github.com/cilium/cilium/pull/814
.. _815: https://github.com/cilium/cilium/pull/815
.. _818: https://github.com/cilium/cilium/pull/818
.. _822: https://github.com/cilium/cilium/pull/822
.. _828: https://github.com/cilium/cilium/pull/828
.. _829: https://github.com/cilium/cilium/pull/829
.. _849: https://github.com/cilium/cilium/pull/849
.. _850: https://github.com/cilium/cilium/pull/850
.. _853: https://github.com/cilium/cilium/pull/853
.. _860: https://github.com/cilium/cilium/pull/860
.. _871: https://github.com/cilium/cilium/pull/871
.. _873: https://github.com/cilium/cilium/pull/873
.. _874: https://github.com/cilium/cilium/pull/874
.. _875: https://github.com/cilium/cilium/pull/875
.. _881: https://github.com/cilium/cilium/pull/881
.. _886: https://github.com/cilium/cilium/pull/886
.. _888: https://github.com/cilium/cilium/pull/888
.. _892: https://github.com/cilium/cilium/pull/892
.. _894: https://github.com/cilium/cilium/pull/894
.. _896: https://github.com/cilium/cilium/pull/896
.. _905: https://github.com/cilium/cilium/pull/905
.. _911: https://github.com/cilium/cilium/pull/911
.. _912: https://github.com/cilium/cilium/pull/912
.. _918: https://github.com/cilium/cilium/pull/918
.. _925: https://github.com/cilium/cilium/pull/925
.. _932: https://github.com/cilium/cilium/pull/932
.. _934: https://github.com/cilium/cilium/pull/934
.. _938: https://github.com/cilium/cilium/pull/938
.. _959: https://github.com/cilium/cilium/pull/959
.. _964: https://github.com/cilium/cilium/pull/964
.. _973: https://github.com/cilium/cilium/pull/973
.. _975: https://github.com/cilium/cilium/pull/975
.. _980: https://github.com/cilium/cilium/pull/980
.. _982: https://github.com/cilium/cilium/pull/982
.. _985: https://github.com/cilium/cilium/pull/985
.. _990: https://github.com/cilium/cilium/pull/990
.. _991: https://github.com/cilium/cilium/pull/991
.. _998: https://github.com/cilium/cilium/pull/998
.. _1002: https://github.com/cilium/cilium/pull/1002
.. _1003: https://github.com/cilium/cilium/pull/1003
.. _1011: https://github.com/cilium/cilium/pull/1011
.. _1013: https://github.com/cilium/cilium/pull/1013
.. _1017: https://github.com/cilium/cilium/pull/1017
.. _1018: https://github.com/cilium/cilium/pull/1018
.. _1020: https://github.com/cilium/cilium/pull/1020
.. _1026: https://github.com/cilium/cilium/pull/1026
.. _1027: https://github.com/cilium/cilium/pull/1027
.. _1036: https://github.com/cilium/cilium/pull/1036
.. _1039: https://github.com/cilium/cilium/pull/1039
.. _1045: https://github.com/cilium/cilium/pull/1045
.. _1055: https://github.com/cilium/cilium/pull/1055
.. _1075: https://github.com/cilium/cilium/pull/1075
.. _1080: https://github.com/cilium/cilium/pull/1080
.. _1088: https://github.com/cilium/cilium/pull/1088
.. _1090: https://github.com/cilium/cilium/pull/1090
.. _1094: https://github.com/cilium/cilium/pull/1094
.. _1098: https://github.com/cilium/cilium/pull/1098
.. _1103: https://github.com/cilium/cilium/pull/1103
.. _1108: https://github.com/cilium/cilium/pull/1108
.. _1112: https://github.com/cilium/cilium/pull/1112
.. _1114: https://github.com/cilium/cilium/pull/1114
.. _1115: https://github.com/cilium/cilium/pull/1115
.. _1121: https://github.com/cilium/cilium/pull/1121
.. _1122: https://github.com/cilium/cilium/pull/1122
.. _1124: https://github.com/cilium/cilium/pull/1124
.. _1126: https://github.com/cilium/cilium/pull/1126
.. _1135: https://github.com/cilium/cilium/pull/1135
.. _1139: https://github.com/cilium/cilium/pull/1139
.. _1140: https://github.com/cilium/cilium/pull/1140
.. _1150: https://github.com/cilium/cilium/pull/1150
.. _1153: https://github.com/cilium/cilium/pull/1153
.. _1169: https://github.com/cilium/cilium/pull/1169
.. _1175: https://github.com/cilium/cilium/pull/1175
.. _1179: https://github.com/cilium/cilium/pull/1179
.. _1180: https://github.com/cilium/cilium/pull/1180
.. _1182: https://github.com/cilium/cilium/pull/1182
.. _1186: https://github.com/cilium/cilium/pull/1186
.. _1188: https://github.com/cilium/cilium/pull/1188
.. _1195: https://github.com/cilium/cilium/pull/1195
.. _1196: https://github.com/cilium/cilium/pull/1196
.. _1206: https://github.com/cilium/cilium/pull/1206
.. _1207: https://github.com/cilium/cilium/pull/1207
.. _1211: https://github.com/cilium/cilium/pull/1211
.. _1213: https://github.com/cilium/cilium/pull/1213
.. _1219: https://github.com/cilium/cilium/pull/1219
.. _1227: https://github.com/cilium/cilium/pull/1227
.. _1235: https://github.com/cilium/cilium/pull/1235
.. _1242: https://github.com/cilium/cilium/pull/1242
.. _1244: https://github.com/cilium/cilium/pull/1244
.. _1246: https://github.com/cilium/cilium/pull/1246
.. _1260: https://github.com/cilium/cilium/pull/1260
.. _1262: https://github.com/cilium/cilium/pull/1262
.. _1266: https://github.com/cilium/cilium/pull/1266
.. _1268: https://github.com/cilium/cilium/pull/1268
.. _1271: https://github.com/cilium/cilium/pull/1271
.. _1275: https://github.com/cilium/cilium/pull/1275
.. _1286: https://github.com/cilium/cilium/pull/1286
.. _1288: https://github.com/cilium/cilium/pull/1288
.. _1296: https://github.com/cilium/cilium/pull/1296
.. _1297: https://github.com/cilium/cilium/pull/1297
.. _1301: https://github.com/cilium/cilium/pull/1301
.. _1304: https://github.com/cilium/cilium/pull/1304
.. _1313: https://github.com/cilium/cilium/pull/1313
.. _1317: https://github.com/cilium/cilium/pull/1317
.. _1320: https://github.com/cilium/cilium/pull/1320
.. _1322: https://github.com/cilium/cilium/pull/1322
.. _1328: https://github.com/cilium/cilium/pull/1328
.. _1330: https://github.com/cilium/cilium/pull/1330
.. _1338: https://github.com/cilium/cilium/pull/1338
.. _1344: https://github.com/cilium/cilium/pull/1344
.. _1349: https://github.com/cilium/cilium/pull/1349
.. _1350: https://github.com/cilium/cilium/pull/1350
.. _1354: https://github.com/cilium/cilium/pull/1354
.. _1356: https://github.com/cilium/cilium/pull/1356
.. _1365: https://github.com/cilium/cilium/pull/1365
.. _1370: https://github.com/cilium/cilium/pull/1370
.. _1373: https://github.com/cilium/cilium/pull/1373
.. _1380: https://github.com/cilium/cilium/pull/1380
.. _1385: https://github.com/cilium/cilium/pull/1385
.. _1390: https://github.com/cilium/cilium/pull/1390
.. _1394: https://github.com/cilium/cilium/pull/1394
.. _1397: https://github.com/cilium/cilium/pull/1397
.. _1406: https://github.com/cilium/cilium/pull/1406
.. _1410: https://github.com/cilium/cilium/pull/1410
.. _1425: https://github.com/cilium/cilium/pull/1425
.. _1426: https://github.com/cilium/cilium/pull/1426
.. _1427: https://github.com/cilium/cilium/pull/1427
.. _1440: https://github.com/cilium/cilium/pull/1440
.. _1444: https://github.com/cilium/cilium/pull/1444
.. _1451: https://github.com/cilium/cilium/pull/1451
.. _1219: https://github.com/cilium/cilium/pull/1219
.. _1180: https://github.com/cilium/cilium/pull/1180
.. _1271: https://github.com/cilium/cilium/pull/1271
.. _1179: https://github.com/cilium/cilium/pull/1179
.. _1632: https://github.com/cilium/cilium/pull/1632
.. _1624: https://github.com/cilium/cilium/pull/1624
.. _1455: https://github.com/cilium/cilium/pull/1455
.. _1441: https://github.com/cilium/cilium/pull/1441
.. _1435: https://github.com/cilium/cilium/pull/1435
.. _1464: https://github.com/cilium/cilium/pull/1464
.. _1440: https://github.com/cilium/cilium/pull/1440
.. _1468: https://github.com/cilium/cilium/pull/1468
.. _1454: https://github.com/cilium/cilium/pull/1454
.. _1459: https://github.com/cilium/cilium/pull/1459
.. _1573: https://github.com/cilium/cilium/pull/1573
.. _1599: https://github.com/cilium/cilium/pull/1599
.. _1496: https://github.com/cilium/cilium/pull/1496
.. _1217: https://github.com/cilium/cilium/pull/1217
.. _1064: https://github.com/cilium/cilium/pull/1064
.. _789: https://github.com/cilium/cilium/pull/789
.. _1379: https://github.com/cilium/cilium/pull/1379
.. _1473: https://github.com/cilium/cilium/pull/1473
.. _1587: https://github.com/cilium/cilium/pull/1587
.. _1492: https://github.com/cilium/cilium/pull/1492
.. _1440: https://github.com/cilium/cilium/pull/1440
.. _1474: https://github.com/cilium/cilium/pull/1474
.. _1508: https://github.com/cilium/cilium/pull/1508
.. _1352: https://github.com/cilium/cilium/pull/1352
.. _1505: https://github.com/cilium/cilium/pull/1505
.. _1548: https://github.com/cilium/cilium/pull/1548
.. _1513: https://github.com/cilium/cilium/pull/1513
.. _1511: https://github.com/cilium/cilium/pull/1511
.. _1532: https://github.com/cilium/cilium/pull/1532
.. _1531: https://github.com/cilium/cilium/pull/1531
.. _1545: https://github.com/cilium/cilium/pull/1545
.. _1555: https://github.com/cilium/cilium/pull/1555
.. _1575: https://github.com/cilium/cilium/pull/1575
.. _1614: https://github.com/cilium/cilium/pull/1614
.. _1558: https://github.com/cilium/cilium/pull/1558
.. _1569: https://github.com/cilium/cilium/pull/1569
.. _1570: https://github.com/cilium/cilium/pull/1570
.. _1596: https://github.com/cilium/cilium/pull/1596
.. _1599: https://github.com/cilium/cilium/pull/1599
.. _1507: https://github.com/cilium/cilium/pull/1507
.. _1605: https://github.com/cilium/cilium/pull/1605
.. _1623: https://github.com/cilium/cilium/pull/1623
.. _1622: https://github.com/cilium/cilium/pull/1622
.. _1642: https://github.com/cilium/cilium/pull/1642
.. _1677: https://github.com/cilium/cilium/pull/1677
.. _1634: https://github.com/cilium/cilium/pull/1634
.. _1484: https://github.com/cilium/cilium/pull/1484
.. _1651: https://github.com/cilium/cilium/pull/1651
.. _1665: https://github.com/cilium/cilium/pull/1665
.. _1675: https://github.com/cilium/cilium/pull/1675
.. _1550: https://github.com/cilium/cilium/pull/1550
.. _1615: https://github.com/cilium/cilium/pull/1615
.. _1638: https://github.com/cilium/cilium/pull/1638
.. _1661: https://github.com/cilium/cilium/pull/1661
.. _1479: https://github.com/cilium/cilium/pull/1479
.. _1599: https://github.com/cilium/cilium/pull/1599
.. _1496: https://github.com/cilium/cilium/pull/1496
.. _1217: https://github.com/cilium/cilium/pull/1217
.. _1064: https://github.com/cilium/cilium/pull/1064
.. _789: https://github.com/cilium/cilium/pull/789
.. _1597: https://github.com/cilium/cilium/pull/1597
.. _1643: https://github.com/cilium/cilium/pull/1643
.. _1528: https://github.com/cilium/cilium/pull/1528
.. _1464: https://github.com/cilium/cilium/pull/1464
.. _1464: https://github.com/cilium/cilium/pull/1464
.. _1462: https://github.com/cilium/cilium/pull/1462
.. _1568: https://github.com/cilium/cilium/pull/1568
.. _1466: https://github.com/cilium/cilium/pull/1466
.. _1490: https://github.com/cilium/cilium/pull/1490
.. _1512: https://github.com/cilium/cilium/pull/1512
.. _1683: https://github.com/cilium/cilium/pull/1683
.. _1381: https://github.com/cilium/cilium/pull/1381
.. _1683: https://github.com/cilium/cilium/pull/1683
.. _1663: https://github.com/cilium/cilium/pull/1663
.. _1574: https://github.com/cilium/cilium/pull/1574
.. _1563: https://github.com/cilium/cilium/pull/1563
.. _1468: https://github.com/cilium/cilium/pull/1468
.. _1464: https://github.com/cilium/cilium/pull/1464
.. _1663: https://github.com/cilium/cilium/pull/1663
.. _1548: https://github.com/cilium/cilium/pull/1548
.. _1585: https://github.com/cilium/cilium/pull/1585
.. _1601: https://github.com/cilium/cilium/pull/1601
.. _1612: https://github.com/cilium/cilium/pull/1612
.. _1628: https://github.com/cilium/cilium/pull/1628
.. _1632: https://github.com/cilium/cilium/pull/1632
.. _1624: https://github.com/cilium/cilium/pull/1624
.. _1455: https://github.com/cilium/cilium/pull/1455
.. _1441: https://github.com/cilium/cilium/pull/1441
.. _1435: https://github.com/cilium/cilium/pull/1435
.. _1542: https://github.com/cilium/cilium/pull/1542
.. _1648: https://github.com/cilium/cilium/pull/1648
.. _1646: https://github.com/cilium/cilium/pull/1646
.. _1519: https://github.com/cilium/cilium/pull/1519
.. _1519: https://github.com/cilium/cilium/pull/1519
.. _1535: https://github.com/cilium/cilium/pull/1535
.. _1573: https://github.com/cilium/cilium/pull/1573
.. _1666: https://github.com/cilium/cilium/pull/1666
.. _1777: https://github.com/cilium/cilium/pull/1777
.. _1691: https://github.com/cilium/cilium/pull/1691
.. _1821: https://github.com/cilium/cilium/pull/1821
.. _1858: https://github.com/cilium/cilium/pull/1858
.. _1847: https://github.com/cilium/cilium/pull/1847
.. _1757: https://github.com/cilium/cilium/pull/1757
.. _1767: https://github.com/cilium/cilium/pull/1767
.. _1817: https://github.com/cilium/cilium/pull/1817
.. _1764: https://github.com/cilium/cilium/pull/1764
.. _1713: https://github.com/cilium/cilium/pull/1713
.. _1816: https://github.com/cilium/cilium/pull/1816
.. _1837: https://github.com/cilium/cilium/pull/1837
.. _1776: https://github.com/cilium/cilium/pull/1776
.. _1793: https://github.com/cilium/cilium/pull/1793
.. _1810: https://github.com/cilium/cilium/pull/1810
.. _1788: https://github.com/cilium/cilium/pull/1788
.. _1848: https://github.com/cilium/cilium/pull/1848
.. _1865: https://github.com/cilium/cilium/pull/1865
.. _1733: https://github.com/cilium/cilium/pull/1733
.. _1801: https://github.com/cilium/cilium/pull/1801
.. _1828: https://github.com/cilium/cilium/pull/1828
.. _1836: https://github.com/cilium/cilium/pull/1836
.. _1826: https://github.com/cilium/cilium/pull/1826
.. _1833: https://github.com/cilium/cilium/pull/1833
.. _1834: https://github.com/cilium/cilium/pull/1834
.. _1827: https://github.com/cilium/cilium/pull/1827
.. _1829: https://github.com/cilium/cilium/pull/1829
.. _1832: https://github.com/cilium/cilium/pull/1832
.. _1835: https://github.com/cilium/cilium/pull/1835
.. _2452: https://github.com/cilium/cilium/pull/2452
.. _2348: https://github.com/cilium/cilium/pull/2348
.. _2521: https://github.com/cilium/cilium/pull/2521
.. _2504: https://github.com/cilium/cilium/pull/2504
.. _2499: https://github.com/cilium/cilium/pull/2499
.. _2490: https://github.com/cilium/cilium/pull/2490
.. _2489: https://github.com/cilium/cilium/pull/2489
.. _2453: https://github.com/cilium/cilium/pull/2453
.. _2436: https://github.com/cilium/cilium/pull/2436
.. _2432: https://github.com/cilium/cilium/pull/2432
.. _2404: https://github.com/cilium/cilium/pull/2404
.. _2393: https://github.com/cilium/cilium/pull/2393
.. _2386: https://github.com/cilium/cilium/pull/2386
.. _2377: https://github.com/cilium/cilium/pull/2377
.. _2359: https://github.com/cilium/cilium/pull/2359
.. _2358: https://github.com/cilium/cilium/pull/2358
.. _2356: https://github.com/cilium/cilium/pull/2356
.. _2304: https://github.com/cilium/cilium/pull/2304
.. _2254: https://github.com/cilium/cilium/pull/2254
.. _2247: https://github.com/cilium/cilium/pull/2247
.. _2246: https://github.com/cilium/cilium/pull/2246
.. _2235: https://github.com/cilium/cilium/pull/2235
.. _2512: https://github.com/cilium/cilium/pull/2512
.. _2508: https://github.com/cilium/cilium/pull/2508
.. _2502: https://github.com/cilium/cilium/pull/2502
.. _2478: https://github.com/cilium/cilium/pull/2478
.. _2396: https://github.com/cilium/cilium/pull/2396
.. _2382: https://github.com/cilium/cilium/pull/2382
.. _2358: https://github.com/cilium/cilium/pull/2358
.. _2355: https://github.com/cilium/cilium/pull/2355
.. _2350: https://github.com/cilium/cilium/pull/2350
.. _2340: https://github.com/cilium/cilium/pull/2340
.. _2325: https://github.com/cilium/cilium/pull/2325
.. _2324: https://github.com/cilium/cilium/pull/2324
.. _2313: https://github.com/cilium/cilium/pull/2313
.. _2299: https://github.com/cilium/cilium/pull/2299
.. _2271: https://github.com/cilium/cilium/pull/2271
.. _2265: https://github.com/cilium/cilium/pull/2265
.. _2237: https://github.com/cilium/cilium/pull/2237
.. _2219: https://github.com/cilium/cilium/pull/2219
.. _1580: https://github.com/cilium/cilium/pull/1580
.. _2052: https://github.com/cilium/cilium/pull/2052
.. _2127: https://github.com/cilium/cilium/pull/2127
.. _2044: https://github.com/cilium/cilium/pull/2044
.. _2212: https://github.com/cilium/cilium/pull/2212
.. _2156: https://github.com/cilium/cilium/pull/2156
.. _2096: https://github.com/cilium/cilium/pull/2096
.. _1870: https://github.com/cilium/cilium/pull/1870
.. _2060: https://github.com/cilium/cilium/pull/2060
.. _1888: https://github.com/cilium/cilium/pull/1888
.. _1835: https://github.com/cilium/cilium/pull/1835
.. _1871: https://github.com/cilium/cilium/pull/1871
.. _2228: https://github.com/cilium/cilium/pull/2228
.. _2225: https://github.com/cilium/cilium/pull/2225
.. _2181: https://github.com/cilium/cilium/pull/2181
.. _2179: https://github.com/cilium/cilium/pull/2179
.. _2162: https://github.com/cilium/cilium/pull/2162
.. _2137: https://github.com/cilium/cilium/pull/2137
.. _2136: https://github.com/cilium/cilium/pull/2136
.. _2129: https://github.com/cilium/cilium/pull/2129
.. _2123: https://github.com/cilium/cilium/pull/2123
.. _2115: https://github.com/cilium/cilium/pull/2115
.. _2112: https://github.com/cilium/cilium/pull/2112
.. _2108: https://github.com/cilium/cilium/pull/2108
.. _2090: https://github.com/cilium/cilium/pull/2090
.. _2024: https://github.com/cilium/cilium/pull/2024
.. _2022: https://github.com/cilium/cilium/pull/2022
.. _2014: https://github.com/cilium/cilium/pull/2014
.. _1987: https://github.com/cilium/cilium/pull/1987
.. _1986: https://github.com/cilium/cilium/pull/1986
.. _1979: https://github.com/cilium/cilium/pull/1979
.. _1949: https://github.com/cilium/cilium/pull/1949
.. _1939: https://github.com/cilium/cilium/pull/1939
.. _1924: https://github.com/cilium/cilium/pull/1924
.. _2210: https://github.com/cilium/cilium/pull/2210
.. _1899: https://github.com/cilium/cilium/pull/1899
.. _2223: https://github.com/cilium/cilium/pull/2223
.. _1995: https://github.com/cilium/cilium/pull/1995
.. _2192: https://github.com/cilium/cilium/pull/2192
.. _2116: https://github.com/cilium/cilium/pull/2116
.. _2099: https://github.com/cilium/cilium/pull/2099
.. _2079: https://github.com/cilium/cilium/pull/2079
.. _2078: https://github.com/cilium/cilium/pull/2078
.. _2048: https://github.com/cilium/cilium/pull/2048
.. _2037: https://github.com/cilium/cilium/pull/2037
.. _2007: https://github.com/cilium/cilium/pull/2007
.. _1989: https://github.com/cilium/cilium/pull/1989
.. _1970: https://github.com/cilium/cilium/pull/1970
.. _1951: https://github.com/cilium/cilium/pull/1951
.. _1917: https://github.com/cilium/cilium/pull/1917
.. _1898: https://github.com/cilium/cilium/pull/1898
.. _1893: https://github.com/cilium/cilium/pull/1893
.. _1888: https://github.com/cilium/cilium/pull/1888
.. _1854: https://github.com/cilium/cilium/pull/1854
.. _1678: https://github.com/cilium/cilium/pull/1678
.. _1865: https://github.com/cilium/cilium/pull/1865
.. _1733: https://github.com/cilium/cilium/pull/1733
.. _2720: https://github.com/cilium/cilium/pull/2720
.. _2708: https://github.com/cilium/cilium/pull/2708
.. _2667: https://github.com/cilium/cilium/pull/2667
.. _2625: https://github.com/cilium/cilium/pull/2625
.. _2597: https://github.com/cilium/cilium/pull/2597
.. _2315: https://github.com/cilium/cilium/pull/2315
.. _2823: https://github.com/cilium/cilium/pull/2823
.. _2813: https://github.com/cilium/cilium/pull/2813
.. _2807: https://github.com/cilium/cilium/pull/2807
.. _2789: https://github.com/cilium/cilium/pull/2789
.. _2735: https://github.com/cilium/cilium/pull/2735
.. _2719: https://github.com/cilium/cilium/pull/2719
.. _2718: https://github.com/cilium/cilium/pull/2718
.. _2699: https://github.com/cilium/cilium/pull/2699
.. _2684: https://github.com/cilium/cilium/pull/2684
.. _2649: https://github.com/cilium/cilium/pull/2649
.. _2637: https://github.com/cilium/cilium/pull/2637
.. _2633: https://github.com/cilium/cilium/pull/2633
.. _2619: https://github.com/cilium/cilium/pull/2619
.. _2614: https://github.com/cilium/cilium/pull/2614
.. _2607: https://github.com/cilium/cilium/pull/2607
.. _2595: https://github.com/cilium/cilium/pull/2595
.. _2953: https://github.com/cilium/cilium/pull/2953
.. _2937: https://github.com/cilium/cilium/pull/2937
.. _2922: https://github.com/cilium/cilium/pull/2922
.. _2912: https://github.com/cilium/cilium/pull/2912
.. _2887: https://github.com/cilium/cilium/pull/2887
.. _2881: https://github.com/cilium/cilium/pull/2881
.. _2855: https://github.com/cilium/cilium/pull/2855
.. _2814: https://github.com/cilium/cilium/pull/2814
.. _2944: https://github.com/cilium/cilium/pull/2944
.. _2933: https://github.com/cilium/cilium/pull/2933
.. _2929: https://github.com/cilium/cilium/pull/2929
.. _2926: https://github.com/cilium/cilium/pull/2926
.. _2894: https://github.com/cilium/cilium/pull/2894
.. _2867: https://github.com/cilium/cilium/pull/2867
.. _2865: https://github.com/cilium/cilium/pull/2865
.. _2858: https://github.com/cilium/cilium/pull/2858
.. _2852: https://github.com/cilium/cilium/pull/2852
.. _2821: https://github.com/cilium/cilium/pull/2821
.. _2806: https://github.com/cilium/cilium/pull/2806
.. _2991: https://github.com/cilium/cilium/pull/2991
.. _2970: https://github.com/cilium/cilium/pull/2970
.. _2918: https://github.com/cilium/cilium/pull/2918
.. _3052: https://github.com/cilium/cilium/pull/3052
.. _3049: https://github.com/cilium/cilium/pull/3049
.. _3042: https://github.com/cilium/cilium/pull/3042
.. _3040: https://github.com/cilium/cilium/pull/3040
.. _3029: https://github.com/cilium/cilium/pull/3029
.. _3020: https://github.com/cilium/cilium/pull/3020
.. _3018: https://github.com/cilium/cilium/pull/3018
.. _3013: https://github.com/cilium/cilium/pull/3013
.. _3047: https://github.com/cilium/cilium/pull/3047
.. _3036: https://github.com/cilium/cilium/pull/3036
.. _3034: https://github.com/cilium/cilium/pull/3034
.. _3054: https://github.com/cilium/cilium/pull/3054
.. _3102: https://github.com/cilium/cilium/pull/3102
.. _2997: https://github.com/cilium/cilium/pull/2997
.. _2878: https://github.com/cilium/cilium/pull/2878
.. _2772: https://github.com/cilium/cilium/pull/2772
.. _3193: https://github.com/cilium/cilium/pull/3193
.. _3188: https://github.com/cilium/cilium/pull/3188
.. _3181: https://github.com/cilium/cilium/pull/3181
.. _3156: https://github.com/cilium/cilium/pull/3156
.. _3153: https://github.com/cilium/cilium/pull/3153
.. _3128: https://github.com/cilium/cilium/pull/3128
.. _3104: https://github.com/cilium/cilium/pull/3104
.. _3103: https://github.com/cilium/cilium/pull/3103
.. _3094: https://github.com/cilium/cilium/pull/3094
.. _3069: https://github.com/cilium/cilium/pull/3069
.. _2992: https://github.com/cilium/cilium/pull/2992
.. _2966: https://github.com/cilium/cilium/pull/2966
.. _3167: https://github.com/cilium/cilium/pull/3167
.. _3151: https://github.com/cilium/cilium/pull/3151
.. _3120: https://github.com/cilium/cilium/pull/3120
.. _3119: https://github.com/cilium/cilium/pull/3119
.. _3096: https://github.com/cilium/cilium/pull/3096
.. _3015: https://github.com/cilium/cilium/pull/3015
.. _3190: https://github.com/cilium/cilium/pull/3190
.. _3430: https://github.com/cilium/cilium/pull/3430
.. _3372: https://github.com/cilium/cilium/pull/3372
.. _3451: https://github.com/cilium/cilium/pull/3451
.. _3446: https://github.com/cilium/cilium/pull/3446
.. _3406: https://github.com/cilium/cilium/pull/3406
.. _3405: https://github.com/cilium/cilium/pull/3405
.. _3386: https://github.com/cilium/cilium/pull/3386
.. _3378: https://github.com/cilium/cilium/pull/3378
.. _3375: https://github.com/cilium/cilium/pull/3375
.. _3366: https://github.com/cilium/cilium/pull/3366
.. _3348: https://github.com/cilium/cilium/pull/3348
.. _3341: https://github.com/cilium/cilium/pull/3341
.. _3321: https://github.com/cilium/cilium/pull/3321
.. _3308: https://github.com/cilium/cilium/pull/3308
.. _3275: https://github.com/cilium/cilium/pull/3275
.. _3271: https://github.com/cilium/cilium/pull/3271
.. _3265: https://github.com/cilium/cilium/pull/3265
.. _3256: https://github.com/cilium/cilium/pull/3256
.. _3246: https://github.com/cilium/cilium/pull/3246
.. _3228: https://github.com/cilium/cilium/pull/3228
.. _3221: https://github.com/cilium/cilium/pull/3221
.. _3216: https://github.com/cilium/cilium/pull/3216
.. _3205: https://github.com/cilium/cilium/pull/3205
.. _3199: https://github.com/cilium/cilium/pull/3199
.. _3186: https://github.com/cilium/cilium/pull/3186
.. _3127: https://github.com/cilium/cilium/pull/3127
.. _3448: https://github.com/cilium/cilium/pull/3448
.. _3407: https://github.com/cilium/cilium/pull/3407
.. _3391: https://github.com/cilium/cilium/pull/3391
.. _3364: https://github.com/cilium/cilium/pull/3364
.. _3350: https://github.com/cilium/cilium/pull/3350
.. _3320: https://github.com/cilium/cilium/pull/3320
.. _3301: https://github.com/cilium/cilium/pull/3301
.. _3298: https://github.com/cilium/cilium/pull/3298
.. _3278: https://github.com/cilium/cilium/pull/3278
.. _3274: https://github.com/cilium/cilium/pull/3274
.. _3269: https://github.com/cilium/cilium/pull/3269
.. _3267: https://github.com/cilium/cilium/pull/3267
.. _3238: https://github.com/cilium/cilium/pull/3238
.. _3234: https://github.com/cilium/cilium/pull/3234
.. _3037: https://github.com/cilium/cilium/pull/3037
