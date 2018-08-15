******
NEWS
******

1.2.0
=====

Major Changes
-------------

* Add periodic aggregation of datapath notifications (4936_, @joestringer)
* Provide cached visibility + retries of BPF maps via API (4854_, @tgraf)
* Add support for etcd-operator to ease Cilium deployment. (4826_, @aanm)
* Agent aware user-defined reserved identities (4775_, @aanm)
* Add toFQDNs rules that support DNS based egress policy (4750_, @raybejjani)
* Inter cluster connectivity (ClusterMesh) (4738_, @tgraf)
* Tunneling mode without kvstore dependency (4732_, @tgraf)
* Push nightly container image to container registry (4731_, @nebril)
* Automatically detect MTU of network (4687_, @tgraf)
* Use local service ID allocation when DSR is disabled (4664_, @tgraf)
* Allow running Cilium with kube-router for BGP routing (4547_, @tgraf)
* Add kvstore based node discovery (4270_, @tgraf)

Bugfixes Changes
----------------

* daemon: always re-add CNP when receiving an update from Kubernetes (5024_, @aanm)
* pkg/endpoint: annotate pod with the numeric representation of an identity (5019_, @aanm)
* kvstore: Wait for kvstore watcher to exit  (4945_, @tgraf)
* Count references to CIDR prefix lengths and generate bpf_netdev config based on it (4910_, @joestringer)
* makefile: Run go tool vet on the api and pkg subdirs (4909_, @rlenglet)
* Don't perform IPCache lookup when identity is health/init/fixed-identity (4889_, @joestringer)
* pkg/kvstore: fix high-cpu usage when Cilium loses Consul connectivity (4888_, @aanm)
* correctly convert CIDRs within a single CIDR policy rule which allow access to the world to reserved:world identity when rule contains multiple CIDRs (4846_, @ianvernon)
* Fix deadlock for endpoint state when endpoint is in StateWaitingForIdentity when no labels were changed (4840_, @aanm)
* Fix bug where traffic from a host to a service IP was classified as from the world, not from the host (4830_, @joestringer)
* cni: Check if directories exist before creating them (4799_, @tgraf)
* Prevent Cilium from deadlock when interacting with etcd (4788_, @aanm)
* bpf: Fix ipcache lookup for kernels with HAVE_LPM_MAP_TYPE (4773_, @tgraf)
* Watch for Kubernetes Namespace label changes (4756_, @aanm)
* Change default "CRI-o" mounting path to "/var/run/crio/crio.sock" (4753_, @aanm)
* Check endpoint status before modifying identity labels (4739_, @aanm)
* cilium-docker: fix gatewayIPv4 assignment (4709_, @nirmoy)
* Support updating controllers instead of requiring to re-create them (4683_, @rlenglet)
* pkg/policy: take into account To / FromRequires when computing L4 policy (4682_, @ianvernon)
* endpoint: Fix restored endpoints not showing up in ipcache (4678_, @tgraf)
* stop logging conflicting errors as errors when modifying kubernetes objects (4676_, @aanm)
* change the minimal number of BPF regeneration builders from 4 to 2 (4670_, @aanm)
* Service backends may now be added without potentially disturbing existing TCP sessions. (4667_, @jrfastab)
* Fix PolicyRevision of endpoint bumped prematurely (4636_, @aanm)
* metricsmap: Fix index out of range error (4623_, @joestringer)
* Fix bug where inserting the same CIDR in multiple rules, then removing one rule, would result in traffic not being allowed based on the rule that remains in the policy. (4611_, @joestringer)
* Fix sidecar proxy deadlock during BPF generation (4610_, @rlenglet)
* Fix regression that caused policies with `ToServices` rules to not allow traffic to services with external backends (4587_, @joestringer)
* Fix endpoint restore log regarding health endpoint (4561_, @manalibhutiyani)

Other Changes
-------------

* allocator: Support watching allocations in arbitrary kvstore connections (4934_, @tgraf)
* Use UpdateStatus for Cilium Endpoint Status in k8s 1.11 (4877_, @aanm)
* bpf: Shift ingress ipcache source lookup to netdev (4874_, @joestringer)
* Split BPF ingress program into IPv4 and IPv6 handlers (4867_, @joestringer)
* bpf: Allow to use 24 bits for security identities (4858_, @tgraf)
* Implement datapath trace notification aggregation (4828_, @joestringer)
* pkg/policy/api: allow ToPorts coupled with ToServices (4805_, @ianvernon)
* Maintain ipcache entries for Cilium host IPs based on k8s node annotations (4797_, @aanm)
* Speed up regeneration of endpoints with a large number of rules (4790_, @ianvernon)
* Watch for Kubernetes Namespace label changes (4756_, @aanm)
* Watch for kubernetes pod labels changes (4730_, @aanm)
* kvstore: Support creation of multiple clients (4725_, @tgraf)
* Changed the prometheus yaml to deploy in monitoring namespace (4699_, @ackerman80)
* set Cilium DaemonSet priorityClass to "system-node-critical" (4690_, @aanm)
* Expose endpoint and policy computation time metrics (4684_, @manalibhutiyani)
* contrib: add sysconfig file headers (4671_, @nirmoy)
* Add opensuse to Distribution Compatibility Matrix (4665_, @nirmoy)
* agent: Require go 1.10 for safe namespace operations (4599_, @tgraf)
* cilium-health: accept only positive interval (4593_, @nirmoy)
* Refactor EndpointSelector usage into helper functions (4548_, @joestringer)
* Don't remove old (pre-1.0) cilium-envoy.log on startup (4518_, @manalibhutiyani)
* Add metric "cilium_datapath_errors_total" for tracking errors in the datapath. (4507_, @joestringer)
* Add Kafka specific CI test checks to make sure kafka cluster is up correctly. (4488_, @manalibhutiyani)
* Metrics to report count of current endpoints tagged by endpoint states (4376_, @manalibhutiyani)
* Use UpdateStatus for Cilium Network Policy Status in k8s 1.11 (2972_, @aanm)


1.1.0
=====

::

    Amey Bhide (2):
          contrib: Script to figure cilium pod for a given pod
          Adds flag to clean up cilium state before startup

    André Martins (114):
          vendor: update k8s dependencies to 1.10.0
          docs: update k8s dependencies to 1.10.0
          examples/kubernetes: add k8s spec file auto-generator
          examples/kubernetes: add k8s spec files for master (:latest)
          docs/conf.py: Update copyright date to 2018
          docs: add global var SCM_BRANCH for branch name
          docs: update docs with tabs for multiple k8s versions
          test: use generate k8s spec files for testing
          tests: disabling K8sValidatedUpdates test
          README: change jenkins badge links
          fix misspelled comments in the code
          docs: fix l4 policy examples
          docs: review kafka GSG
          docs: update minikube GSG
          examples/k8s: fix 1.8 spec files
          docs: add sphinx-spelling to documentation
          docs: add custom worldlist for spellcheck
          docs: fix spelling in documentation
          pkg/node: fix nil pointer dereference
          packaging/docker: update docker runtime to 17.10
          Dockerfile: point dockerfile to quay.io base images
          envoy: move Dockerfile.builder to envoy directory
          Makefile: remove docker-image push instructions
          docs: fix titles formatting
          docs: add quay.io tutorial
          docs: add misspell words checker
          docs: fix some misspelled words
          docs: review troubleshooting guide
          examples/kubernetes: keep file order when catenating all files into one
          examples/kubernetes: avoid port conflict for running etcd
          examples/kubernetes: change etcd default port
          docs: use common minikube setup for all GSG
          examples/kubernetes: move standalone-etcd.yaml to addons/
          docs: GSG add instructions to install standalone etcd
          docs: add istio GSG to the list of GSGs
          docs: fix misspelled words
          test: update kubedns to 1.14.9
          test: fix star wars demo
          test: use cilium exec helper
          ctmap: remove debug message
          test: fix wrong IPv6 assignment
          Revert "CI: Temporarily add retry 3 times logic in connectivity.go"
          test: change archive type to zip
          k8s: remove unused code for KNP extensions/v1beta1
          test: change k8s 1.7 manifests to extensions/v1beta1
          development: add cache to k8s components
          k8s: add some fixes to the kubernetes spec file
          k8s: only watch for ingress changes if LB is enabled
          Vagrantfile: re-add workaround for kube-proxy in node-2
          start.sh: add routes based on VM name
          test: update k8s tests for 1.8, 1.9, 1.10 and 1.11
          pkg/ip: fix getNextIP for IPv4
          pkg/option: move pkg/option/config to pkg/option/map_options.go
          pkg/option: move endpoint library options to option package
          daemon: move daemon's libray option to pkg/option
          endpoint: move endpoint's library option to pkg/option
          daemon: move daemon's config to option/config
          vendor.conf to golang/dep
          docs: list dep in dependencies list
          pkg/endpoint: fix owner merge conflict
          docs: fix typos
          docs: change minikube GSG to have necessary flags to run CNI
          docs: remove duplicated cilium installation instructions from GSG
          docs: layout fixes in GSG
          pkg/bpf: Use pointer receivers for MapKeys types
          test: update k8s versions to 1.7.15, 1.8.13, 1.9.8, 1.10.3 and 1.11.0-beta.0
          vendor: update k8s dependencies to 1.10.2
          common: add C2GoArray function
          pkg/ip: add GetNextIP
          pkg: allocate first IP in IPv4 allocation range
          daemon: in k8s mode always allow localhost traffic
          test: download exact k8s version of k8s upstream e2e
          contrib/vagrant: add container-d-integration
          pkg rename containerd to docker
          pkg/workloads: add containerd integration
          daemon: add containerd integration
          vendor: add containerd
          contrib/vagrant: fix container-d-integration
          workloads/containerd: add 10 second timeout for Status()
          pkg/workloads: show docker messages
          Revert "common/files: Add fileScanner struct"
          Revert "pkg/bpf: Use the other directory when /sys/fs/bpf is not BPFFS"
          add cri-o support
          docs: document runtime integration for developer VMs
          Revert "Contrib: Add Systemd parameters"
          docs: document dep usage for developers
          examples: add registry address to all container images
          workloads: cri allow grpc reconnectivity after failure
          workloads/crio: set default path to /var/run/crio.sock
          test/helpers: Fix WaitForKubeDNSEntry function on timeout
          daemon/k8s: remove .new in log messages when updating values
          pkg/endpoint: Keep BPF object files if compilation is skipped.
          examples/minikube: remove unused cilium-ds.yaml
          docs: add cri-o minikube guide
          pkg/k8s: allow from both namespace and pod selector in KNP
          kubernetes/templates: add DaemonSet file for CRI-o
          daemon: return error if createEndpoint fails
          daemon: use endpoint RLock in HandleEndpoint
          daemon: return NewPutEndpointIDCreated if endpoint is StateReady
          examples/kubernetes: remove etcd Secrets from the ConfigMap
          docs: document how to set up config map with etcd certificates
          docker/Dockerfile: update base image to ubuntu 18.04
          docker/Dockerfile: update iproute2 to 4.16
          docker/Dockerfile: update loopback cni to 0.6.0
          docker/Dockerfile: add gpg
          Dockerfile: update cilium-runtime with 2018-06-04
          docs: add documentation to upgrade ConfigMap
          docs: typo fix
          examples/kubernetes: use POSIX regex for CILIUM_VERSION checker
          docs: fix broken links
          docs: use Documentation context to avoid longer image builds
          docs: add checklinks target
          docs: fix mesos guide
          daemon: skip health endpoint on restore

    Arvind Soni (8):
          doc: Star Wars theme HTTP Getting Started Guide
          Text edits based on the reviews
          Fix image formatting and simplifies app yaml
          Elasticsearch Getting Started Guide
          revised elasticsearch getting started guide
          Added example for the policy trace Added kubectl exec ... part to the cilium monitor command
          expanded install guide for kops with complete steps from scratch
          Fixed a reference that was to localhost Changed the clustername to include a username to avoid stepping on multiple clusters

    Ashwin Paranjpe (3):
          Update docs related to cluster-diagnosis
          GH4164 Append rule labels while parsing api.Rule
          GH-4339 Add k8s label source in GetPolicyLabels

    ChristopherBiscardi (1):
          cilium/cmd: add ls alias for list commands

    Cynthia Thomas (1):
          Upgrade Note edit

    Daniel Borkmann (11):
          docs: update mailmap and authors
          bpf: further work on bpf reference guide
          docs, bpf: complete iproute2 section and add llvm inline asm example
          docs, bpf: initial xdp section and improved projects section
          docs, bpf: finalize initial round on xdp section
          docs, bpf: initial tc bpf section
          docs: update mailmap and authors
          docs, bpf: fix typo in overview graphic
          docs, bpf: minor follow-up fixes in the ref guide
          docs, bpf: improve llvm6.0 dependency note
          bpf: remove geneve TLV options

    Diego Casati (1):
          add '[bB]log and Ubuntu to the spelling list. This fixes the issue when creating an ePub out of the docs

    Eloy Coto (107):
          Test: Trigger `vm.ReportFailed` in the global AfterAll
          Test: Enable egress-deny
          Test: Fix hack in `SetAndWaitForEndpointConfiguration`
          Nightly: Change Ping behaviour on egress rules
          Nightly: Add listening check on TCP KeepAlive
          Test: Add cilium monitor in GuestBook Examples
          Test: Do not gather envoy.log
          Bugtool: Add gops output
          Test: Enable Cilium Update test
          Test: trigger AfterFailed before AfterEach when is in Context
          Test: Add separate logs per each cilium pod
          Test: Fix issue with Kubectl describe
          Test: Enabled K8sUpdates correctly.
          DOC: Cheatsheet change structure
          Test: Validate DNS before trying to connect on curl
          Test: CNP use full FQDN
          DOC: Update cilium contributing docs:
          Docs: Add a new `test-docs-please` phrase to test only docs
          Docs: review GRPC GSG
          DOC: Review Getting help section
          Documentation: Address PR comments
          Test: Added new Jenkins jon to run Kubernetes official e2e tests
          Test: Increase logs for Kube-dns issues
          Jenkins: Fix timeout on docs.
          CI: Add colors to builds.
          Ginkgo: Run monitor on test
          Test: Fix typos
          Test: Update Kafka Env variable.
          Test: Fix issues with Updates and Kube-dns
          Nightly: Fix issues with Kubectl exec
          CI: Update packer-ci job and documentation
          Docs: Fix spelling wordlist and sphinx warnings
          Test: Archive in quiet mode
          Test: Fix recursion issue with Kubectl.CiliumExec
          Test: Check that after restart cilium still return 403 messages
          Test: Import Network Policy and ensure that it is applied in all Cilium Pods.
          Vagrantfile: Update Vagrant version to 68
          Jenkins: Add automatic trigger if a label is present
          Ginkgo: Add segmentation fault check on `ValidateErrorsOnLogs`
          Test: Gather core dumps in test if are present.
          Test: Gather core dumps from cilium kubernetes pods
          Nightly: Exclude connectivity test on invalid policies
          Test: Fix Bookinfo issues
          Test: Updating Kube-dns manifest to get more verbose
          Test: Fix issues on `kubectl.CiliumReport`
          Bugtool: Fix gops commands
          Test: Simplified Kafka K8S test
          Test: Add NACK message in log checks.
          Test/K8s: Added debug logs in cilium DS
          Test: K8s Policies did not wait for all endpoints to be ready.
          Contrib: Add a jenkins status script.
          Test: Update Vagrant boxes
          Test: CMDSuccess Matcher
          Test: Use helpers.CMDSuccess in ExpectWithOffset
          Test: Clean all res.CombineOutput in all ResCmd asserts
          Test: CMDSuccess fix typos
          Test: Improved Ginkgo logs
          Test: Append the AfterFailed commands to the Jenkins Output.
          Test: Add more context commands on AfterFailed commands
          Test: Dump vagrant provision logs to Jenkins console.
          Test: Add test result in Jenkins Junit
          Jenkins: Fix issues with downstreams Jobs
          Test: Improved Kubectl CEP helpers
          Test: Enable containerd on Jenkins builds.
          Test: Fix issues with Ginkgo Kubernetes Job
          Test: Ginkgo fix AfterFailed when fail on JustAfterEach.
          Test: Do not log cilium logs in test-output.log
          Vagrantfiles: Update base image to 77
          Test: K8st update how cilium is installed.
          Contrib: Add Systemd parameters
          Test: Dump Vagrant output to Jenkins console
          Test: Fix assert line on CMDRes.Expect*
          Test: Kubernetes upstream fix Cilium installation.
          Test: re-enable debug on Cilium
          Test: Fix PodCIDR on Kubeadm init.
          Test: Add cep output on Kubernetes report
          Test: Fix PodCIDR issues on Kubernetes 1.7
          Ginkgo-ext: Fix Codelocation on asserts
          Test: Refactoring how policies are applied.
          Test: Delete helper.ApplyNetworkPolicyUsingAPI
          Test: Use Kubecfg native options.
          Test: Refactor CiliumEndpointWait
          Test: CurlFail wrapper log HTTP response headers
          Test: Cmd.SendToLog change format
          Nightly: Fix issues on test.
          Test: Wait for kubedns to be ready after cilium upgrade
          Test: Demo tests waiting to policies to be applied.
          Test: K8st Tunnels delete services before delete Cilium
          Test: Fix panic on Microscope callback
          Test: Skip Kube-dns if the Kubernetes version is 1.11
          Test: Bugtool dump in a folder, not in tar format.
          Test: Avoid long json in test-output
          Test: Do not dump Cilium logs on test-output.log
          Test: Update Vagrant box to version 83
          Revert "Revert to working Vagrant box and cilium-builder image"
          Test: provision uninstall crio cni interface
          Test: Add prometheus deployment on Kubernetes test
          Test: Move RuntimeKafka test to use BeforeAll
          Test: Helpers update some ginkgo.By messages
          Test: Update monitorStop func to not panic.
          Contrib: Backport script to use different versions
          Endpoint: Log policyRevision on endpoint log.
          Test:Guestbook wait for pods to be ready
          apipanic: Log stack as string
          Documentation: Update docs to minimun 4.9.17 kernel version
          Docs: Update minikube GSG.
          Test: Wait until all pods are ready

    Eohyung Lee (1):
          Fix broken kubernetes-ingress example

    Ian Vernon (176):
          pkg/policy/api: add SelectsAllEndpoints function
          pkg/policy: fix merging of L4-related policy
          examples/minikube: convert L3-L4 policy to CiliumNetworkPolicy
          Documentation/gettingstarted: update Minikube GSG to reflect how we handle L4-only and L4-L7 policy on the same port
          Documentation/gettingstarted: update `cilium status` output in Docker GSG
          pkg/k8s: add TODO for cleaning up unit tests
          pkg/maps/ipcache: log if map unable to be opened
          pkg/logging/logfields: add log field for BPF map name
          pkg/bpf: add additional logging and error handling
          bpf/lib: unconditionally create ipcache bpf map in datapath
          .gitignore: ignore test/test_results directory
          test/helpers: gather more K8s metadata
          test/k8sT: query both service IP and hostname of redis master
          test/k8sT: add wait for service endpoints to be ready in guestbook test
          test/k8sT: add more descriptive error messages to Guestbook test
          pkg/endpoint: log what caused policy changes
          pkg/ip: add functionality to coalesce CIDR list
          test/k8sT: do not access redis-master via hostname, only service IP
          test/helpers: add previous Cilium pod logs to kubectl.GatherLogs()
          test/k8sT: do not defer deletion of resources within It
          pkg/policy: remove redundant length check in AllowsAllAtL3
          pkg/policy: do not use length checks on L4Filter.Endpoints
          pkg/policy: change parser type logic for merging L4Filter
          Documentation/policy: add label-based egress documentation
          test/helpers: add helper function for adding IP addresses to VM loopback device
          test: factor out IPs which represent the host
          test/helpers: add helper function for flushing global connection tracking table
          test/helpers: add HostDockerNetwork constant
          test/runtime: add test for egress to host
          test/helpers: change `ip addr` commands to use `ExecWithSudo`
          test/runtime: misc. cleanups for host egress test
          pkg/policy: change string "l3" --> "L4" in tests
          pkg/policy: misc. cleanup in merging port functions
          pkg/envoy: always use dport in proxy statistics
          debuginfo: remove unneeded per-endpoint calls to some bpf commands
          debuginfo: run `cilium endpoint health` for each endpoint
          cmd: update misc. command Short descriptions
          test/helpers: validate policy before importing in `PolicyImportAndWait`
          test/runtime: add L3-dependent L7 egress tests
          test/helpers: use rsync to copy files instead of cp (#3826)
          test/k8sT: wrap CNP Specs test in Context
          test/k8sT: do not defer resources in CNP Specs test
          test/helpers: make sure that key is non-empty for running `docker logs`
          k8sT: test default-deny ingress and egress policy
          ginkgo-kubernetes-all.Jenkinsfile: increase timeouts
          test/helpers: remove unnecessary logs for creating / deleting Docker containers
          test/helpers: log to console when report generation begins / ends
          Documentation: remove bash-test framework references
          test/k8sT: move cleanupNetworkPolicy to AfterEach within test
          test/k8sT: wrap policy across namespaces test in Context
          test/k8sT: move creation and deletion of resources
          test/k8sT: wrap Checks Service test in `Context`
          test/k8sT: move creation of resources outside of `It`
          test/k8sT: move cross-node service test within `Context`
          test/k8sT: move creation of resources
          test/k8sT: move NodePort test to within across nodes `Context`
          test/k8sT: fix deletions in AfterEach to not have assertions
          test/k8sT: fix instantiation of variables
          test/k8sT: change "Checks service across nodes" to use "BeforeAll" and "AfterAll"
          test: add helper PolicyEnforcement assertion to avoid boilerplate code
          test/runtime: convert RuntimeValidatedPolicyImportTests to use BeforeAll / AfterAll
          test/runtime: remove unused constants
          test/runtime: add ExpectEndpointSummary helper
          test/runtime: cleanup RuntimeValidatedChaos test
          pkg/policy/api: reject rules which use non-TCP protocols in conduit with L7 rules
          pkg/policy: remove L3L4Policy field from Consumable
          pkg/policy: remove SecurityIDContexts and associated types
          test/k8sT: wrap Geneve test in `Context`
          test/k8sT: move creation / deletion of resources outside `It`
          test/k8sT: wrap vxlan test in `Context`
          test/k8sT: move creation / deletion of resources outside `It`
          pkg/endpoint: do not link created Consumables to ConsumableCache
          pkg/policy: remove Remove for ConsumableCache
          pkg/identity: add GetAllReservedIdentities function
          pkg/policy: remove ConsumableCache
          pkg/u8proto: add constant to represent all protocols being allowed
          pkg/maps/policymap: coalesce Allow and AllowL4 functions
          pkg/maps/policymap: merge IdentityExists and L4Exists functions
          pkg/maps/policymap: merge Deletion functions
          pkg/endpoint: remove WaitGroup return value from TriggerPolicyUpdatesLocked
          pkg/identity: move LabelArray from Consumable to SecurityIdentity
          pkg/policy: remove \"changed\" return value from regenerateConsumable
          test/helpers: disable microscope in K8s tests
          pkg/endpoint: remove PortMap field
          test/k8sT: do not set Debug=False during tests
          test/k8sT: rename variable to be more descriptive
          test: add helper to wait for CEP revision update in K8s
          test/helpers: check whether cep is nil before trying to access its fields
          test/helpers: add WaitForCEPToExist function
          test/k8sT: wait for CEP to exist before getting policy revision
          vagrant: configure journald to allow for large amounts of logs
          test/helpers: fix ManifestGet to use filepath.Join
          test/helpers: remove Kubectl receiver from ManifestGet
          test/k8sT: group var declarations in var( ... )
          test/k8sT: move instantiation of vars to when they are declared
          test/k8sT: move K8s chaos test to use BeforeAll
          test/k8sT: add some assertion helpers
          test/k8sT: get manifests in var declarations
          test/k8sT: have KafkaPolicies test use assertion helpers
          test/k8sT: add wrapper for expecting all pods to be deleted
          test/k8sT: replace WaitKubeDNS with ExpectKubeDNSReady
          test/k8sT: refactor WaitForPods to return only an error
          test/k8sT: use ExpectCiliumReady in more helpers
          test/k8sT: remove unused demoPath var
          test/k8sT: move instanation of var to its declaration
          test/k8sT: move initialize function for demo test into BeforeAll
          test/k8sT: group var declarations
          test/k8sT: move Health.go initialization into BeforeAll
          test/k8sT: change WaitForServiceEndpoints to only return an error
          test/k8sT: move instantiation of manifest variables in declarations
          test/k8sT: remove unneeded type declarations for vars
          test/k8sT: move instantiation of vars to declaration
          test/k8sT: move initialize function to BeforeAll
          test/helpers: move ManifestGet to utils.go
          test/runtime: add output of command if curl to Google fails in test
          pkg/policy: remove debugging Println calls in unit test
          pkg/policy/api: add basic HTTP Rule sanitization
          pkg/maps/policymap: export PolicyKey type
          policy: factor out endpoint PolicyMap updates into controller
          pkg/endpoint: refactor label-based L3 policy determination
          pkg/bpf: update comment to reflect current behavior
          pkg/endpoint: rename L4Policy field to RealizedL4Policy
          pkg/endpoint: add DesiredL4Policy field for endpoint
          endpoint: remove consumable checks
          pkg/endpoint: check SecurityIdentity directly in regenerateBPF
          pkg/endpoint: check if endpoint SecurityIdentity is nil in TriggerPolicyUpdatesLocked
          pkg/endpoint: add Iteration to Endpoint
          pkg/endpoint: remove use of Consumable in regeneratePolicy
          pkg/endpoint: do not populate endpoint policy model with Consumable info
          pkg/endpoint: check SecurityIdentity instead of Consumable ID
          pkg/endpoint: remove Consumable from Endpoint
          pkg/policy: remove Consumable
          pkg/endpoint: specify why local copy of DesiredL4Policy is made
          test: fix Policy cmd test resource deletion
          test/runtime: move initialize func into BeforeAll
          test: fix CLI resource creation / deletion
          test/runtime: move policy deletion to AfterEach
          test/k8sT: fix deletion of policy in external services test
          test/k8sT: use ExpectWithOffset in helper function
          test/k8sT: add faliure messages to assertions in validateEgress
          test/k8sT/manifests: re-add l3_l4_policy.yaml
          pkg/endpoint: release lock if syncPolicyMap fails
          configuration: move TracingEnabled to pkg/option
          Revert "Re-enable microscsope in CI"
          cmd: specify JSON format for `cilium policy import`
          cleanup: remove refs to Consumable in comments
          pkg/endpoint: check if PolicyMap is nil in syncPolicyMap
          pkg/endpoint: include node headerfile hash
          daemon: factor out node config headerfile into separate function
          pkg/node: move IPv4Loopback address from daemon to node package
          daemon: remove loopbackIPv4 from Daemon type
          pkg/option: sort options in GetFmtList
          tests: remove unmaintained / unused tests
          pkg/endpointmanager: always regenerate if policy forcibly computed
          daemon: trigger policy updates upon daemon configuration update
          test/k8sT: add k8s default-allow tests
          Documentation/cmdref: update cilium-agent cmdref
          pkg/bpf: include map file descriptor in error messages
          bugtool: get list of open file descriptors
          test/runtime: add connectivity test after daemon configuration update
          pkg/endpoint: close and reopen policy map if dump fails
          pkg/logging/logfields: add new BPF map logfields
          pkg/maps/policymap: set fd to 0 after close
          pkg/endpoint: always ForcePolicyCompute if endpoint assigned new identity
          pkg/endpoint: log clearing maps upon regen failure
          examples/kubernetes-ingress/scripts: factor out cri-o installation into function
          daemon: change when restored endpoints are inserted into endpoint manager
          api/v1: add "sync-build-endpoint" to EndpointChangeRequest
          pkg/endpointmanager: update comment to remove reference to endpoint creating state
          plugins/cilium-cni: specify that endpoints should synchronously be regenerated via API
          daemon: wait for endpoint to be in ready state if specified via EndpointChangeRequest
          GH-4248: Return Annotations in CNP NodeStatus
          test/k8sT: wrap KafkaPolicies test within Context
          daemon: synchronously add endpoints to endpointmanager in \`regenerateRestoredEndpoints\`
          test/helpers: gather logs from all pods
          Makefile: add jenkins-precheck Makefile target

    Jarno Rajahalme (46):
          envoy: Update generated go-files for Cilium HTTP filter.
          envoy: Set SO_LINGER and SO_KEEPALIVE on accepted sockets.
          envoy: Fix integration test
          docs: Document the backporting process.
          daemon: Fix Envoy version check and add hidden option to skip it
          daemon: Remove deprecated '--envoy-proxy' option
          envoy: Pass 'non-redirect' http traffic through.
          endpoint: Fix label replacement.
          daemon: Regenerate endpoint in PATCH handler also when endpoint is in waiting-for-identity state.
          envoy: Remove assert, reduce logging.
          bpf: Honor DROP_ALL also in ingress to a container.
          bpf: Make all funtions in lib/policy.h conditional on DROP_ALL
          Makefile: Fix the name of the builder Dockerfile in envoy.
          envoy: Fix integration test setting of original dst address.
          envoy: Use network byte-order addresses in host map.
          envoy: Support CIDRs in NPHDS.
          envoy: Add host map to cilium integration test
          envoy: Egress intergation tests.
          docs: Refine backporting instructions.
          envoy: Manage life-cycles of singleton maps properly.
          envoy: Initialize thread local host map with an empty map.
          envoy: Minor cleanup.
          envoy: Use distinct Stats stores for each instance of a xDS client.
          envoy: Fix handling of zero length CIDR prefixes.
          systemd: Enable core dumps.
          envoy: Make policy direction configurable for Istio.
          maps: Use pointer receivers for MapValue types.
          daemon: Sync local IPs to lxcmap periodically.
          envoy: Configure gRPC service explicitly to get rid of deprecation warning in the logs.
          test: Change DROP_ALL to install a dummy policy.
          policy: Do not enable DROP_ALL mode if not needed.
          docs: Fix ginkgo command line.
          ctmap: Make GC bpf map dumps more robust.
          envoy: Log CIDR->ID mappings at debug level.
          proxy: Test if port is available before allocating it for a proxy.
          proxy: Release redirect sooner.
          docs: Remove repetition from Istio GSG.
          bugtool: Add '-a' option to netstat.
          Gopkg: Update golang/protobuf
          envoy: Rebase to get gRPC proxy responses.
          bpf: Only create veth pair if it does not already exist.
          envoy: Update generated Cilium protobufs.
          envoy: Update integration test.
          init.sh: Use 'ip route replace' instead of 'ip route add'
          Docs: Troubleshooting updates.
          Docs: Remove CoreOS Installation Guide

    Jess Frazelle (1):
          pkg/bpf: add function wrappers for prog syscalls.

    Joe Stringer (174):
          daemon: Sync loadbalancer BPF maps from goroutine
          k8s: Gather timestamps in cilium_logs on failure
          docs: Update kubernetes policy page
          docs: Update policy intro page
          docs: Fix contributing guide warnings
          docs: Improve L3 policy section
          docs: Improve L4-L7 (+HTTP) policy section
          docs: Improve kafka policy wording
          docs: Document per-endpoint policy configuration
          docs: Document the guiding policy principles
          docs: Add GH links for future roadmap features
          bpf: Fix conntrack entries for ICMP
          bpf: Derive proxy_port from policy rather than CT
          bpf: Only apply CIDR ingress to reserved identities
          bpf: Apply egress CIDR policy to reserved identities
          docs: Document consistent CIDR policy
          cidrmap: Allow insert of any length of CIDR
          policy: Log errors inserting CIDR entries
          bpf: Rename tunnel_endpoint_map -> cilium_tunnel_map
          tunnel: Remove old tunnel map upon upgrade.
          bpf: Only create conntrack entries for SYN packets
          Revert "bpf: Allow CT creation on FIN"
          bpf: Fix log message about not supporting CIDR
          docs: Pass sphinx options to spellcheck make target
          docs: Split spellcheck check from main builds
          docs: Print spelling list upon failure
          ipcache: Shift NPHDS logic to envoy
          envoy: Handle IP->ID deletes inside cache
          daemon: Push reserved IP->Identity mappings to XDS
          xds: Add tests for cache.Lookup
          monitor: Fix CT entry dst port printing
          policy: Support reserved:cluster entity
          bpf: Fix tracing message for egress policy
          bpf: Fix default build config
          ipcache: Avoid issuing delete for identity=0
          xds: Validate NPHDS updates before upserting
          docs: Update concepts for egress policy
          docs: Fix bpf spelling complaint
          docs: Describe namespace selector behaviour in k8s
          endpoint: Remove unnecessary l3 wildcard expansion
          ipcache: Reuse existing function for lookup
          endpoint: Refactor some IPID handling code to ipcache
          ipcache: Log inserts/removes from map
          runtime: Refactor egress before/after functions
          monitor: Fix IPv6 string formatting in CT messages
          policy: Refactor L4Filter creation
          policy: Create L7 rules with wildcard selector
          policy: Expand comments for policy objects
          policy: Move computeResultantCIDRSet() to api
          policy: Use typed CIDRSlice / CIDRRuleSlice
          policy: Shift error checking comment to function doc
          bpf: Rework ipcache to support LPM lookups.
          k8sT: Make health test more robust
          Makefile: Fix quiet target for make unit-tests
          labels: Add CIDR to labels libraries
          labels: Format only one CIDR label
          policy: Add rule CIDR->*net.IPNet conversion libraries
          Makefile: Start etcd test container with -listen-peer-urls
          daemon: Check if device exists on endpoint restore
          contrib: Remove KVstore containers in systemd scripts
          k8sT/Services: Fix URL for bookinfo tests
          k8sT/Services: Remove fetch http://details:9080/
          ipcache: Support CIDR prefix to ID mappings
          daemon: Populate BPF ipcache with CIDR prefixes
          daemon: Allocate identities for CIDRs
          policy: Resolve CIDRs in rule GetAsEndpointSelectors()
          daemon: Fix ipcache conflict between hosts and prefixes
          daemon: Refactor ipcache initialization.
          daemon: Push reserved CIDR ranges into ipcache
          api: Allow egress CIDR+L4 rules
          runtime: Add CIDR + L4/L7 egress tests.
          ipcache: Reject policies with too many CIDRs.
          CODEOWNERS: Shift ownership of ipcache to a team
          identity: Fix pair.PrefixString() arguments
          manifests: Pin bookinfo container image versions
          k8s: Support IPv6 addresses in CIDR policy
          k8s: Add CRD IP address validation unit tests
          docs: Describe downgrade impact of IPv6 CRD validation
          k8s: CIDR: Expand v6 regex to make it more readable
          k8s: CIDR: Disallow IPv4-mapped IPv6 addresses
          k8s: CIDR: Format IPv6 CIDR regex
          policy: Remove CIDR L3 egress plumbing
          k8s: Bump CRD schema version.
          bpf: Ensure maps are restored on load failure
          bpf: Fix failure handling in CreateMap
          bpf: Respond to all ARP requests
          cmd: Fix `cilium bpf ipcache`
          test: Refactor policy labels name for common usage
          test: Fix no-op checks in CT tests
          test: Handle endpoint list errors in helper
          bpf: Improve logging output for map creation
          ipcache: Refactor ipcache limitations check to map
          bpf: Remove egress CIDR lookup
          bpf: Support LPM for ipcache on newer kernels
          ipcache: Loosen CIDR configuration restrictions
          cmd: Fix import ordering for bpf ipcache
          cmd: Describe LPM limitation of IPCache
          Remove upstart artifacts.
          test: Don't gather logs in -holdEnvironment
          bpf: Fix lxc header guard
          endpoint: Fix detection of L4 policy changes
          ipcache: Rename ipIDPair parameter
          ipcache: Provide old mapping to listeners on change
          docs: Attempt to use RTD version for GH URLs
          daemon: Install rules to mark local applications
          bpf: Mark traffic from outside local host as world
          daemon: Reuse proxy magic marker variables
          daemon: Format packet marks as 32bit hexits
          docs: Update dependencies for latest Envoy
          metricsmap: Set the key size properly
          policy: Express egress CIDRs in endpoint model
          endpoint: Use policy for IP LPM, not IPCache
          policy: Add test for default CIDR prefix lengths
          test: Add bpf/verifier-test.sh to ginkgo
          chaos: Use JSON output for endpoint restore check
          pkg: Add MTU package
          vendor: Update netlink library for route MTU
          node: Configure route MTUs depending on destination
          cni: Configure default route MTU in endpoints
          daemon: Configure MTU for devices using pkg/mtu
          docs: Describe MTU changes from v1.0 to v1.1
          daemon: Add --k8s-legacy-host-allows-world option
          k8s: Regenerate example YAMLs for host-allows-world
          docs: Document the v1.1 host vs world policy
          docs: Improve formatting of upgrade notes
          docs: Use absolute paths for iptables diagram
          docs: Update k8s iptables diagram for Cilium 1.1
          endpoint: Initialize ProxyWaitGroup later
          test: Bump journald log ratelimit to 10000
          identity: Return errors from ReleaseSlice()
          policy: Expose EndpointSelectors for reserved labels
          policy: Wildcard L7 for AllowsLocalhost, HostAllowsWorld
          policy: Don't remove L4+ policies for host/world
          labels: Fix source for existing cidr tests
          labels: Resolve CIDR 0.0.0.0/0 to reserved:world
          ipcache: Don't push reserved identities to kvstore
          policy: Make CIDRRule error more consistent
          policy: Allow 0/0 CIDR to match reserved:world
          policy: Support CIDRs in rules with zero length prefix
          test: Add runtime policy test for 0.0.0.0/0
          docs: Document downgrade for /0 CIDR rules
          policy: Use common kafka port for tests
          policy: Improve unit test descriptions
          policy: Fix l4filter test 1 to adhere to comments
          policy: Document l4filter test cases
          policy: Add l4filter l7rules generation comment
          health: Measure timestamp at start of probe
          health: Only overwrite probes with newer reports
          health-ep: Depend on option package for config
          health-ep: Add health EP to manager later
          health-ep: Refactor cleanup logic
          health-ep: Rely on pidfile for deferred cleanup
          pidfile: Refactor kill by pidfile into pidfile
          health-ep: Refactor error handling to caller
          daemon: Allow endpoint to be freed without releasing IP
          daemon: Controllerize cilium-health endpoint
          health-ep: Bump timeouts for endpoint readiness
          health-ep: Document threadsafety
          endpointmanager: Simplify CT GC launch code
          apipanic: Log stack at debug level
          metrics: Add datapath management metrics
          ctmap: Add metrics for conntrack dump resets
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

    Julien Kassar (2):
          Replace ADD with COPY instruction in Dockerfile
          Update envoy Dockerfile

    Junli Ou (1):
          docs: Specify the instruction format on little-endian machine.

    Maciej Kwiek (18):
          Clear logging in state.go
          Recover from panics in Cilium API
          Add pkg/apipanic to API codeowners
          [DOCS] Edit API compatibility guarantees section
          Remove combine flag from microscope call
          Log monitor client disconnect nicely
          Notify monitor about policy changes
          Wrap monitor policy event information is json
          Structure ep regen monitor notifications
          Structure agent start monitor notification
          Add docstrings to agent monitor notification code
          GetLabels -> GetOpLabels in monitor messages
          Unflake monitor agent notifications tests
          Move endpoint interface from endpoint to monitor
          [Docs] Kops installation guide stub
          `cilium monitor` json mode
          Re-enable microscsope in CI
          [Monitor] add src and dst data to json output

    Manali Bhutiyani (39):
          test: Make the Kafka CI errors more descriptive. Fixes: #3503 Related to: #3502 Signed-Off-By: Manali Bhutiyani <manali@covalent.io>
          test: Move topic creation in the BeforeEach function Fixes: #3503 Related to: #3502 Signed-Off-By: Manali Bhutiyani <manali@covalent.io>
          docs: Correct spelling mistakes in the docs Fixes: #3523 Signed-Off-By: Manali Bhutiyani <manali@covalent.io>
          CI: Temporarily add retry 3 times logic in connectivity.go Fixes: #3596 Related to: #3393 Related to: #3595 Related to: #3558
          docs: Minikube audit. Add reference links wherever required. Improve docs wherever required. Part of the 1.0 Documentation Review. Fixes: #3669 Related to: #3597
          CI: Add ingress/egress default deny tests for CNP Fixes :#3343 Signed-Off-By: Manali Bhutiyani <manali@covalent.io>
          CI: Remove call to WaitUntilEndpointUpdates, if CiliumPolicyAction is present. CiliumPolicyAction takes care of waiting till endpoints get updated correctly. Remove the unnecessary calling of WaitUntilEndpointUpdates, in addition to CiliumPolicyAction.
          docs: Correct backport label in docs from stable/needs-backporting to stable/needs-backport Fixes: #3738 Signed-Off-By: Manali Bhutiyani <manali@covalent.io>
          Kafka : remove noise from logging EOF messages in Kafka parser We keep seeing a lot of these on normal client (produce/consume) connection close. We should not be logging valid EOF as errors.
          CI: add Runtime default DROP_ALL test This test adds the runtime DROP_ALL tests and does 3 checks to make sure DROP_ALL is applied properly
          CI: Move RuntimeValidatedPolicyDropAllTests to RuntimeValidatedPolicies Make the DROP_ALL gingko test more time-efficient and resource effecient, by grouping it with RuntimeValidatedPolicies
          endpoint: Remove endpoint state directories left behind after build failure Failed regeneration files `XXXXX_next_fail` may stick around after regeneration. We are correctly deleting these files on regeneration, but not on deletion of endpoint. This commit deletes the endpoint XXX_next_fail files on endpoint deletion.
          docs: Fix the gsg to point to the correct prometheus yaml The path examples/kubernetes/plugins/prometheus/prometheus.yaml has changed to examples/kubernetes/addons/prometheus/prometheus.yaml Fix this in the GSG docs.
          docs: Fix spellchecker to include word Jenkinsfiles
          metrics: Add new L7 proxy based metrics This commit declares new proxy based metrics to be exposed via the prometheus framework namely:
          docs:  Update docs with new L7 proxy based prometheus metrics
          linux/bpf.h: Add reference link to in-kernel sk_buff structure.
          cmd: Add a CLI command to access the bpf L3-L4 metrics map
          bpf: Add BPF map cilium_metrics for L3-l4 packet drops/forwards
          pkg/maps/metricsmap: Add a new userspace pkg/maps/metricsmap to access BPF metrics maps.
          pkg/maps/metricsmap/: Add a doc.go in the metricsmap pkg
          bpf: Add metricsmap helper funcs and controller metricsmap-bpf-prom-sync
          daemon: Remove unnecessary explicit conversion of time
          pkg/metrics: Add prometheus counterVectors for Drops and Forwards
          pkg/monitor: Export DropReason to be consistent with cilium monitor
          docs: update docs with L3/L4 drop/forward metrics
          bpf: Change BPF metrics map to type BPF_PER_CPU_HASH_MAP.
          pkg/maps/metricsmap: userspace aggregation of BPF_PER_CPU_HASH_MAP metrics map.
          docs: Change kafka image to point to a more stable tag 1.1.0 instead of latest
          CI/k8s: Change kafka image to point to a more stable tag 1.1.0 instead of latest
          docs: Correct spelling in ServiceAccount documentation
          test/manifest: Remove automatic topic creation on container start
          test/runtime: Remove hardcoded timeouts in the kafka runtime test
          test/runtime: Change check from listTopics to createTopics to check if Kafka broker is up.
          test/K8s: Wait for kafka broker to be up correctly.
          test/k8s: Increase kafka-zookeeper session/connection timeout to 60 sec
          test/runtime: Increase kafka-zookeeper session/connection timeout to 60 sec
          docs/examples: Increase kafka-zookeeper session/connection timeout to 60 sec
          daemon: Fix endpoint restore log regarding health endpoint

    Marius Gerling (2):
          Dependency to LLVM >= 6.0 in Documentation added
          Dependency to LLVM >= 6.0 in Documentation modified

    Mark deVilliers (1):
          Check for nil before accessing Status

    Matt Layher (3):
          pkg/labels: fix go vet issues
          pkg/policy: fix go vet issues
          test/runtime: fix go vet issues

    Michael Schubert (1):
          docs: fix shown command in minikube guide

    Michal Rostecki (24):
          daemon/endpoint: Handle DeleteElement error properly
          pkg/endpoint: Don't declare errs variable in function scope
          pkg/envoy/xds: Assign value to ip variable only if it's used
          pkg/ip: Assign value to allowedCIDRs variable only if it's used
          pkg/policy: Don't assingn unused variables
          pkg/k8s: Remove unused `node` variable assignment
          pkg/k8s: Assign value to `rules` variable only if it's used
          pkg/kvstore: Handler error from Get method properly
          common/files: Add fileScanner struct
          pkg/bpf: Use the other directory when /sys/fs/bpf is not BPFFS
          pkg/identity: Fix ineffassign errors
          pkg/workloads: Fix ineffassign errors
          pkg/mountinfo: Add utility for getting mountinfo
          bpf: Allow to define BPF map root via env variable
          pkg/envoy: Don't hardcode BPFFS mount path
          pkg/default: Add defaults for pkg/bpffs package
          pkg/bpf: Use the other directory when /sys/fs/bpf is not BPFFS
          pkg/health/client: PathIsHealthy as a public function
          pkg/endpoint/id: New package to avoid import cycle
          pkg/metrics: Define Prometheus metrics for `cilium status` data
          pkg/kvstore: Fix ineffassign error
          pkg/bpf: Fix ineffassign error
          pidfile: Fix error message formatting
          cmd: Detect BPF map root properly

    Nirmoy Das (5):
          daemon: exit if tunnel is not supported
          cilium status: fix --brief to print less when cilium isn't running
          bpf: drop incase of unsupported IPv6 headers
          bpf: monitor drops in NAT64/NAT46 tail calls
          cilium-docker: pass default cilium url when cilium-api is not provided

    Patrice Peterson (1):
          Various link fixes in documentation.

    Peter Slovak (1):
          app3 -> app1 in stateful conntrack paragraph

    Ray Bejjani (30):
          k8s: Fix bug with CEP cross-version delete
          api: Switch API version from v1beta to v1
          cli: protect against API nils
          daemon: Add more info logs on startup
          docs: Update system requirements
          doc: Update metrics documentation & list exported metrics
          doc: system requirements mention meltdown
          doc: Reword docker integration text
          k8s: CEP GC controller logs errors at debug level
          doc: Update spelling list and fix misspellings
          scripts: contrib/backports/check_stable handles backports-done label
          scripts: contrib/backports/check_stable prints PR link
          doc: Add a section about CiliumEndpoint CRDs
          docs: Correct RBAC urls in upgrade guide
          test: CmdRes.CombineOutput does not clobber stdout
          test: Star Wars demo checks HTTP status in stdout
          test: Switch Kafka runtime test to use CombineOutput
          monitor: Don't spinloop on node-monitor crashes
          monitor: pass payload objects by reference
          monitor: only read perf buffer on listener connect
          monitor: refactor globals into an object
          controller: Cleanup global manager on UpdateController
          monitor: Fatal on critical errors instead of panic
          monitor: More correctly cancel contexts on exit
          endpoint: Force regeneration when there are underlying errors
          monitor: cilium-agent passes along BPF mount path
          test: report collection prints error from ssh.RunCommand
          test: Do not print nil errors in ssh.Exec
          test: Increase kubedns timeouts above 5 minutes
          daemon: Warn on too-old status data

    Romain Lenglet (76):
          npds: Properly translate L4-only rules
          envoy: Rename the xDS cluster into xds-grpc-cilium
          proxy: Create access log file and setup notifier at startup
          docs: Use go-swagger Docker container to generate APIs
          daemon: Clean up access log setup
          test: Fix K8s demos to not use TTYs with kubectl exec
          doc: Update Istio GSG for Istio 0.7.0
          examples/kubernetes: Generate daemon sets defs for sidecar mode
          doc: Use K8s-version-specific YAML files in Istio GSG
          doc: Replace cilium-sidecar.yaml with a config map setting
          doc: Fix spelling
          test: Fix Star Wars demo test
          test: Always execute "cilium endpoint get" with -o json
          test: Force using IPv4 for egress connections to google.com
          policy: Synthesize wildcard L7 rules for L3-only rules
          policy: Replace adding L3-only rules into L4PolicyMap with extra loop
          envoy: Optimize lookup in allowed remote policies ordered list
          daemon: Define CILIUM_ACCESS_LOG and CILIUM_ACCESS_LABELS env vars
          daemon: Stop calling viper.AutomaticEnv() in daemon and cilium-health
          endpoint: Skip BPF compilation if headerfile is unchanged
          endpoint: Support hashing C headers with very long lines
          etcd: Clear the etcd status error when connectivity is OK
          Revert "etcd: Clear the etcd status error when connectivity is OK"
          etcd: Clear the etcd status error when connectivity is OK
          npds: Don't update NetworkPolicy if none has been calculated
          npds: Don't wait for ACK from sidecar proxy with no L7 rules
          ipcache: Fix ipcache deletion of old identities on update
          envoy: Fix dynamic casts that remove constness
          envoy: Update to same Envoy version as Istio master
          build: Fix builder image tag; fix tag used by ginkgo
          vagrant: Update box version to use updated Bazel cache
          envoy: Remove obsolete Envoy V2 API protobuf generated files
          Makefile: Remove instructions to push the -builder Docker image
          envoy: Build Istio Docker images
          tests: Fix old 10-proxy.sh test
          labels: Replace ParseStringLabels with NewLabelsFromModel
          controller: Skip StopFunc when stopping controller for update
          k8s: Consistently check for namespace labels in endpoint selectors
          endpoint: Allow traffic in BPF map when transitioning to allow-all
          ipcache: Update NPHDS cache before updating BPF maps
          ipcache: Create copies of NPHDS cache resources when updating
          xds: Match the client's version if higher than the server's
          ipcache: Create copies of NPHDS cache resources when deleting
          daemon: Define reserved:init label and set it on endpoints with no labels
          policy: Always enable policy for reserved:init endpoints in default mode
          api: Add "init" as supported entity
          identity: Allocate reserved identities for entity reserved labels
          cilium-docker: Remove constraint on endpoint state after creation
          cilium-docker: Create veth pair on endpoint creation
          cilium-docker: Remove now-unnecessary PATCH /endpoint/{id} API call
          endpoint: Fix state machine to support changing endpoint's labels
          daemon: Fix identity label update APIs
          test: Handle initializing endpoints with the reserved:init identity
          k8s: Don't add namespace labels into reserved:init endpoint selectors
          endpointmanager: Don't generate new endpoints waiting-for-identity
          envoy: Update Istio to the latest 0.8 RC version
          doc: Document the endpoint lifecycle and reserved:init identity
          docs: Update Istio GSG to Istio 0.8.0 pre-release
          daemon: Delete old ID mapping when updating the IP for a reserved ID
          Update to Istio 0.8 release
          docs: In GSGs, create the etcd-cilium deployment in kube-system
          docs: Add Istio injection annotations into all Istio examples
          docs: Remove the unnecessary init policy to Kafka in Istio example
          docs: Move the Istio GSG to use Helm
          vagrant: Revert updating the Vagrant box and cilium-builder tag
          Revert "vagrant: Revert updating the Vagrant box and cilium-builder tag"
          Revert to working Vagrant box and cilium-builder image
          Revert "Revert to working Vagrant box and cilium-builder image"
          Revert to working Vagrant box and cilium-builder image (#4430)
          k8s: Add label to endpoints injected with Istio + Cilium sidecar
          endpoint: Remove unused LabelsHash field from Endpoint
          endpoint: Replace sidecar-http-proxy flag with per-endpoint setting
          examples/kubernetes: Remove sidecar-http-proxy setting from examples
          docs: Remove use of the sidecar-http-proxy flag in the Istio GSG
          test: Remove sidecar-http-proxy setting from template
          docs: Remove sidecar-http-proxy config from upgrade instructions

    Shantanu Deshpande (7):
          Miscellaneous typo fixes in documentation.
          Change logging of new connections from warn to info level
          Sorting controller output by name (alphabetical) in status command
          Fix weird indentation for rules
          Add org to spellcheck wordlist
          Fixes 'any' reference target not found warning
          Misc fixes for kops installation guide

    Steven Ceuppens (5):
          Add "cilium identity list" output to bugtool
          Fix: `cilium monitor` allows invalid arguments
          Add "docker info" output to bugtool
          bugtool: make archive output configurable
          Split debuginfo into separate files

    Tasdik Rahman (2):
          docs: k8s: updating docs for k8s v1.9, 1.10 and 1.11 support
          docs: k8s: updating formatting

    Thomas Graf (97):
          labels: Ignore istio sidecar annotation labels
          etcd: Move etcd status check into the background
          cilium: Make cilium endpoint list resilient
          policy: Apply wildcarded source L7 rules to all sources
          bpf: Remove proxy_port from conntrack table
          policy: Remove logic to reset proxy port
          policy: Do not make initial endpoint DROP_ALL mode dependent on policy option
          bpf: Remove connection tracking entries on policy deny
          policy: Remove connection tracking cleanup on policy change
          agent: Provide non-blocking agent status
          health: Do sanity checking on health response
          policy: Do not wildcard CIDR 0/0 for world and all entity
          Revert "Revert "bpf: Allow CT creation on FIN""
          Revert "bpf: Only create conntrack entries for SYN packets"
          policy: Add TestWildcardL4RulesIngress and TestWildcardL4RulesEgress
          contrib: Provide script to show unmanaged Kubernetes pods
          workloads: Silence noisy harmless warning
          Bump version in master tree to 1.0.90
          endpoint: Improve logging of endpoint lifecycle events
          tunnel: Add debug messages on tunnel map manipulation
          bpf: Avoid unnecessary debug output on policy map open
          testutils: Factor our random rune generator
          agent: Fix panic when node.GetNodes() is empty
          agent: Fix indentation of loopback address
          kvstore: Introduce shared store type
          store: Cast event.Value to string
          policy: Overwrite eventual L4 localhost policies when AllowLocalhost=true
          Update NEWS
          Prepare for 1.1.0-rc1
          Merge branch 'master' into v1.1
          Prepare for 1.1.0-rc2 release
          identity: Ignore nil identity when generating IdentityCache
          Documentation: Fix warnings
          identity: Resolve unknown identity to label reserved:unknown
          defaults: Move defaults into pkg/defaults
          agent: Add --ipv6-cluster-alloc-cidr option to specify IPv6 cluster prefix
          agent: Reserve existing endpoint IPs before allocating auxiliary IPs
          identity: Make API resilient if allocator is not initialized yet
          node: Undo default IPv6 prefix change
          Merge branch 'master' into v1.1
          Prepare 1.1.0-rc3 release
          Merge branch 'master' into v1.1
          Prepare for 1.1.0-rc3 release #2
          agent: Correctly restore router IPs from cilium_host interface
          Merge branch 'master' into v1.1
          Preparae for 1.1.0-rc3 #3
          test: Be verbose about VM provision failures
          bpf: Separate conntrack timeouts for TCP and non-TCP
          conntrack: Increase conntrack interval to 1 minute
          doc: Add missing indices to spelling list
          allocator: Use DefaultLogger
          test: Print status message while building & installing cilium
          test: Do not compile non container build with PKG_BUILD=1
          byteorder: Do not depend on external Linux only library
          test: Hardcode identity for health endpoint
          maps/tunnel: Use DefaultLogger
          tunnel: Make BPF tunnel map updates atomic
          k8s: Add --k8s-require-ipv4-pod-cidr and --k8s-require-ipv6-pod-cidr option
          test: Require IPv4 PodCIDR to be specified in the node resource
          Merge branch 'master' into v1.1
          bpffs: Fix panic when root directory does not exist
          Merge branch 'master' into v1.1
          Prepare for 1.1.0-rc4 release
          test: Wait for DNS entry of kafka and zookeeper service
          kubernetes: Fix generation of DaemonSet files to include v image tag prefix
          Merge branch 'master' into v1.1
          kubernetes: Fix image tag references
          k8s: Updated LastUpdated after waiting for endpoint status
          metrics: Correctly abort on errors and check for Payload to be non-nil
          metrics: Fail with Fatal() when client creation fails
          metrics: Check IPAM field for nil
          kubernetes: Add missing parenthesis to only fail on invalid version
          k8s: Represent ServiceAccountName as endpoint label
          test: ServiceAccount integration tests
          doc: Add documentation and example for service account matching
          doc: Document exposing pods across namespaces
          allocator: Increase allocator list timeout to 2 minutes
          Merge branch 'master' into v1.1
          Merge branch 'master' into v1.1
          docker/Dockerfile: update golang to 1.10.2
          doc: Document k8s troubleshooting scripts
          doc: Restructure troubleshooting section
          doc: Provide egress example to kube-dns across namespaces
          test: Use latest stable etcd and consul images
          allocator: benchmark: Reserve ID space for reserved identities
          trigger: New trigger package
          identity: Process identity events in batches
          identity: Fix allocator init with more than pre-existing 1024 keys
          allocator: Avoid scanning sequentual list when allocating
          Prepare for 1.1.0 release
          AUTHORS: Update to latest list
          allocator: Re-use randomly generated ID sequence between allocations
          cni: Change default configuration filename to 00-cilium.conf
          agent: Require go 1.10 for safe namespace operations
          identity: Move CIDR identity code into pkg/identity/cidr
          k8s: Simplify EndpointSelector creation in tests
          NEWS: Update after latest backports

    Tobias Klauser (1):
          pkg/bpf: update BPF_* constants as of Linux kernel 4.17-rc3

    ackerman80 (3):
          Update minikube.rst
          examples/minikube: update http-sw-app.yaml
          examples/minikube: delete unused yamls

    
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
.. _4936: https://github.com/cilium/cilium/pull/4936
.. _4854: https://github.com/cilium/cilium/pull/4854
.. _4826: https://github.com/cilium/cilium/pull/4826
.. _4775: https://github.com/cilium/cilium/pull/4775
.. _4750: https://github.com/cilium/cilium/pull/4750
.. _4738: https://github.com/cilium/cilium/pull/4738
.. _4732: https://github.com/cilium/cilium/pull/4732
.. _4731: https://github.com/cilium/cilium/pull/4731
.. _4687: https://github.com/cilium/cilium/pull/4687
.. _4664: https://github.com/cilium/cilium/pull/4664
.. _4547: https://github.com/cilium/cilium/pull/4547
.. _4270: https://github.com/cilium/cilium/pull/4270
.. _5024: https://github.com/cilium/cilium/pull/5024
.. _5019: https://github.com/cilium/cilium/pull/5019
.. _4945: https://github.com/cilium/cilium/pull/4945
.. _4910: https://github.com/cilium/cilium/pull/4910
.. _4909: https://github.com/cilium/cilium/pull/4909
.. _4889: https://github.com/cilium/cilium/pull/4889
.. _4888: https://github.com/cilium/cilium/pull/4888
.. _4846: https://github.com/cilium/cilium/pull/4846
.. _4840: https://github.com/cilium/cilium/pull/4840
.. _4830: https://github.com/cilium/cilium/pull/4830
.. _4799: https://github.com/cilium/cilium/pull/4799
.. _4788: https://github.com/cilium/cilium/pull/4788
.. _4773: https://github.com/cilium/cilium/pull/4773
.. _4756: https://github.com/cilium/cilium/pull/4756
.. _4753: https://github.com/cilium/cilium/pull/4753
.. _4739: https://github.com/cilium/cilium/pull/4739
.. _4709: https://github.com/cilium/cilium/pull/4709
.. _4683: https://github.com/cilium/cilium/pull/4683
.. _4682: https://github.com/cilium/cilium/pull/4682
.. _4678: https://github.com/cilium/cilium/pull/4678
.. _4676: https://github.com/cilium/cilium/pull/4676
.. _4670: https://github.com/cilium/cilium/pull/4670
.. _4667: https://github.com/cilium/cilium/pull/4667
.. _4636: https://github.com/cilium/cilium/pull/4636
.. _4623: https://github.com/cilium/cilium/pull/4623
.. _4611: https://github.com/cilium/cilium/pull/4611
.. _4610: https://github.com/cilium/cilium/pull/4610
.. _4587: https://github.com/cilium/cilium/pull/4587
.. _4561: https://github.com/cilium/cilium/pull/4561
.. _4934: https://github.com/cilium/cilium/pull/4934
.. _4877: https://github.com/cilium/cilium/pull/4877
.. _4874: https://github.com/cilium/cilium/pull/4874
.. _4867: https://github.com/cilium/cilium/pull/4867
.. _4858: https://github.com/cilium/cilium/pull/4858
.. _4828: https://github.com/cilium/cilium/pull/4828
.. _4805: https://github.com/cilium/cilium/pull/4805
.. _4797: https://github.com/cilium/cilium/pull/4797
.. _4790: https://github.com/cilium/cilium/pull/4790
.. _4756: https://github.com/cilium/cilium/pull/4756
.. _4730: https://github.com/cilium/cilium/pull/4730
.. _4725: https://github.com/cilium/cilium/pull/4725
.. _4699: https://github.com/cilium/cilium/pull/4699
.. _4690: https://github.com/cilium/cilium/pull/4690
.. _4684: https://github.com/cilium/cilium/pull/4684
.. _4671: https://github.com/cilium/cilium/pull/4671
.. _4665: https://github.com/cilium/cilium/pull/4665
.. _4599: https://github.com/cilium/cilium/pull/4599
.. _4593: https://github.com/cilium/cilium/pull/4593
.. _4548: https://github.com/cilium/cilium/pull/4548
.. _4518: https://github.com/cilium/cilium/pull/4518
.. _4507: https://github.com/cilium/cilium/pull/4507
.. _4488: https://github.com/cilium/cilium/pull/4488
.. _4376: https://github.com/cilium/cilium/pull/4376
.. _2972: https://github.com/cilium/cilium/pull/2972
