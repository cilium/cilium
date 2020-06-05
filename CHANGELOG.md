# Changelog

## v1.6.9

Summary of Changes
------------------

**Minor Changes:**
* Add "--iptables-lock-timeout" to configure iptables --wait parameter (Backport PR #11883, Upstream PR #11701, @joestringer)
* bump k8s dependencies and test to v1.16.9 (#11045, @aanm)
* bump k8s dependencies to v1.15.12 and v1.16.10 (#11681, @aanm)
* Properly tear down gops agent on shutdown (Backport PR #11883, Upstream PR #11471, @tklauser)
* Support DNS matchPattern="*" to match "." (Backport PR #11883, Upstream PR #11633, @joestringer)

**Bugfixes:**
* `identity does not exist` warning messages are not logged if the allocation attempt is not at max (Backport PR #11883, Upstream PR #11580, @djboris9)
* Avoid duplication of generated toCIDRs when using a toServices based CNP (or CCNP) (#11900, @aanm)
* bpf: Preserve source identity for hairpin via stack (Backport PR #11496, Upstream PR #10926, @tgraf)
* CRD: fix allocation logic of identities with the same set of labels (Backport PR #11411, Upstream PR #11040, @aanm)
* daemon: Fatal on startup when Identity CRD is enabled without k8s (Backport PR #11266, Upstream PR #11015, @raybejjani)
* datapath/iptables: Masquerade hairpin traffic that traversed the stack (Backport PR #11496, Upstream PR #10928, @tgraf)
* Do not depend on `KUBERNETES_SERVICE_HOST` nor `KUBERNETES_SERVICE_PORT` environment variables to detect if cilium is running in k8s mode (Backport PR #11266, Upstream PR #11021, @aanm)
* endpoint: Avoid transient drops during policy map update (Backport PR #11266, Upstream PR #10936, @jrajahalme)
* envoy: Take xds mutator lock for map access (Backport PR #11883, Upstream PR #11541, @jrajahalme)
* etcd: Increase status check timeout to 10 seconds (Backport PR #11883, Upstream PR #11750, @tgraf)
* Fix issue where traffic from a pod could be dropped despite allow policy when DNS L7 rules are used (Backport PR #11883, Upstream PR #11764, @joestringer)
* Fix leaking endpoint state metric (Backport PR #11933, Upstream PR #11884, @christarazi)
* Fix possible endpoint restore failure in CRD mode. (Backport PR #11266, Upstream PR #10785, @aanm)
* k8s: Defer marking node as ready to just API is served (Backport PR #11266, Upstream PR #10767, @tgraf)
* k8s: Do not send DeleteService event upon DeleteEndpoints (Backport PR #11496, Upstream PR #11467, @brb)
* Log more information for error 'Unable update CRD identity information with a reference for this node' (Backport PR #11266, Upstream PR #10923, @aanm)
* proxy: Do not decrement proxy port reference count when reverting. (Backport PR #11883, Upstream PR #11753, @jrajahalme)
* proxy: Keep DNS port allocated (Backport PR #11662, Upstream PR #11661, @jrajahalme)
* Setting the agent.sleepAfterInit helm chart value to True will correctly configure the agent to sleep after Init (Backport PR #11429, Upstream PR #11203, @seanmwinn)
* Tight CNP and CCNP schema validation for badly formatted policies (yaml or json) (Backport PR #11411, Upstream PR #10727, @aanm)

**CI Changes:**
* CI: K8sKafkaPolicyTest kafka-broker starts up without errors (Backport PR #10761, Upstream PR #10721, @raybejjani)

**Misc Changes:**
* [v1.6] Dockerfile: Bump cilium-runtime to latest image (#11627, @joestringer)
* backporting: add 'upstream-prs' tag for code block (Backport PR #10761, Upstream PR #10033, @aanm)
* bpf: remap MARK_MAGIC_SNAT_DONE marker to avoid conflicts (Backport PR #11496, Upstream PR #11008, @borkmann)
* Fix incorrect name in sysctl_linux_test.go (Backport PR #11266, Upstream PR #10729, @christarazi)
* make: pick up all privileged tests in `make tests-privileged` (Backport PR #10761, Upstream PR #10734, @tklauser)
* Makefile: Fix --yaml arg for microk8s (Backport PR #11883, Upstream PR #10839, @joestringer)
* policy: Fix rule translation test flake (Backport PR #11933, Upstream PR #11913, @joestringer)
* proxy: release redir.mutex on early exit, update a comment on mutex use (Backport PR #11883, Upstream PR #11666, @qmonnet)
* Retry on conflicts when creating/updating CiliumNode objects on agent startup (Backport PR #11908, Upstream PR #11673, @ashrayjain)

# v1.6.8

Summary of Changes
------------------

**Minor Changes:**
* Add option to retrieve pprof traces from running cilium-agents (Backport PR #10684, Upstream PR #10666, @aanm)
* Update k8s libraries to 1.16.8 (#10662, @aanm)

**Bugfixes:**
* Fix issue where lxc_config.h header disappears after some regenerations (Backport PR #10640, Upstream PR #10630, @joestringer)
* kubernetes: do not set enable-endpoint-health-checking=false with portmap (Backport PR #10684, Upstream PR #10566, @soumynathan)
* policy: Keep NameManager locked during SelectorCache operations (Backport PR #10532, Upstream PR #10501, @jrajahalme)

**CI Changes:**
* [CI] Replace jenkinsfiles with symlinks (Backport PR #10460, Upstream PR #10262, @nebril)
* test: Fix possible race in waitForNPods helper function (Backport PR #10499, Upstream PR #10481, @brb)
* update: fix preflight step in upgrade test (#10472, @aanm)

**Misc Changes:**
* Adds details about required kernel versions above 4.9.17, supported OS update (Backport PR #10684, Upstream PR #10537, @seanmwinn)
* Istio integration has been updated to Istio release 1.4.6 (#10469, @jrajahalme)
* test: Avoid using global map for Cilium configuration (Backport PR #10460, Upstream PR #10388, @brb)

# v1.6.7

Summary of Changes
------------------

**Minor Changes:**
* add option to hold cilium agent after init container (Backport PR #10135, Upstream PR #10101, @aanm)
* Do not listen on any port by default for cilium-operator (#10369, @aanm)
* Fallback mode for a missing `xt_socket` kernel module is added where kernel's IP early demux functionality is disabled. This fallback is enabled by default if it is needed for corre
ct policy enforcement and visibility functionality. This fallback may be disabled by setting `enable-xt-socket-fallback=false`. (Backport PR #10361, Upstream PR #10299, @jrajahalme)
* ServiceMonitor should default to release namespace (Backport PR #10135, Upstream PR #10088, @dsexton)

**Bugfixes:**
* AKS: Fix dynamic reconfiguration of bridge mode (Backport PR #10379, Upstream PR #10383, @tgraf)
* bpf: Fix proxy redirection for egress programs (Backport PR #10223, Upstream PR #10113, @tgraf)
* cilium: only enable IPv6 forwarding if IPv6 is enabled (Backport PR #10135, Upstream PR #9034, @jrfastab)
* Correct clustermesh identity sync kvstore backend usage (to actually use the remote) (Backport PR #10223, Upstream PR #10185, @raybejjani)
* doc: Fix AKS guide regression (Backport PR #10379, Upstream PR #10308, @tgraf)
* Envoy fixes for CVE-2020-8659, CVE-2020-8660, CVE-2020-8661, CVE-2020-8664 (Backport PR #10443, Upstream PR #10434, @jrajahalme)
* etcd: Fix gRPC load balancer issue (Backport PR #10379, Upstream PR #10381, @tgraf)
* Fix cilium-operator deadlock for clusters with more than 128 services (Backport PR #10127, Upstream PR #10010, @aanm)
* Fix concurrent access of a variable used for metrics (Backport PR #10223, Upstream PR #10137, @aanm)
* Fix memory corruption on clusters with IPv6 and NodePort enabled (Backport PR #10223, Upstream PR #10192, @aanm)
* Fix regression to avoid freeing alive IPs (Backport PR #10237, Upstream PR #10207, @tgraf)
* Fixups for Correct clustermesh identity sync kvstore backend usage (Backport PR #10291, Upstream PR #10243, @raybejjani)
* ipam: Protect release from releasing alive IP (Backport PR #10095, Upstream PR #10066, @tgraf)
* ipcache: Add probe to check for dump capability to support delete (Backport PR #10223, Upstream PR #10144, @tgraf)
* Make cilium bpf {ct, nat} {list, flush} to work when running in ipv6-only mode (Backport PR #10291, Upstream PR #10193, @brb)
* node: Remove permanent ARP entry when remote node is deleted (Backport PR #10361, Upstream PR #10227, @brb)
* pkg/bpf: Protect attr in perf_linux.go with runtime.KeepAlive (#10206, @brb)
* pkg/bpf: Protect each uintptr with runtime.KeepAlive (Backport PR #10267, Upstream PR #10168, @brb)
* pkg/endpoint: access endpoint state safely across go routines (Backport PR #10223, Upstream PR #10140, @aanm)
* policy: fix innermap's flag error in eppolicymap (Backport PR #10291, Upstream PR #10201, @zhiyuan0x)

**CI Changes:**
* test: Wait for Istio POD termination before deleting istio-system or cilium (Backport PR #10361, Upstream PR #10325, @jrajahalme)

**Misc Changes:**
* bpf: Fix space hack in Makefile (Backport PR #10223, Upstream PR #10173, @brb)
* bpf: remove unused GetProgNextID, GetProgFDByID and GetProgInfoByFD (Backport PR #10267, Upstream PR #10187, @tklauser)
* bugtool: Dump NAT BPF maps entries with bpftool (Backport PR #10223, Upstream PR #10190, @brb)
* charts: Generate versions from VERSION file (Backport PR #10223, Upstream PR #10171, @joestringer)
* doc: Adjust documentation to renamed cilium-sysdump tool (Backport PR #10361, Upstream PR #10165, @tgraf)
* doc: Document L7 limitation in azure-cni chaining mode (Backport PR #10223, Upstream PR #10131, @tgraf)
* doc: Fix links to contributing guide (Backport PR #10361, Upstream PR #10322, @CybrPunk)
* docs: fix link for Cilium-PR-Kubernetes-Upstream job (Backport PR #10223, Upstream PR #10178, @tklauser)
* Documentation: Lock dependency to fix build (Backport PR #10438, Upstream PR #10419, @Ropes)
* Fix dead link in 1.4->1.5 upgrade documentation (Backport PR #10443, Upstream PR #10416, @Ropes)
* fqdn: Avoid races when updating global cache on GC (Backport PR #10443, Upstream PR #9483, @raybejjani)
* golang: update to 1.12.17 (#10210, @aanm)
* helm: Allow disabling xt_socket fallback (Backport PR #10361, Upstream PR #10342, @brb)
* install: Support generating vX.Y-dev charts (Backport PR #10361, Upstream PR #10355, @joestringer)
* pkg/bpf: Fix KeepAlive usage for pathStr (Backport PR #10361, Upstream PR #10288, @brb)
* Update release process steps (Backport PR #10135, Upstream PR #10035, @aanm)
* Use -F flag in git log in check-stable script (Backport PR #10291, Upstream PR #10283, @nebril)

**Other Changes:**
* .github: update github-actions project (#10045, @aanm)
* [1.6] Fix CRI-O regression in the tree (#10412, @joestringer)
* [v1.6] wip run with race detector (#10130, @aanm)
* update k8s dependencies to 1.16.7 (#10216, @aanm)

# v1.6.6

Summary of Changes
------------------

**Minor Changes:**
* golang: update to 1.12.15 (#9874, @aanm)
* golang: update to 1.12.16 (#9987, @aanm)

**Bugfixes:**
* Fix to allocate a global identity for an empty container label-set. (Backport PR #9827, Upstream PR #9821, @borkmann)
* Enable IP forwarding on daemon start (Backport PR #9841, Upstream PR #8954, @mrostecki)
* eni: Fix releases of excess IPs (Backport PR #9962, Upstream PR #9858, @tgraf)
* cni: Fix IP leak when CNI ADD times out (Backport PR #9962, Upstream PR #9913, @tgraf)
* cni: Fix noisy warning "Unknown CNI chaining configuration" (Backport PR #9962, Upstream PR #9937, @tgraf)
* Fix cilium installation in GCloud beta "rapid" channel (Backport PR #10007, Upstream PR #9959, @joestringer)
* garbage collect stale distributed locks (Backport PR #10007, Upstream PR #9982, @aanm)
* fqdn: Support setting tofqdns-min-ttl to 0 (Backport PR #9753, Upstream PR #9743, @raybejjani)

**Misc Changes:**
* Add missing words to spelling_wordlist (Backport PR #9753, Upstream PR #9643, @ungureanuvladvictor)
* Fix GC Locks bugs (Backport PR #10007, Upstream PR #10005, @aanm)
* nodeinit/templates: fix indentation of sys-fs-bpf (Backport PR #10024, Upstream PR #10008, @aanm)
* v1.6: install: Update the chart versions (#9788, @joestringer)

**Other Changes:**
* update k8s tested versions to v1.14.10, v1.15.7 and v1.16.4 (#9870, @aanm)
* .github: Update actions to v1.6.6 project (#9775, @joestringer)
* Fix github actions 1.6 (#9781, @aanm)
