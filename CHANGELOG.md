# Changelog

## v1.19.0-rc.1

Summary of Changes
------------------

**Minor Changes:**
* auth: Disable by default (Backport PR cilium/cilium#44003, Upstream PR cilium/cilium#42665, @christarazi)
* Exclude topology.kubernetes.io labels from security labels by default (Backport PR cilium/cilium#43780, Upstream PR cilium/cilium#43725, @moscicky)
* hubble-relay: Add `hubble.relay.logOptions.format` and `hubble.relay.logOptions.level` Helm values to configure log format (text, text-ts, json, json-ts) and level (debug, info, warn, error) (Backport PR cilium/cilium#44003, Upstream PR cilium/cilium#43644, @puwun)
* Split selector cache to reduce cpu usage and reduce lock contention in the selector cache (Backport PR cilium/cilium#44025, Upstream PR cilium/cilium#42580, @odinuge)

**Bugfixes:**
* Add support for specifying plpmtud (mtu discovery) settings for Pod endpoints, with the default now being "1" (blackhole-detected). (Backport PR cilium/cilium#44025, Upstream PR cilium/cilium#43710, @tommyp1ckles)
* bpf: Correct refinement of inner packet L4 checksum detection (Backport PR cilium/cilium#43922, Upstream PR cilium/cilium#43868, @br4243)
* bpf: Fix marker to skip nodeport when punting to proxy (Backport PR cilium/cilium#43866, Upstream PR cilium/cilium#43069, @borkmann)
* clustermesh: correctly phase out not ready/not service endpoints from global services (Backport PR cilium/cilium#44025, Upstream PR cilium/cilium#43807, @MrFreezeex)
* endpoint/manager: wait for completed endpoint restoration before starting periodic GC & regeneration controllers (Backport PR cilium/cilium#43866, Upstream PR cilium/cilium#43776, @mhofstetter)
* endpoint/mgr: don't register periodic regeneration if interval is 0 (Backport PR cilium/cilium#43866, Upstream PR cilium/cilium#43790, @mhofstetter)
* Fix a bug where removed addresses from EndpointSlices might be missed if multiple EndpointSlices share the same name (Backport PR cilium/cilium#44025, Upstream PR cilium/cilium#43999, @EmilyShepherd)
* fix: incorrect schema entries for cpu limits (Backport PR cilium/cilium#43780, Upstream PR cilium/cilium#43735, @jcpunk)
* gateway api: fix for multiple listeners on a gateway check (Backport PR cilium/cilium#43922, Upstream PR cilium/cilium#43802, @xtineskim)
* Hubble Export FieldMask - Introduce functionality to specify multiple 'oneof' variants like l4.TCP/l4.UDP Hubble Export Aggregation - Enrich aggregated flow logs with timestamp to preserve temporal context (Backport PR cilium/cilium#44003, Upstream PR cilium/cilium#43924, @mereta)
* Make BIG TCP initialization flow more robust and fix bugs. (Backport PR cilium/cilium#44025, Upstream PR cilium/cilium#43891, @gentoo-root)

**CI Changes:**
* .github/ariane-config: schedule runs on conformance-ipsec.yaml (Backport PR cilium/cilium#44003, Upstream PR cilium/cilium#43907, @aanm)
* .github/workflows: k8s-kind-network-e2e: add shorter timeout (Backport PR cilium/cilium#43922, Upstream PR cilium/cilium#43908, @aanm)
* .github/workflows: re-add workflow_dispatch to tests-e2e-upgrade (Backport PR cilium/cilium#43922, Upstream PR cilium/cilium#43906, @aanm)
* ci: fix tests-datapath-verifier on 1.19 (Backport PR cilium/cilium#44003, Upstream PR cilium/cilium#43931, @marseel)
* cyclonus: add higher timeout and retries to avoid flakes (Backport PR cilium/cilium#44003, Upstream PR cilium/cilium#43909, @aanm)
* gateway-api: Skip MeshHTTPRouteMatching to stabilize CI (Backport PR cilium/cilium#44003, Upstream PR cilium/cilium#43890, @joestringer)
* gh: e2e-upgrade: test patch releases (Backport PR cilium/cilium#43751, Upstream PR cilium/cilium#43627, @julianwiedmann)
* gha: let CiliumEndpointSlice migration be run nightly on stable branches (Backport PR cilium/cilium#44003, Upstream PR cilium/cilium#43921, @giorio94)
* gke: lower scope of ESP firewall rule (Backport PR cilium/cilium#43866, Upstream PR cilium/cilium#43691, @marseel)

**Misc Changes:**
* .github/actions: login with cosign to sign helm OCI charts (Backport PR cilium/cilium#43866, Upstream PR cilium/cilium#43782, @aanm)
* bpf: subnet: make subnet map read-only (Backport PR cilium/cilium#44025, Upstream PR cilium/cilium#43948, @julianwiedmann)
* chore(deps): update all github action dependencies (v1.19) (cilium/cilium#43838, @cilium-renovate[bot])
* chore(deps): update all github action dependencies (v1.19) (cilium/cilium#43978, @cilium-renovate[bot])
* chore(deps): update all-dependencies (v1.19) (cilium/cilium#43833, @cilium-renovate[bot])
* chore(deps): update all-dependencies (v1.19) (cilium/cilium#43972, @cilium-renovate[bot])
* chore(deps): update base-images (v1.19) (cilium/cilium#43834, @cilium-renovate[bot])
* chore(deps): update base-images (v1.19) (cilium/cilium#43977, @cilium-renovate[bot])
* chore(deps): update docker.io/library/busybox:1.37.0 docker digest to e226d63 (v1.19) (cilium/cilium#43973, @cilium-renovate[bot])
* chore(deps): update module sigs.k8s.io/kube-api-linter to v0.0.0-20260114104534-18147eee9c49 (v1.19) (cilium/cilium#43835, @cilium-renovate[bot])
* chore(deps): update module sigs.k8s.io/kube-api-linter to v0.0.0-20260123105127-470c3a315f3a (v1.19) (cilium/cilium#43974, @cilium-renovate[bot])
* chore(deps): update quay.io/cilium/cilium-envoy docker tag to v1.35.9-1768610924-2528359430c6adba1ab20fc8396b4effe491ed96 (v1.19) (cilium/cilium#43836, @cilium-renovate[bot])
* chore(deps): update quay.io/cilium/cilium-envoy docker tag to v1.35.9-1768828720-c6e4827ebca9c47af2a3a6540c563c30947bae29 (v1.19) (cilium/cilium#43975, @cilium-renovate[bot])
* chore(deps): update stable lvh-images (v1.19) (patch) (cilium/cilium#43837, @cilium-renovate[bot])
* chore(deps): update stable lvh-images (v1.19) (patch) (cilium/cilium#43976, @cilium-renovate[bot])
* Clarify the upgrade notes for v1.19 (Backport PR cilium/cilium#43957, Upstream PR cilium/cilium#43913, @joestringer)
* clustermesh: add missing reason in mcs condition metrics (Backport PR cilium/cilium#43866, Upstream PR cilium/cilium#43775, @MrFreezeex)
* daemon: fix version for deprecated encryption strict egress mode flags (Backport PR cilium/cilium#43866, Upstream PR cilium/cilium#43731, @rgo3)
* docs(observability): Add tutorial for IP option tracing (Backport PR cilium/cilium#44025, Upstream PR cilium/cilium#43961, @Bigdelle)
* docs: add helm underlayProtocol value to documentation (Backport PR cilium/cilium#44025, Upstream PR cilium/cilium#43934, @aanm)
* docs: add operator prometheus TLS (Backport PR cilium/cilium#44025, Upstream PR cilium/cilium#43997, @phuhung273)
* docs: Add upgrade note about wildcard service entries. (Backport PR cilium/cilium#44025, Upstream PR cilium/cilium#44013, @ajmmm)
* docs: adjust URL to latest stable Hubble CLI version (Backport PR cilium/cilium#43780, Upstream PR cilium/cilium#43745, @tklauser)
* endpoint/restore: introduce metrics (Backport PR cilium/cilium#43866, Upstream PR cilium/cilium#43748, @mhofstetter)
* endpoint/restore: remove special handling for host endpoint in case of ipsec (Backport PR cilium/cilium#43922, Upstream PR cilium/cilium#43757, @mhofstetter)
* Fix BPF IPv6 neighbor discovery code to fully pull in skb data into linear section. (Backport PR cilium/cilium#43922, Upstream PR cilium/cilium#43873, @borkmann)
* install: Quieten noisy build output (Backport PR cilium/cilium#44003, Upstream PR cilium/cilium#43960, @joestringer)

**Other Changes:**
* install: Update image digests for v1.19.0-rc.0 (cilium/cilium#43772, @cilium-release-bot[bot])

## v1.19.0-rc.0

Summary of Changes
------------------

**Major Changes:**
* Publish Helm charts to OCI registries (cilium/cilium#43624, @aanm)

**Minor Changes:**
* Add Strict Mode Ingress Encryption Support for Wireguard (cilium/cilium#39239, @rgo3)
* helm: add SYSLOG capability for Cilium Agent (cilium/cilium#43201, @marseel)
* policy: Mark FromRequires and ToRequires as deprecated (cilium/cilium#43167, @TheBeeZee)
* Remove deprecated `l2-pod-announcements-interface` flag (cilium/cilium#43063, @dylandreimerink)
* renovate: Allow cilium-envoy 1.35.x for v1.18 (cilium/cilium#43623, @sayboras)
* Support BIG TCP in tunneling mode, provided that kernel supports BIG TCP for UDP tunnels. (cilium/cilium#43416, @gentoo-root)

**Bugfixes:**
* bpf:wireguard: delivery host packets to bpf_host for ingress policies (cilium/cilium#42892, @smagnani96)
* Fix an issue in proxy NOTRACK iptables rule for aws-cni chaining mode which causes proxy->upstream(outside cluster) traffic not being SNAT'd. (cilium/cilium#43566, @fristonio)
* Fix bug in LoadBalancer that would cause node connectivity faults if Service LoadBalancer VIPs are allocated with Node-IPAM. (cilium/cilium#43565, @ajmmm)
* Fix ICMP error packet handling by adding the missing checksum recalculation performed during RevNAT for SNATed load-balanced traffic. (cilium/cilium#43196, @yushoyamaguchi)
* fix: incorrect schema entries for cpu limits (cilium/cilium#43735, @jcpunk)
* Fixed a race condition while trying to create per endpoint routes which could result in connectivity issues (cilium/cilium#42915, @dylandreimerink)
* loadbalancer: Fix GetInstancesOfService to avoid removing an endpoint from Service A causes all requests to Service B to fail if the name of Service A is the prefix of Service B (cilium/cilium#43620, @imroc)
* pkg/azure/api : Fixed an issue where public IP assignment would permanently fail on Azure VMSS VMs. (cilium/cilium#43598, @41ks)
* pkg/loadbalancer: further restrict use of wildcard svc entries (cilium/cilium#43721, @ajmmm)
* xds: fix nil-pointer in `processRequestStream` (cilium/cilium#43609, @mhofstetter)

**CI Changes:**
* bgp: Add component test for DefaultGateway auto-discovery (cilium/cilium#43430, @rastislavs)
* bpf: tests: IGMP improvements (cilium/cilium#43684, @julianwiedmann)
* chore: comment job to use generated token instead of PAT (pull_request_target) (cilium/cilium#43655, @sekhar-isovalent)
* ci: Fix CIFuzz build by enabling Go module downloads for dependencies not in vendor directory (cilium/cilium#43504, @puwun)
* ci: fix gke public api endpoint restriction (cilium/cilium#43685, @Artyop)
* conformance-{l3-l4,l7}: add scheduled runs (cilium/cilium#43718, @aanm)
* fix: add get-runner-ip step with error chechking and https url (cilium/cilium#43654, @sekhar-isovalent)
* fix: azure aks apiserver hardening (cilium/cilium#43633, @sekhar-isovalent)
* gh: cilium-config: encryption-strict-egress is also supported for IPsec (cilium/cilium#43634, @julianwiedmann)
* gh: introduce testing with kernel 6.18 (cilium/cilium#43639, @julianwiedmann)

**Misc Changes:**
* .github/workflows: add missing permissions for cosign (cilium/cilium#43715, @aanm)
* .github/workflows: include_conn_disrupt_test_l7_traffic conditionally (cilium/cilium#43724, @aanm)
* .github/workflows: remove leftover files on charts directories (cilium/cilium#43716, @aanm)
* Add OCI-helm documentation (cilium/cilium#43641, @aanm)
* bpf,readme: how to run tests using lvh (cilium/cilium#42570, @viktor-kurchenko)
* bpf: nodeport: evaluate svc hostport check prior to DNAT (cilium/cilium#43611, @julianwiedmann)
* bpf: wireguard: use set_decrypt_mark() (cilium/cilium#43686, @julianwiedmann)
* chore(deps): update all github action dependencies (main) (cilium/cilium#43660, @cilium-renovate[bot])
* chore(deps): update all github action dependencies (main) (cilium/cilium#43682, @cilium-renovate[bot])
* chore(deps): update all lvh-images main (main) (patch) (cilium/cilium#43657, @cilium-renovate[bot])
* chore(deps): update all-dependencies (main) (cilium/cilium#43700, @cilium-renovate[bot])
* chore(deps): update base-images (main) (cilium/cilium#43659, @cilium-renovate[bot])
* chore(deps): update module sigs.k8s.io/kube-api-linter to v0.0.0-20260109151746-62264808e5f3 (main) (cilium/cilium#43658, @cilium-renovate[bot])
* chore(deps): update quay.io/cilium/cilium-envoy docker tag to v1.35.9-1767794330-db497dd19e346b39d81d7b5c0dedf6c812bcc5c9 (main) (cilium/cilium#43637, @cilium-renovate[bot])
* ci: bump eks cluster pool cleanup timeout (cilium/cilium#43733, @Artyop)
* CODEOWNERS: add missing codeowners entries (cilium/cilium#43692, @aanm)
* CODEOWNERS: fine-tune sig-datapath ownership (cilium/cilium#42959, @julianwiedmann)
* docs: add ztunnel documentation page (cilium/cilium#42819, @rgo3)
* Enable renovate to manage `Documentation` requirements (cilium/cilium#43433, @HadrienPatte)
* fix(deps): update all go dependencies main (main) (cilium/cilium#43661, @cilium-renovate[bot])
* fix: update helm lint to only look for yaml files in examples/crds (cilium/cilium#43616, @sekhar-isovalent)
* Improve crdcheck tool performance and error handling (cilium/cilium#43590, @noexecstack)
* lb: Do not populate NodePort Frontends if KPR is disabled (cilium/cilium#43599, @rastislavs)
* node/address: don't use global functions in each other (cilium/cilium#43621, @mhofstetter)
* node: remove node.GetNodeAddressing (cilium/cilium#43482, @mhofstetter)
* node: remove unnecessary test setup with `SetTestLocalNodeStore` (cilium/cilium#43601, @mhofstetter)
* Policy pass fixes (cilium/cilium#43589, @jrajahalme)
* Prepare for release v1.19.0-pre.4 (cilium/cilium#43596, @cilium-release-bot[bot])
* Prepare for v1.20 development cycle (cilium/cilium#43706, @joestringer)
* Prepare v1.19 stable branch (cilium/cilium#43709, @joestringer)
* proxy/accesslogger: use `LocalNodeStore` to retrieve node IPs (cilium/cilium#43600, @mhofstetter)
* README: Update releases (cilium/cilium#43604, @aanm)
* README: Update releases (cilium/cilium#43736, @jrajahalme)
* release: change OCI registry (cilium/cilium#43646, @aanm)
* renovate: Allow cilium-envoy minor upgrade for stable branches (cilium/cilium#43640, @sayboras)
* renovate: Fix python dependency updates (cilium/cilium#43695, @HadrienPatte)
* Replace Index{,Byte} with Cut,Contains (cilium/cilium#43708, @joestringer)
* Updating USERS.md to include Celonis (cilium/cilium#43740, @tchellomello)
* v1.19 branch fixes (cilium/cilium#43764, @aanm)
* workflows: Add id-token permission to call-publish-helm job (cilium/cilium#43717, @aanm)

