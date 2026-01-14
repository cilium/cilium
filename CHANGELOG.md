# Changelog

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

