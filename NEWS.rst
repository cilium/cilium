******
NEWS
******

Version 1.0-rc2
===============

:date: 2017-12-04
:commit: nil

Major Changes
-------------

* Tech preview of Envoy as Cilium HTTP proxy, adding HTTP2 and gRPC support. (#1580, @jrajahalme)
* Introduce "cilium-health", a new tool for investigating cluster connectivity issues. (#2052, @joestringer)
* cilium-agent collects and serves prometheus metrics (#2127, @raybejjani)
* bugtool and debuginfo (#2044, @scanf)
* Add nightly test infrastructure (#2212, @ianvernon)
* Separate ingress and egress default deny modes with better control (#2156, @manalibhutiyani)
* k8s: add support for IPBlock and Egress Rules with IPBlock (#2096, @ianvernon)
* Kafka: Support access logging for Kafka requests/responses (#1870, @manalibhutiyani)
* Added cilium endpoint log command that returns the endpoint's status log (#2060, @raybejjani)
    * Change endpoint status log in cilium endpoint get to show only the most recent log
* Routes connecting the host to the Cilium IP space is now implemented as
  individual route for each node in the cluster. This allows to assign IPs
  which are part of the cluster CIDR to endpoints outside of the cluster
  as long as the IPs are never used as node CIDRs. (#1888, @tgraf)
* Standardized structured logging (#1801, #1828, #1836, #1826, #1833, #1834, #1827, #1829, #1832, #1835, @raybejjani)

Bugfixes Changes
----------------

* Fix L4Filter JSON marshalling (#1871, @joestringer)
* Fix swapped src dst IPs on Conntrack related messages on the monitor's output (#2228, @aanm)
* Fix output of cilium endpoint list for endpoints using multiple labels. (#2225, @aanm)
* bpf: fix verifier error in dameon debug mode with newer LLVM versions (#2181, @borkmann)
* pkg/kvstore: fixed race in internal mutex map (#2179, @aanm)
* Proxy ingress policy fix for LLVM 4.0 and greater. Resolves return code 500 'Internal Error' seen with some policies and traffic patterns. (#2162, @jrfastab)
* Printing patch clang and kernel patch versions when starting cilium. (#2137, @aanm)
* Clean up Connection Tracking entries when a new policy no longer allows it. #1667, #1823 (#2136, @aanm)
* k8s: fix data race in d.loadBalancer.K8sEndpoints (#2129, @aanm)
* Add internal queue for k8s watcher updates #1966 (#2123, @aanm)
* k8s: fix missing deep copy when updating status (#2115, @aanm)
* Accept traffic to Cilium in FORWARD chain (#2112, @tgraf)
    * Also clear the masquerade bit in the FORWARD chain to skip the masquerade rule installed by kube-proxy
* Fix SNAT issue in combination with kube-proxy, when masquerade rule installed by kube-proxy takes precedence over rule installed by Cilium. (#2108, @tgraf)
* Fixed infinite loop when importing CNP to kubernetes with an empty kafka version (#2090, @aanm)
* Mark cilium pod as CriticalPod in the DaemonSet (#2024, @manalibhutiyani)
* proxy: Provide identities { host | world | cluster } in SourceEndpoint (#2022, @manalibhutiyani)
* In kubernetes mode, fixed bug that was allowing cilium to start up even if the kubernetes api-server was not reachable #1973 (#2014, @aanm)
* Support policy with EndpointSelector missing (#1987, @raybejjani)
* Implemented deep copy functionality when receiving events from kubernetes watcher #1885 (#1986, @aanm)
* pkg/labels: Filter out pod-template-generation label (#1979, @michi-covalent)
* bpf: Double timeout on building BPF programs (#1949, @raybejjani)
* policy: add PolicyTrace msg to AllowsRLocked() when L4 policies not evaluated (#1939, @gnahckire)
* Handle Kafka responses correctly (#1924, @manalibhutiyani)
* bpf: Avoid excessive proxymap updates (#2210, @joestringer)
* cilium-agent correctly restarts listening for CiliumNetworkPolicy changes when it sees decoding errors (#1899, @raybejjani)

Other Changes
-------------

* Automatically generate command reference of agent (#2223, @tgraf)
* Access log rotation support with backup compression and automatic deletion support. (#1995, @manalibhutiyani)
* kubernetes examples support prometheus metrics scraping (along with sample prometheus configuration) (#2192, @raybejjani)
* Start serving the cilium API almost immediately while restoring endpoints on the background. (#2116, @aanm)
* Added cilium endpoint healthz command that returns a summary of the endpoint's health (#2099, @raybejjani)
* Documentation: add a CLI reference section (#2079, @scanf)
* Documentation: add support for tabs via plugin (#2078, @scanf)
* Feature Request: Add option to disable loadbalancing  (#2048, @manalibhutiyani)
* monitor: reduce overhead (#2037, @scanf)
* Use auto-generated client to communicate with kube-apiserver (#2007, @aanm)
* Documented kubernetes API Group usage in docs (#1989, @raybejjani)
    * cilium status returns which kubernetes API Groups are supported/used by the agent
* doc: Add Kafka policy documentation (#1970, @tgraf)
* Add Pull request and issue template (#1951, @tgraf)
* Update Vagrant images to ubuntu 17.04 for the getting started guides (#1917, @aanm)
* Add CONTRIBUTING.md (#1898, @tgraf)
* Introduction of release notes gathering script in use by the Kubernetes project (#1893, @tgraf)
* node: Install individual per node routes (#1888, @tgraf)
* Add CLI for dumping BPF endpoint map (lxcmap) (#1854, @joestringer)
* add command for resetting agent state (#1678, @scanf)
* Improved CI testing infrastructure and fixed several test flakes (#1848, #1865)
* Foundation of new Ginkgo build-driven-development framework for CI (#1733)

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
