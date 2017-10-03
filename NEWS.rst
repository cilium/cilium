****
NEWS
****

HEAD
====

Bug Fixes
---------
* Fixed issue where L4 policy trace would incorrectly determine that traffic
  would be rejected when the L4 policy specifies the protocol (1587_)
* Synchronization of compilation of base and endpoint programs (1440_)

Features
--------
* Add bash code completion (1597_)
* L7 logging records now include additional information about the identity of
  the destination when outside of the cluster (1615_)
* Default policy enforcement behavior for non-Kubernetes environments is now
  the same as for Kubernetes environments; traffic is allowed by default until
  a rule selects an endpoint (1464_)

CI
__
* Improved CI testing infrastructure (1632_, 1624_, 1455_, 1441_, 1435_)

Kubernetes
----------
* Add here

Mesos
-----
* Add here

Documentation
-------------
* Policy enforcement mode documentation (1464_)

Other
-----
* Add new --pprof flag to serve the pprof API (1646_)
* New builtin deadlock detection for developers. Enable this in Makefile.defs. (1648_)
* Update Sirupsen/logrus to sirupsen/logrus (1573_)
* Refactor pod annotation logic (1468_)

0.11
====

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


0.10
====

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
----
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

0.9.0
=====

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
-----

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


0.8.0
=====

- First initial release

.. _424: https://github.com/cilium/cilium/pull/424
.. _474: https://github.com/cilium/cilium/pull/474
.. _499: https://github.com/cilium/cilium/pull/499
.. _503: https://github.com/cilium/cilium/pull/503
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
.. _886: https://github.com/cilium/cilium/pull/886
.. _1013: https://github.com/cilium/cilium/pull/1013
.. _1039: https://github.com/cilium/cilium/pull/1039
.. _1094: https://github.com/cilium/cilium/pull/1094
.. _1112: https://github.com/cilium/cilium/pull/1112
.. _1115: https://github.com/cilium/cilium/pull/1115
.. _1139: https://github.com/cilium/cilium/pull/1139
.. _905: https://github.com/cilium/cilium/pull/905
.. _1126: https://github.com/cilium/cilium/pull/1126
.. _1150: https://github.com/cilium/cilium/pull/1150
.. _1103: https://github.com/cilium/cilium/pull/1103
.. _1055: https://github.com/cilium/cilium/pull/1055
.. _1036: https://github.com/cilium/cilium/pull/1036
.. _1075: https://github.com/cilium/cilium/pull/1075
.. _1026: https://github.com/cilium/cilium/pull/1026
.. _860: https://github.com/cilium/cilium/pull/860
.. _871: https://github.com/cilium/cilium/pull/871
.. _873: https://github.com/cilium/cilium/pull/873
.. _875: https://github.com/cilium/cilium/pull/875
.. _1098: https://github.com/cilium/cilium/pull/1098
.. _925: https://github.com/cilium/cilium/pull/925
.. _938: https://github.com/cilium/cilium/pull/938
.. _932: https://github.com/cilium/cilium/pull/932
.. _1090: https://github.com/cilium/cilium/pull/1090
.. _1121: https://github.com/cilium/cilium/pull/1121
.. _894: https://github.com/cilium/cilium/pull/894
.. _1108: https://github.com/cilium/cilium/pull/1108
.. _896: https://github.com/cilium/cilium/pull/896
.. _980: https://github.com/cilium/cilium/pull/980
.. _982: https://github.com/cilium/cilium/pull/982
.. _1017: https://github.com/cilium/cilium/pull/1017
.. _1045: https://github.com/cilium/cilium/pull/1045
.. _1075: https://github.com/cilium/cilium/pull/1075
.. _912: https://github.com/cilium/cilium/pull/912
.. _918: https://github.com/cilium/cilium/pull/918
.. _964: https://github.com/cilium/cilium/pull/964
.. _973: https://github.com/cilium/cilium/pull/973
.. _991: https://github.com/cilium/cilium/pull/991
.. _998: https://github.com/cilium/cilium/pull/998
.. _1002: https://github.com/cilium/cilium/pull/1002
.. _934: https://github.com/cilium/cilium/pull/934
.. _959: https://github.com/cilium/cilium/pull/959
.. _975: https://github.com/cilium/cilium/pull/975
.. _985: https://github.com/cilium/cilium/pull/985
.. _1003: https://github.com/cilium/cilium/pull/1003
.. _1018: https://github.com/cilium/cilium/pull/1018
.. _990: https://github.com/cilium/cilium/pull/990
.. _1080: https://github.com/cilium/cilium/pull/1080
.. _1088: https://github.com/cilium/cilium/pull/1088
.. _1114: https://github.com/cilium/cilium/pull/1114
.. _911: https://github.com/cilium/cilium/pull/911
.. _794: https://github.com/cilium/cilium/pull/794
.. _874: https://github.com/cilium/cilium/pull/874
.. _881: https://github.com/cilium/cilium/pull/881
.. _888: https://github.com/cilium/cilium/pull/888
.. _892: https://github.com/cilium/cilium/pull/892
.. _1011: https://github.com/cilium/cilium/pull/1011
.. _1020: https://github.com/cilium/cilium/pull/1020
.. _1027: https://github.com/cilium/cilium/pull/1027
.. _1122: https://github.com/cilium/cilium/pull/1122
.. _1135: https://github.com/cilium/cilium/pull/1135
.. _1175: https://github.com/cilium/cilium/pull/1175
.. _1227: https://github.com/cilium/cilium/pull/1227
.. _1244: https://github.com/cilium/cilium/pull/1244
.. _1246: https://github.com/cilium/cilium/pull/1246
.. _1235: https://github.com/cilium/cilium/pull/1235
.. _1268: https://github.com/cilium/cilium/pull/1268
.. _1275: https://github.com/cilium/cilium/pull/1275
.. _1124: https://github.com/cilium/cilium/pull/1124
.. _1266: https://github.com/cilium/cilium/pull/1266
.. _1286: https://github.com/cilium/cilium/pull/1286
.. _1262: https://github.com/cilium/cilium/pull/1262
.. _1207: https://github.com/cilium/cilium/pull/1207
.. _1304: https://github.com/cilium/cilium/pull/1304
.. _1313: https://github.com/cilium/cilium/pull/1313
.. _1317: https://github.com/cilium/cilium/pull/1317
.. _1320: https://github.com/cilium/cilium/pull/1320
.. _1322: https://github.com/cilium/cilium/pull/1322
.. _1140: https://github.com/cilium/cilium/pull/1140
.. _1242: https://github.com/cilium/cilium/pull/1242
.. _1330: https://github.com/cilium/cilium/pull/1330
.. _1338: https://github.com/cilium/cilium/pull/1338
.. _1349: https://github.com/cilium/cilium/pull/1349
.. _1260: https://github.com/cilium/cilium/pull/1260
.. _1328: https://github.com/cilium/cilium/pull/1328
.. _1365: https://github.com/cilium/cilium/pull/1365
.. _1262: https://github.com/cilium/cilium/pull/1262
.. _1207: https://github.com/cilium/cilium/pull/1207
.. _1380: https://github.com/cilium/cilium/pull/1380
.. _1373: https://github.com/cilium/cilium/pull/1373
.. _1426: https://github.com/cilium/cilium/pull/1426
.. _1427: https://github.com/cilium/cilium/pull/1427
.. _1444: https://github.com/cilium/cilium/pull/1444
.. _1354: https://github.com/cilium/cilium/pull/1354
.. _1440: https://github.com/cilium/cilium/pull/1440
.. _1406: https://github.com/cilium/cilium/pull/1406
.. _1454: https://github.com/cilium/cilium/pull/1454
.. _1459: https://github.com/cilium/cilium/pull/1459
.. _1182: https://github.com/cilium/cilium/pull/1182
.. _1195: https://github.com/cilium/cilium/pull/1195
.. _1196: https://github.com/cilium/cilium/pull/1196
.. _1186: https://github.com/cilium/cilium/pull/1186
.. _1211: https://github.com/cilium/cilium/pull/1211
.. _1153: https://github.com/cilium/cilium/pull/1153
.. _1213: https://github.com/cilium/cilium/pull/1213
.. _1188: https://github.com/cilium/cilium/pull/1188
.. _1169: https://github.com/cilium/cilium/pull/1169
.. _1296: https://github.com/cilium/cilium/pull/1296
.. _1297: https://github.com/cilium/cilium/pull/1297
.. _1288: https://github.com/cilium/cilium/pull/1288
.. _1394: https://github.com/cilium/cilium/pull/1394
.. _1356: https://github.com/cilium/cilium/pull/1356
.. _1365: https://github.com/cilium/cilium/pull/1365
.. _1397: https://github.com/cilium/cilium/pull/1397
.. _1370: https://github.com/cilium/cilium/pull/1370
.. _1206: https://github.com/cilium/cilium/pull/1206
.. _1350: https://github.com/cilium/cilium/pull/1350
.. _1425: https://github.com/cilium/cilium/pull/1425
.. _1390: https://github.com/cilium/cilium/pull/1390
.. _1385: https://github.com/cilium/cilium/pull/1385
.. _1410: https://github.com/cilium/cilium/pull/1410
.. _1344: https://github.com/cilium/cilium/pull/1344
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
