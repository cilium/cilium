****
NEWS
****

HEAD
====

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


