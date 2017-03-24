Roadmap
=======

Requirements for 1.0
--------------------

-  [ ] Kernel (merged upstream)
-  [X] Perf ring buffer access
-  [X] Modification of packet size
-  [X] Skb trimming
-  [ ] Crypto integration [#198]
-  [ ] Fragmentation handling [#200]
-  [ ] Policy
-  [X] Ingress/consumer access based on labels
-  [X] Distributed label to ID map
-  [ ] Verification suite [#201]
-  [ ] Add port mapping to spec [#202]
-  [ ] Egress CIDR policy [#164]
-  [X] Kubernetes network policy integration
-  [X] etcdv3 (tested with 3.1.0) [#203]
-  [ ] BPF Modules
-  [X] L3

   -  [X] IPv6
   -  [X] IPv4

-  [X] L4

   -  [X] port mapping

-  [X] L2

   -  [X] ARP responder
   -  [X] NDISC responder
   -  [X] MAC rewrite

-  [X] Policy

   -  [X] per CPU consumer hashtable

-  [X] Connection tracking

   -  [X] TCP/UDP flow tracking
   -  [X] Directional tracking SYN/REPLY
   -  [X] ICMP/NDISC
   -  [X] Expect hole punching for related errors
   -  [X] per cpu per flow statistic collection
   -  [X] NAT tracking for reverse translation

-  [X] Encapsulation
-  [X] Local endpoint hashtable
-  [X] Fast packet capturing mechanism based on perf ring
-  [X] Debugging framework based on perf ring
-  [ ] Load balancer
-  [X] Core
-  [X] DSR
-  [X] K8s service and endpoints integration
-  [ ] "Cilium-proxy" for kubernetes (waiting for
   https://github.com/kubernetes/kubernetes/pull/35472)
-  [ ] Modes

   -  [ ] Modular framework [#163]
   -  [X] Hash based
   -  [ ] RR [#191]
   -  [ ] Least connected [#191]

-  [ ] Integration
-  [X] CNI [STRIKEOUT:(waiting for
   https://github.com/containernetworking/cni/pull/115)]
-  [ ] libnetwork (waiting for
   https://github.com/docker/libnetwork/pull/826)
-  [ ] GCE (test and write tutorial for GCE)

Post 1.0
--------

-  [ ] BPF Modules
-  [ ] Connection tracking

   -  [ ] TCP sequence verification
