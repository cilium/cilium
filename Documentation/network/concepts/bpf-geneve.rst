.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _bpf_geneve_datapath:

***************************
Native BPF Geneve Datapath
***************************

The native BPF Geneve datapath provides full in-eBPF encapsulation and
decapsulation for Geneve overlay tunnels (RFC 8926), eliminating the kernel
``cilium_geneve`` netdev overhead and packet recirculation.

Overview
========

In traditional Cilium Geneve tunneling, egress packets from pods are annotated
with tunnel metadata via ``bpf_skb_set_tunnel_key`` and redirected to the
virtual ``cilium_geneve`` kernel netdev. The Linux kernel network stack then
re-processes the packet through the Geneve driver, encapsulates it, and transmits
it out the physical netdev. On ingress, the packet hits the physical netdev,
enters the kernel UDP stack on port 6081, gets decapsulated by the kernel Geneve
driver, and is injected into the ``cilium_geneve`` interface for eBPF processing.

The native BPF Geneve datapath moves both encapsulation and decapsulation
entirely into eBPF:

* **Egress (Encapsulation)**: The eBPF program directly constructs the outer
  IPv4/IPv6, UDP, and Geneve headers at the TC and XDP layers via
  ``ctx_adjust_hroom``, computes 5-tuple flow-hash entropy for the UDP source port
  (for both inner IPv4 and inner IPv6 flows, including IPv6 flow label) for ECMP
  hashing across network fabrics, preserves inner IPv4 DSCP/TOS and inner IPv6
  Traffic Class into the outer header, and redirects the fully formed frame
  directly out the physical netdev via an O(1) TTL-bounded LRU route cache
  (``cilium_geneve_routes`` / ``cilium_geneve_routes6``, 30s TTL) backed by FIB
  lookup (``bpf_fib_lookup``).
* **Ingress (Decapsulation)**: Incoming packets arriving on physical netdevs with
  the configured Geneve UDP destination port (``CONFIG(tunnel_port)``, defaulting
  to ``6081``) are intercepted directly in eBPF. The program validates the Geneve
  header and up to 63 variable-length TLV options (252 bytes), extracts the
  security identity from the VNI or Option TLVs, strips the outer encapsulation
  headers via ``ctx_adjust_hroom``, sets the overlay identity mark
  (``MARK_MAGIC_OVERLAY``), and jumps directly into ``bpf_overlay`` via the
  ``cilium_calls_bpf_overlay`` cross-program tail call.

Performance Improvements
========================

By eliminating kernel netdev transitions, per-packet ``metadata_dst_alloc()`` SLAB
allocations, and uncached ``TUNNEL_NOCACHE`` FIB lookups, native BPF Geneve
demonstrates substantial throughput, packet-rate, latency, and CPU efficiency gains:

* **TCP Throughput**: **+34.8% to +40.0%** increase in default ``eth`` mode (up to
  **49.43 Gbps**, peak **50.49 Gbps**) and **+61.3% to +72.5%** increase in L3 ``ip``
  mode (up to **57.67 Gbps**, peak **59.51 Gbps**) vs. **35.75 Gbps** kernel
  ``collect_md`` baseline on 8 streams.
* **Small-Packet (64B UDP) Rate**: **+40.3% to +41.9%** increase (**92.09 kpps** in
  ``eth`` mode and **93.09 kpps** in ``ip`` mode vs. **65.62 kpps** baseline).
* **Latency**: **-23.5% to -26.6%** reduction in average pod-to-pod ICMP RTT
  (**0.079 ms** in ``eth`` mode and **0.083 ms** in ``ip`` mode vs. **0.108 ms**
  baseline).
* **CPU Efficiency**: **+30.5% to +55.2%** more Gbps delivered per 1% SoftIRQ CPU
  across 1 to 64 concurrent TCP streams.

Architecture & Packet Lifecycle
===============================

.. code-block:: text

   +-------------------------------------------------------------------------+
   |                             EGRESS PATH                                 |
   |                                                                         |
   |  [ Pod / Container ]                                                    |
   |         |                                                               |
   |         v                                                               |
   |    cil_from_lxc (TC ingress)                                            |
   |         |                                                               |
   |         v (tunnel routing decision)                                     |
   |    tail_geneve_encap4 / tail_geneve_encap6                              |
   |         |-- GSO-aware PMTU check & DSR Reverse DNAT                     |
   |         |-- Lookup cilium_geneve_routes / cilium_geneve_routes6 (30s)   |
   |         |-- ctx_adjust_hroom (expand headroom for IP+UDP+Geneve+TLVs)   |
   |         |-- Write Outer IP (TOS/TC) + UDP (sport = flow hash) + Geneve  |
   |         v                                                               |
   |    bpf_redirect (Physical Netdev - eth0)                                |
   +-------------------------------------------------------------------------+

   +-------------------------------------------------------------------------+
   |                            INGRESS PATH                                 |
   |                                                                         |
   |  Physical Netdev (eth0)                                                 |
   |         |                                                               |
   |         v                                                               |
   |    cil_from_netdev (TC ingress)                                         |
   |         | (UDP dest port == CONFIG(tunnel_port), default 6081)          |
   |         v                                                               |
   |    tail_geneve_decap4 / tail_geneve_decap6                              |
   |         |-- Parse & validate Geneve header + up to 63 TLVs (252B)       |
   |         |-- ctx_adjust_hroom (strip outer IP+UDP+Geneve headers)        |
   |         |-- Derive src_sec_identity & set MARK_MAGIC_OVERLAY            |
   |         v                                                               |
   |    cilium_calls_bpf_overlay -> bpf_overlay (tail_handle_ipv4 / v6)      |
   |         |                                                               |
   |         v                                                               |
   |  [ Local Pod Delivery / Host Stack ]                                    |
   +-------------------------------------------------------------------------+

Underlay IP Protocol Support & Path MTU Discovery
=================================================

Native BPF Geneve supports both IPv4 and IPv6 underlay networks:

* **IPv4 Underlay**: 20-byte outer IPv4 header + 8-byte UDP header + 8-byte Geneve
  header (36 bytes in ``ip`` mode, 50 bytes in ``eth`` TEB mode, plus TLV options).
* **IPv6 Underlay**: 40-byte outer IPv6 header + 8-byte UDP header + 8-byte Geneve
  header (56 bytes in ``ip`` mode, 70 bytes in ``eth`` TEB mode, plus TLV options).

When ``--geneve-inner-protocol=ip`` is configured, Cilium's control-plane MTU
manager (``pkg/mtu``) automatically reduces the tunnel overhead by 14 bytes so
Pod network namespaces receive a ``1464B`` route MTU on IPv4 underlays (``1444B``
on IPv6 underlays) instead of ``1450B`` (``1430B``).

Both underlays also enforce datapath RFC 1191 / RFC 8201 Path MTU Discovery
(``bpf_geneve_check_mtu`` and ``bpf_geneve_reply_icmp_too_big``): when
``inner_l3_len + encap_overhead`` exceeds the underlay interface/route MTU (checked
via ``CONFIG(device_mtu)`` and ``fib_params.l.tot_len`` /
``BPF_FIB_LKUP_RET_FRAG_NEEDED``, using per-segment ``ctx->gso_size`` when
``ctx->gso_segs > 1``), ``tail_geneve_encap4`` and ``tail_geneve_encap6`` generate an
``ICMP_DEST_UNREACH`` / ``ICMP_FRAG_NEEDED`` (Type 3, Code 4) or
``ICMPV6_PKT_TOOBIG`` (Type 2, Code 0) reply with the exact reduced tunnel
Next-Hop MTU (``underlay_mtu - encap_overhead``: ``1450`` in ``eth`` mode, ``1464`` in
``ip`` mode on a ``1500B`` underlay) and redirect it back to the sender. In ``eth``
mode, ``bpf_geneve_encap4`` and ``bpf_geneve_encap6`` pass
``BPF_F_ADJ_ROOM_ENCAP_L2(ETH_HLEN) | BPF_F_ADJ_ROOM_ENCAP_L2_ETH`` to
``bpf_skb_adjust_room`` so the kernel GSO/GRO engine preserves full UDP tunnel
segmentation offload across ``ETH_P_TEB`` frames.

Datapath Plugin Integration
===========================

Native BPF Geneve is also available as a Cilium Datapath Plugin
(``CiliumDatapathPlugin`` v2alpha1), enabling operators to load and manage the
Geneve datapath hooks dynamically without modifying core daemon images.

The plugin binary runs as a node-local daemon talking to the Cilium agent over a
UNIX domain socket (``/var/run/cilium/plugins/bpf-geneve-datapath.sock``),
handling both ``PrepareCollection`` and ``InstrumentCollection`` lifecycle hooks.

.. code-block:: yaml

    apiVersion: cilium.io/v2alpha1
    kind: CiliumDatapathPlugin
    metadata:
      name: bpf-geneve-datapath
    spec:
      attachmentPolicy: Always
      socket: /var/run/cilium/plugins/bpf-geneve-datapath.sock

Configuration
=============

To enable native BPF Geneve encapsulation and decapsulation in Helm (with optional
``enable-bpf-geneve``, ``geneve-inner-protocol``, and ``tunnel-port`` configuration):

.. code-block:: yaml

    routingMode: tunnel
    tunnelProtocol: geneve
    tunnelPort: 6081         # Configurable UDP destination port (default 6081)
    enableBpfGeneve: true    # true (default) or false (fallback to cilium_geneve collect_md)
    geneveInnerProtocol: eth # "eth" (default TEB 0x6558) or "ip" (L3 IPv4/IPv6)
    bpf:
      geneveDatapath: true

Performance Evaluation & Reproducible Benchmark Script
======================================================

Anyone checking out the repository can reproduce the 3-mode, 24-metric cross-node
throughput, CPU efficiency, SoftIRQ utilization, and Path MTU Discovery evaluation
on a local 3-node Kind cluster by running:

.. code-block:: shell-session

    $ ./contrib/scripts/benchmark-geneve-bpf.sh

The script provisions a 3-node Kind cluster (or reuses an existing ``geneve-perf``
cluster), deploys cross-node Pod endpoints, a ClusterIP Service, and an external
Docker client container targeting an intermediate-node NodePort hop, switches
dynamically between ``bpf_eth``, ``bpf_ip``, and ``kernel_collect_md`` via the
``cilium-config`` ConfigMap, verifies live ``ICMP_FRAG_NEEDED`` PMTU discovery
(``mtu = 1450`` in ``eth`` mode and ``mtu = 1464`` in ``ip`` mode) plus exact
``1464B`` L3 ``DF=1`` unfragmented forwarding, runs 5 iterations across 24
throughput, packet rate, CPU efficiency, SoftIRQ utilization, and tail-latency
metrics, and outputs a formatted Markdown comparison table:

* **TCP Single-Stream Bulk (P=1)**: ``5.654 ± 0.193 Gbps`` (``eth``) /
  ``7.415 ± 0.466 Gbps`` (``ip``) vs. ``4.237 ± 0.106 Gbps`` (Kernel ``collect_md``)
  — **+33.4% / +75.0% throughput**.
* **TCP 4-Stream Bulk (P=4)**: ``23.730 ± 0.235 Gbps`` (``eth``) /
  ``29.015 ± 0.906 Gbps`` (``ip``) vs. ``17.495 ± 0.232 Gbps`` (Kernel ``collect_md``)
  — **+35.6% / +65.8% throughput**.
* **TCP 8-Stream Bulk (P=8)**: ``49.744 ± 0.783 Gbps`` (``eth``, peak ``50.39 Gbps``) /
  ``59.523 ± 0.918 Gbps`` (``ip``, peak ``60.41 Gbps``) vs. ``36.318 ± 0.362 Gbps``
  (Kernel ``collect_md``) — **+37.0% / +63.9% throughput**.
* **TCP Bidirectional Full-Duplex (--bidir P=4)**: ``38.416 ± 0.987 Gbps`` (``eth``) /
  ``43.045 ± 1.952 Gbps`` (``ip``) vs. ``27.847 ± 0.498 Gbps`` (Kernel ``collect_md``)
  — **+38.0% / +54.6% combined throughput**.
* **TCP Small-Write RPC (-l 128 -N P=4, TCP_NODELAY)**: ``0.098 ± 0.001 Gbps``
  (``eth`` & ``ip``) vs. ``0.070 ± 0.001 Gbps`` (Kernel ``collect_md``) —
  **+39.6% / +40.6% throughput**.
* **Kubernetes ClusterIP Service -> Geneve (P=4)**: ``23.455 ± 0.357 Gbps`` (``eth``) /
  ``29.355 ± 0.887 Gbps`` (``ip``) vs. ``17.454 ± 0.171 Gbps`` (Kernel ``collect_md``)
  — **+34.4% / +68.2% throughput**.
* **Kubernetes Intermediate-Node NodePort -> Geneve (P=4)**: ``22.770 ± 0.266 Gbps``
  (``eth``) / ``28.236 ± 0.855 Gbps`` (``ip``) vs. ``17.501 ± 0.186 Gbps`` (Kernel
  ``collect_md``) — **+30.1% / +61.3% throughput**.
* **UDP Small-Packet (64B), Medium-Packet (512B), and Full-MTU (1380B) Rates (P=4)**:
  ``92.147 kpps`` / ``91.075 kpps`` / ``91.066 kpps`` (``eth``) and
  ``92.733 kpps`` / ``93.016 kpps`` / ``91.318 kpps`` (``ip``) vs.
  ``65.748 kpps`` / ``65.203 kpps`` / ``65.273 kpps`` (Kernel ``collect_md``) —
  **+39.5–40.2% (eth) and +39.9–42.7% (ip) PPS & throughput**.
* **UDP 4000B Multi-Fragment (3x IPv4 Fragments/Datagram, P=4)**:
  ``1.112 ± 0.015 Gbps`` / ``34.780 kpps`` (``eth``) and
  ``1.128 ± 0.009 Gbps`` / ``35.246 kpps`` (``ip``) vs.
  ``0.774 ± 0.005 Gbps`` / ``24.182 kpps`` (Kernel ``collect_md``) —
  **+43.8% / +45.8% fragmented datagram throughput**.
* **TCP 8-Stream CPU & SoftIRQ Efficiency**: ``4.25 ± 0.06 Gbps/core`` (``eth``) and
  ``5.12 ± 0.07 Gbps/core`` (``ip``) vs. ``3.12 ± 0.02 Gbps/core`` (Kernel) —
  **+36.2% / +64.1% CPU efficiency**; ``5.98 ± 0.09 Gbps/SoftIRQ-core`` (``eth``) and
  ``7.26 ± 0.25 Gbps/SoftIRQ-core`` (``ip``) vs. ``3.89 ± 0.05 Gbps/SoftIRQ-core``
  (Kernel) — **+53.6% / +86.5% SoftIRQ efficiency**.
* **UDP 64B Packet CPU Efficiency & Per-Packet CPU Cost**: ``18.16 ± 0.26 kpps/core``
  (``55.07 ± 0.77 µs/pkt``) in ``eth`` mode and ``18.22 ± 0.25 kpps/core``
  (``54.89 ± 0.76 µs/pkt``) in ``ip`` mode vs. ``13.81 ± 0.07 kpps/core``
  (``72.42 ± 0.38 µs/pkt``) in Kernel mode — **+31.5% / +32.0% packet CPU efficiency**
  and **-24.0% / -24.2% CPU time per packet**.
* **Iso-Load 10 Gbps TCP (-b 2.5G -P 4) CPU & SoftIRQ Savings**: ``298.9 ± 8.2% CPU``
  (``246.2% SoftIRQ``) in ``eth`` mode and ``292.5 ± 9.6% CPU`` (``241.8% SoftIRQ``) in
  ``ip`` mode vs. ``405.1 ± 2.6% CPU`` (``328.6% SoftIRQ``) in Kernel mode —
  **-26.2% / -27.8% total CPU** (saving **>1.0 full CPU core** at 10 Gbps) and
  **-25.1% / -26.4% SoftIRQ CPU**.
* **Iso-Load 50 kpps UDP 64B (-b 6.4M -P 4) CPU & SoftIRQ Savings**:
  ``320.4 ± 2.3% CPU`` (``233.9% SoftIRQ``) in ``eth`` mode and ``320.3 ± 5.9% CPU``
  (``230.6% SoftIRQ``) in ``ip`` mode vs. ``391.0 ± 4.3% CPU`` (``284.4% SoftIRQ``) in
  Kernel mode — **-18.1% total CPU** and **-17.7% / -18.9% SoftIRQ CPU**.
* **ICMP Small (64B) & Large Full-MTU (1428B) Ping Mean & p99 Tail RTT (500 samples @ 2ms)**:
  Mean RTT drops from ``0.111 ms`` / ``0.115 ms`` (Kernel) to ``0.087 ms`` / ``0.082 ms``
  (``eth``, **-21.6% / -28.1%**) and ``0.085 ms`` / ``0.082 ms`` (``ip``,
  **-23.9% / -28.8%**); full-MTU ``1428B`` ``p99`` tail RTT drops from ``0.295 ms``
  (Kernel) to ``0.227 ms`` (``eth``, **-23.0%**) and ``0.215 ms`` (``ip``, **-27.2%**).
* **Exact 1464B L3 DF=1 Boundary Verification (ping -M do -s 1436)**: Blocked with
  ``ICMP_FRAG_NEEDED (mtu = 1450)`` in Kernel and ``bpf_eth`` modes; **passes with
  0% packet loss** (``1500B`` wire frame) in ``bpf_ip`` mode, confirming the
  **+14B (+1.0%) L3 Pod MTU gain** and **-28.0% header overhead reduction**.

BPF Test Coverage
=================

The Full eBPF GENEVE Datapath is validated by 14 BPF unit and integration test
suites (totaling 74 ``BPF_PROG_TEST_RUN`` subtests) plus Go unit tests in
``pkg/mtu``, ``pkg/datapath/tunnel``, ``pkg/datapath/loader``, and
``plugins/bpf-geneve-datapath``:

* ``bpf/tests/bpf_geneve_features_test.c`` (8 subtests): Function-level verification
  of the 63-TLV / 252-byte RFC 8926 maximum protocol limit (power-of-two chunked
  load/store and O(1) verifier validation), Geneve option extraction overload
  (``ctx_get_tunnel_opt``), malformed TLV length rejection, unknown critical TLV
  rejection (RFC 8926 Section 3.5.2), inner IPv4 and inner IPv6 5-tuple UDP
  source-port entropy hashing with DSCP/Traffic Class preservation, dual-stack
  ``cilium_geneve_routes`` / ``cilium_geneve_routes6`` LRU cache hit, and 30-second
  route cache TTL expiration with automatic FIB re-learning.
* ``bpf/tests/bpf_geneve_xdp_dsr_test.c`` (7 subtests): End-to-end XDP NodePort DSR
  encapsulation (IPv4 and IPv6 underlays, multi-TLV egress merging, ``eth`` and ``ip``
  inner protocol modes), in-place outer header rewrite on already-encapsulated
  packets, and non-zero TLV offset DSR option extraction.
* ``bpf/tests/tc_lxc_geneve_bpf.c`` (8 subtests): Dual-stack (IPv4 & IPv6) DSR
  Reverse DNAT verification for both remote-node tunnel replies
  (``tail_geneve_encap4/6`` reusing ``nodeport_rev_dnat_fwd_ipv4/6``) and local-node
  host delivery replies (``bpf_lxc.c``), oversized packet Path MTU Discovery
  verification (``ICMP_FRAG_NEEDED`` in both ``eth`` mode ``mtu=150`` and ``ip``
  L3 mode ``mtu=164``, and ``ICMPV6_PKT_TOOBIG``), and TC NodePort tunnel
  encapsulation with options (``nodeport_add_tunnel_encap_opt`` :math:`\rightarrow`
  ``__encap_with_nodeid``) in ``ip`` L3 mode.
* ``bpf/tests/bpf_geneve_e2e_host_to_overlay.c`` (4 subtests): End-to-end
  cross-program integration tests verifying ``bpf_host`` (UDP ingress interception)
  :math:`\rightarrow` ``tail_geneve_decap4/6`` :math:`\rightarrow`
  ``cilium_calls_bpf_overlay`` cross-program tail call :math:`\rightarrow`
  ``bpf_overlay`` (``tail_handle_ipv4``) across IPv4 (``eth`` and ``ip`` modes) and
  IPv6 underlays, plus a full 4-stage tunnel-based TCP connection walkthrough
  (Client Pod SYN + DSR option encap :math:`\rightarrow` Receiver Node ``bpf_host``
  decap + ``bpf_overlay`` DSR Conntrack creation :math:`\rightarrow` Backend Pod
  SYN-ACK reply + ``bpf_geneve_rev_dnat_fwd`` Reverse DNAT + return tunnel encap
  :math:`\rightarrow` Client Node ``bpf_host`` decap + ``bpf_overlay`` verification).
* ``bpf/tests/bpf_geneve_encap_v4.c`` & ``bpf/tests/bpf_geneve_encap_v6.c`` (5 subtests):
  Outer header construction and checksum verification for IPv4 and IPv6 underlays in
  both ``eth`` and ``ip`` modes.
* ``bpf/tests/bpf_geneve_roundtrip.c`` (5 subtests): Full encapsulation and
  decapsulation roundtrip with DSR and custom TLV options.
* ``bpf/tests/bpf_geneve_encap_dispatch.c`` & ``bpf/tests/bpf_geneve_decap_ingress.c``
  (6 subtests): Egress and ingress tail-call dispatch verification, including custom
  ``--tunnel-port`` (``CONFIG(tunnel_port)``) roundtrip and mismatch drop validation.

Attribution
===========

The native BPF Geneve datapath architecture, flow-entropy calculation, and
zero-recirculation in-kernel tunnel design originated from Google's Dataplane V2
networking stack and was contributed to upstream open-source Cilium.

