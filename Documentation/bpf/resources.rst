.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _bpf_users:

Further Reading
===============

Mentioned lists of docs, projects, talks, papers, and further reading
materials are likely not complete. Thus, feel free to open pull requests
to complete the list.

Kernel Developer FAQ
--------------------

Under ``Documentation/bpf/``, the Linux kernel provides two FAQ files that
are mainly targeted for kernel developers involved in the BPF subsystem.

* **BPF Devel FAQ:** this document provides mostly information around patch
  submission process as well as BPF kernel tree, stable tree and bug
  reporting workflows, questions around BPF's extensibility and interaction
  with LLVM and more.

  https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/bpf/bpf_devel_QA.rst

..

* **BPF Design FAQ:** this document tries to answer frequently asked questions
  around BPF design decisions related to the instruction set, verifier,
  calling convention, JITs, etc.

  https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/bpf/bpf_design_QA.rst

Projects using BPF
------------------

The following list includes a selection of open source projects making
use of BPF respectively provide tooling for BPF. In this context the eBPF
instruction set is specifically meant instead of projects utilizing the
legacy cBPF:

**Tracing**

* **BCC**

  BCC stands for BPF Compiler Collection, and its key feature is to provide
  a set of easy to use and efficient kernel tracing utilities all based
  upon BPF programs hooking into kernel infrastructure based upon kprobes,
  kretprobes, tracepoints, uprobes, uretprobes as well as USDT probes. The
  collection provides close to hundred tools targeting different layers
  across the stack from applications, system libraries, to the various
  different kernel subsystems in order to analyze a system's performance
  characteristics or problems. Additionally, BCC provides an API in order
  to be used as a library for other projects.

  https://github.com/iovisor/bcc

..

* **bpftrace**

  bpftrace is a DTrace-style dynamic tracing tool for Linux and uses LLVM
  as a back end to compile scripts to BPF-bytecode and makes use of BCC
  for interacting with the kernel's BPF tracing infrastructure. It provides
  a higher-level language for implementing tracing scripts compared to
  native BCC.

  https://github.com/ajor/bpftrace

..

* **perf**

  The perf tool which is developed by the Linux kernel community as
  part of the kernel source tree provides a way to load tracing BPF
  programs through the conventional perf record subcommand where the
  aggregated data from BPF can be retrieved and post processed in
  perf.data for example through perf script and other means.

  https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/perf

..

* **ply**

  ply is a tracing tool that follows the 'Little Language' approach of
  yore, and compiles ply scripts into Linux BPF programs that are attached
  to kprobes and tracepoints in the kernel. The scripts have a C-like syntax,
  heavily inspired by DTrace and by extension awk. ply keeps dependencies
  to very minimum and only requires flex and bison at build time, only libc
  at runtime.

  https://github.com/wkz/ply

..

* **systemtap**

  systemtap is a scripting language and tool for extracting, filtering and
  summarizing data in order to diagnose and analyze performance or functional
  problems. It comes with a BPF back end called stapbpf which translates
  the script directly into BPF without the need of an additional compiler
  and injects the probe into the kernel. Thus, unlike stap's kernel modules
  this does neither have external dependencies nor requires to load kernel
  modules.

  https://sourceware.org/git/gitweb.cgi?p=systemtap.git;a=summary

..

* **PCP**

  Performance Co-Pilot (PCP) is a system performance and analysis framework
  which is able to collect metrics through a variety of agents as well as
  analyze collected systems' performance metrics in real-time or by using
  historical data. With pmdabcc, PCP has a BCC based performance metrics
  domain agent which extracts data from the kernel via BPF and BCC.

  https://github.com/performancecopilot/pcp

..

* **Weave Scope**

  Weave Scope is a cloud monitoring tool collecting data about processes,
  networking connections or other system data by making use of BPF in combination
  with kprobes. Weave Scope works on top of the gobpf library in order to load
  BPF ELF files into the kernel, and comes with a tcptracer-bpf tool which
  monitors connect, accept and close calls in order to trace TCP events.

  https://github.com/weaveworks/scope

..

**Networking**

* **Cilium**

  Cilium provides and transparently secures network connectivity and load-balancing
  between application workloads such as application containers or processes. Cilium
  operates at Layer 3/4 to provide traditional networking and security services
  as well as Layer 7 to protect and secure use of modern application protocols
  such as HTTP, gRPC and Kafka. It is integrated into orchestration frameworks
  such as Kubernetes. BPF is the foundational part of Cilium that operates in
  the kernel's networking data path.

  https://github.com/cilium/cilium

..

* **Suricata**

  Suricata is a network IDS, IPS and NSM engine, and utilizes BPF as well as XDP
  in three different areas, that is, as BPF filter in order to process or bypass
  certain packets, as a BPF based load balancer in order to allow for programmable
  load balancing and for XDP to implement a bypass or dropping mechanism at high
  packet rates.

  https://suricata.readthedocs.io/en/suricata-5.0.2/capture-hardware/ebpf-xdp.html

  https://github.com/OISF/suricata

..

* **systemd**

  systemd allows for IPv4/v6 accounting as well as implementing network access
  control for its systemd units based on BPF's cgroup ingress and egress hooks.
  Accounting is based on packets / bytes, and ACLs can be specified as address
  prefixes for allow / deny rules. More information can be found at:

  http://0pointer.net/blog/ip-accounting-and-access-lists-with-systemd.html

  https://github.com/systemd/systemd

..

* **iproute2**

  iproute2 offers the ability to load BPF programs as LLVM generated ELF files
  into the kernel. iproute2 supports both, XDP BPF programs as well as tc BPF
  programs through a common BPF loader backend. The tc and ip command line
  utilities enable loader and introspection functionality for the user.

  https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/

..

* **p4c-xdp**

  p4c-xdp presents a P4 compiler backend targeting BPF and XDP. P4 is a domain
  specific language describing how packets are processed by the data plane of
  a programmable network element such as NICs, appliances or switches, and with
  the help of p4c-xdp P4 programs can be translated into BPF C programs which
  can be compiled by clang / LLVM and loaded as BPF programs into the kernel
  at XDP layer for high performance packet processing.

  https://github.com/vmware/p4c-xdp

..

**Others**

* **LLVM**

  clang / LLVM provides the BPF back end in order to compile C BPF programs
  into BPF instructions contained in ELF files. The LLVM BPF back end is
  developed alongside with the BPF core infrastructure in the Linux kernel
  and maintained by the same community. clang / LLVM is a key part in the
  toolchain for developing BPF programs.

  https://llvm.org/

..

* **libbpf**

  libbpf is a generic BPF library which is developed by the Linux kernel
  community as part of the kernel source tree and allows for loading and
  attaching BPF programs from LLVM generated ELF files into the kernel.
  The library is used by other kernel projects such as perf and bpftool.

  https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/lib/bpf

..

* **bpftool**

  bpftool is the main tool for introspecting and debugging BPF programs
  and BPF maps, and like libbpf is developed by the Linux kernel community.
  It allows for dumping all active BPF programs and maps in the system,
  dumping and disassembling BPF or JITed BPF instructions from a program
  as well as dumping and manipulating BPF maps in the system. bpftool
  supports interaction with the BPF filesystem, loading various program
  types from an object file into the kernel and much more.

  https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/bpf/bpftool

..

* **cilium/ebpf**

  ``cilium/ebpf`` (ebpf-go) is a pure Go library that provides utilities for
  loading, compiling, and debugging eBPF programs. It has minimal external
  dependencies and is intended to be used in long-running processes.

  Its ``bpf2go`` utility automates away compiling eBPF C programs and embedding
  them into Go binaries.

  It implements attaching programs to various kernel hooks, as well as kprobes
  and uprobes for tracing arbitrary kernel and user space functions. It also
  features a complete assembler that allows constructing eBPF programs at
  runtime using Go, or modifying them after they've been loaded from an ELF
  object.

  https://github.com/cilium/ebpf

..

* **ebpf_asm**

  ebpf_asm provides an assembler for BPF programs written in an Intel-like assembly
  syntax, and therefore offers an alternative for writing BPF programs directly in
  assembly for cases where programs are rather small and simple without needing the
  clang / LLVM toolchain.

  https://github.com/Xilinx-CNS/ebpf_asm

..

XDP Newbies
-----------

There are a couple of walk-through posts by David S. Miller to the xdp-newbies
mailing list (http://vger.kernel.org/vger-lists.html#xdp-newbies), which explain
various parts of XDP and BPF:

4. May 2017,
     BPF Verifier Overview,
     David S. Miller,
     https://www.spinics.net/lists/xdp-newbies/msg00185.html

3. May 2017,
     Contextually speaking...,
     David S. Miller,
     https://www.spinics.net/lists/xdp-newbies/msg00181.html

2. May 2017,
     bpf.h and you...,
     David S. Miller,
     https://www.spinics.net/lists/xdp-newbies/msg00179.html

1. Apr 2017,
     XDP example of the day,
     David S. Miller,
     https://www.spinics.net/lists/xdp-newbies/msg00009.html

BPF Newsletter
--------------

Alexander Alemayhu initiated a newsletter around BPF roughly once per week
covering latest developments around BPF in Linux kernel land and its
surrounding ecosystem in user space.

All BPF update newsletters (01 - 12) can be found here:

     https://cilium.io/blog/categories/technology/5/

And for the news on the latest resources and developments in the eBPF world,
please refer to the link here:

     https://ebpf.io/blog

Podcasts
--------

There have been a number of technical podcasts partially covering BPF.
Incomplete list:

5. Feb 2017,
     Linux Networking Update from Netdev Conference,
     Thomas Graf,
     Software Gone Wild, Show 71,
     https://blog.ipspace.net/2017/02/linux-networking-update-from-netdev.html
     https://www.ipspace.net/nuggets/podcast/Show_71-NetDev_Update.mp3

4. Jan 2017,
     The IO Visor Project,
     Brenden Blanco,
     OVS Orbit, Episode 23,
     https://ovsorbit.org/#e23
     https://ovsorbit.org/episode-23.mp3

3. Oct 2016,
     Fast Linux Packet Forwarding,
     Thomas Graf,
     Software Gone Wild, Show 64,
     https://blog.ipspace.net/2016/10/fast-linux-packet-forwarding-with.html
     https://www.ipspace.net/nuggets/podcast/Show_64-Cilium_with_Thomas_Graf.mp3

2. Aug 2016,
     P4 on the Edge,
     John Fastabend,
     OVS Orbit, Episode 11,
     https://ovsorbit.org/#e11
     https://ovsorbit.org/episode-11.mp3

1. May 2016,
     Cilium,
     Thomas Graf,
     OVS Orbit, Episode 4,
     https://ovsorbit.org/#e4
     https://ovsorbit.org/episode-4.mp3

Blog posts
----------

The following (incomplete) list includes blog posts around BPF, XDP and related projects:

34. May 2017,
     An entertaining eBPF XDP adventure,
     Suchakra Sharma,
     https://suchakra.wordpress.com/2017/05/23/an-entertaining-ebpf-xdp-adventure/

33. May 2017,
     eBPF, part 2: Syscall and Map Types,
     Ferris Ellis,
     https://ferrisellis.com/posts/ebpf_syscall_and_maps/

32. May 2017,
     Monitoring the Control Plane,
     Gary Berger,
     https://www.firstclassfunc.com/2018/07/monitoring-the-control-plane/

31. Apr 2017,
     USENIX/LISA 2016 Linux bcc/BPF Tools,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2017-04-29/usenix-lisa-2016-bcc-bpf-tools.html

30. Apr 2017,
     Liveblog: Cilium for Network and Application Security with BPF and XDP,
     Scott Lowe,
     https://blog.scottlowe.org/2017/04/18/black-belt-cilium/

29. Apr 2017,
     eBPF, part 1: Past, Present, and Future,
     Ferris Ellis,
     https://ferrisellis.com/posts/ebpf_past_present_future/

28. Mar 2017,
     Analyzing KVM Hypercalls with eBPF Tracing,
     Suchakra Sharma,
     https://suchakra.wordpress.com/2017/03/31/analyzing-kvm-hypercalls-with-ebpf-tracing/

27. Jan 2017,
     Golang bcc/BPF Function Tracing,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2017-01-31/golang-bcc-bpf-function-tracing.html

26. Dec 2016,
     Give me 15 minutes and I'll change your view of Linux tracing,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-12-27/linux-tracing-in-15-minutes.html

25. Nov 2016,
     Cilium: Networking and security for containers with BPF and XDP,
     Daniel Borkmann,
     https://opensource.googleblog.com/2016/11/cilium-networking-and-security.html

24. Nov 2016,
     Linux bcc/BPF tcplife: TCP Lifespans,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-11-30/linux-bcc-tcplife.html

23. Oct 2016,
     DTrace for Linux 2016,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-10-27/dtrace-for-linux-2016.html

22. Oct 2016,
     Linux 4.9's Efficient BPF-based Profiler,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-10-21/linux-efficient-profiler.html

21. Oct 2016,
     Linux bcc tcptop,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-10-15/linux-bcc-tcptop.html

20. Oct 2016,
     Linux bcc/BPF Node.js USDT Tracing,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-10-12/linux-bcc-nodejs-usdt.html

19. Oct 2016,
     Linux bcc/BPF Run Queue (Scheduler) Latency,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-10-08/linux-bcc-runqlat.html

18. Oct 2016,
     Linux bcc ext4 Latency Tracing,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-10-06/linux-bcc-ext4dist-ext4slower.html

17. Oct 2016,
     Linux MySQL Slow Query Tracing with bcc/BPF,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-10-04/linux-bcc-mysqld-qslower.html

16. Oct 2016,
     Linux bcc Tracing Security Capabilities,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-10-01/linux-bcc-security-capabilities.html

15. Sep 2016,
     Suricata bypass feature,
     Eric Leblond,
     https://www.stamus-networks.com/blog/2016/09/28/suricata-bypass-feature

14. Aug 2016,
     Introducing the p0f BPF compiler,
     Gilberto Bertin,
     https://blog.cloudflare.com/introducing-the-p0f-bpf-compiler/

13. Jun 2016,
     Ubuntu Xenial bcc/BPF,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-06-14/ubuntu-xenial-bcc-bpf.html

12. Mar 2016,
     Linux BPF/bcc Road Ahead, March 2016,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-03-28/linux-bpf-bcc-road-ahead-2016.html

11. Mar 2016,
     Linux BPF Superpowers,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-03-05/linux-bpf-superpowers.html

10. Feb 2016,
     Linux eBPF/bcc uprobes,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-02-08/linux-ebpf-bcc-uprobes.html

9. Feb 2016,
     Who is waking the waker? (Linux chain graph prototype),
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-02-05/ebpf-chaingraph-prototype.html

8. Feb 2016,
     Linux Wakeup and Off-Wake Profiling,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-02-01/linux-wakeup-offwake-profiling.html

7. Jan 2016,
     Linux eBPF Off-CPU Flame Graph,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-01-20/ebpf-offcpu-flame-graph.html

6. Jan 2016,
     Linux eBPF Stack Trace Hack,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-01-18/ebpf-stack-trace-hack.html

1. Sep 2015,
     Linux Networking, Tracing and IO Visor, a New Systems Performance Tool for a Distributed World,
     Suchakra Sharma,
     https://thenewstack.io/comparing-dtrace-iovisor-new-systems-performance-platform-advance-linux-networking-virtualization/

5. Aug 2015,
     BPF Internals - II,
     Suchakra Sharma,
     https://suchakra.wordpress.com/2015/08/12/bpf-internals-ii/

4. May 2015,
     eBPF: One Small Step,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2015-05-15/ebpf-one-small-step.html

3. May 2015,
     BPF Internals - I,
     Suchakra Sharma,
     https://suchakra.wordpress.com/2015/05/18/bpf-internals-i/

2. Jul 2014,
     Introducing the BPF Tools,
     Marek Majkowski,
     https://blog.cloudflare.com/introducing-the-bpf-tools/

1. May 2014,
     BPF - the forgotten bytecode,
     Marek Majkowski,
     https://blog.cloudflare.com/bpf-the-forgotten-bytecode/

Books
-----

BPF Performance Tools (Gregg, Addison Wesley, 2019)

Talks
-----

The following (incomplete) list includes talks and conference papers
related to BPF and XDP:

46. July 2021,
     eBPF & Cilium Office Hours episode 13: XDP Hands-on Tutorial, with Liz Rice,
     https://www.youtube.com/watch?v=YUI78vC4qSQ&t=300s

45. June 2021,
     eBPF & Cilium Office Hours episode 9: XDP and Load Balancing,
     with Daniel Borkmann,
     https://www.youtube.com/watch?v=OIyPm6K4ooY&t=308s

44. May 2017,
     PyCon 2017, Portland,
     Executing python functions in the linux kernel by transpiling to bpf,
     Alex Gartrell,
     https://www.youtube.com/watch?v=CpqMroMBGP4

43. May 2017,
     gluecon 2017, Denver,
     Cilium + BPF: Least Privilege Security on API Call Level for Microservices,
     Dan Wendlandt,
     http://gluecon.com/#agenda

42. May 2017,
     Lund Linux Con, Lund,
     XDP - eXpress Data Path,
     Jesper Dangaard Brouer,
     http://people.netfilter.org/hawk/presentations/LLC2017/XDP_DDoS_protecting_LLC2017.pdf

41. May 2017,
     Polytechnique Montreal,
     Trace Aggregation and Collection with eBPF,
     Suchakra Sharma,
     https://hsdm.dorsal.polymtl.ca/system/files/eBPF-5May2017%20(1).pdf

40. Apr 2017,
     DockerCon, Austin,
     Cilium - Network and Application Security with BPF and XDP,
     Thomas Graf,
     https://www.slideshare.net/ThomasGraf5/dockercon-2017-cilium-network-and-application-security-with-bpf-and-xdp

39. Apr 2017,
     NetDev 2.1, Montreal,
     XDP Mythbusters,
     David S. Miller,
     https://netdevconf.info/2.1/slides/apr7/miller-XDP-MythBusters.pdf

38. Apr 2017,
     NetDev 2.1, Montreal,
     Droplet: DDoS countermeasures powered by BPF + XDP,
     Huapeng Zhou, Doug Porter, Ryan Tierney, Nikita Shirokov,
     https://netdevconf.info/2.1/slides/apr6/zhou-netdev-xdp-2017.pdf

37. Apr 2017,
     NetDev 2.1, Montreal,
     XDP in practice: integrating XDP in our DDoS mitigation pipeline,
     Gilberto Bertin,
     https://netdevconf.info/2.1/slides/apr6/bertin_Netdev-XDP.pdf

36. Apr 2017,
     NetDev 2.1, Montreal,
     XDP for the Rest of Us,
     Andy Gospodarek, Jesper Dangaard Brouer,
     https://netdevconf.info/2.1/slides/apr7/gospodarek-Netdev2.1-XDP-for-the-Rest-of-Us_Final.pdf

35. Mar 2017,
     SCALE15x, Pasadena,
     Linux 4.x Tracing: Performance Analysis with bcc/BPF,
     Brendan Gregg,
     https://www.slideshare.net/brendangregg/linux-4x-tracing-performance-analysis-with-bccbpf

34. Mar 2017,
     XDP Inside and Out,
     David S. Miller,
     https://raw.githubusercontent.com/iovisor/bpf-docs/master/XDP_Inside_and_Out.pdf

33. Mar 2017,
     OpenSourceDays, Copenhagen,
     XDP - eXpress Data Path, Used for DDoS protection,
     Jesper Dangaard Brouer,
     http://people.netfilter.org/hawk/presentations/OpenSourceDays2017/XDP_DDoS_protecting_osd2017.pdf

32. Mar 2017,
     source{d}, Infrastructure 2017, Madrid,
     High-performance Linux monitoring with eBPF,
     Alfonso Acosta,
     https://www.youtube.com/watch?v=k4jqTLtdrxQ

31. Feb 2017,
     FOSDEM 2017, Brussels,
     Stateful packet processing with eBPF, an implementation of OpenState interface,
     Quentin Monnet,
     https://archive.fosdem.org/2017/schedule/event/stateful_ebpf/

30. Feb 2017,
     FOSDEM 2017, Brussels,
     eBPF and XDP walkthrough and recent updates,
     Daniel Borkmann,
     http://borkmann.ch/talks/2017_fosdem.pdf

29. Feb 2017,
     FOSDEM 2017, Brussels,
     Cilium - BPF & XDP for containers,
     Thomas Graf,
     https://archive.fosdem.org/2017/schedule/event/cilium/

28. Jan 2017,
     linuxconf.au, Hobart,
     BPF: Tracing and more,
     Brendan Gregg,
     https://www.slideshare.net/brendangregg/bpf-tracing-and-more

27. Dec 2016,
     USENIX LISA 2016, Boston,
     Linux 4.x Tracing Tools: Using BPF Superpowers,
     Brendan Gregg,
     https://www.slideshare.net/brendangregg/linux-4x-tracing-tools-using-bpf-superpowers

26. Nov 2016,
     Linux Plumbers, Santa Fe,
     Cilium: Networking & Security for Containers with BPF & XDP,
     Thomas Graf,
     https://www.slideshare.net/ThomasGraf5/clium-container-networking-with-bpf-xdp

25. Nov 2016,
     OVS Conference, Santa Clara,
     Offloading OVS Flow Processing using eBPF,
     William (Cheng-Chun) Tu,
     http://www.openvswitch.org/support/ovscon2016/7/1120-tu.pdf

24. Oct 2016,
     One.com, Copenhagen,
     XDP - eXpress Data Path, Intro and future use-cases,
     Jesper Dangaard Brouer,
     http://people.netfilter.org/hawk/presentations/xdp2016/xdp_intro_and_use_cases_sep2016.pdf

23. Oct 2016,
     Docker Distributed Systems Summit, Berlin,
     Cilium: Networking & Security for Containers with BPF & XDP,
     Thomas Graf,
     https://www.slideshare.net/Docker/cilium-bpf-xdp-for-containers-66969823

22. Oct 2016,
     NetDev 1.2, Tokyo,
     Data center networking stack,
     Tom Herbert,
     https://netdevconf.info/1.2/session.html?tom-herbert

21. Oct 2016,
     NetDev 1.2, Tokyo,
     Fast Programmable Networks & Encapsulated Protocols,
     David S. Miller,
     https://netdevconf.info/1.2/session.html?david-miller-keynote

20. Oct 2016,
     NetDev 1.2, Tokyo,
     XDP workshop - Introduction, experience, and future development,
     Tom Herbert,
     https://netdevconf.info/1.2/session.html?herbert-xdp-workshop

19. Oct 2016,
     NetDev1.2, Tokyo,
     The adventures of a Suricate in eBPF land,
     Eric Leblond,
     https://netdevconf.info/1.2/slides/oct6/10_suricata_ebpf.pdf

18. Oct 2016,
     NetDev1.2, Tokyo,
     cls_bpf/eBPF updates since netdev 1.1,
     Daniel Borkmann,
     http://borkmann.ch/talks/2016_tcws.pdf

17. Oct 2016,
     NetDev1.2, Tokyo,
     Advanced programmability and recent updates with tc’s cls_bpf,
     Daniel Borkmann,
     http://borkmann.ch/talks/2016_netdev2.pdf
     https://netdevconf.info/1.2/papers/borkmann.pdf

16. Oct 2016,
     NetDev 1.2, Tokyo,
     eBPF/XDP hardware offload to SmartNICs,
     Jakub Kicinski, Nic Viljoen,
     https://netdevconf.info/1.2/papers/eBPF_HW_OFFLOAD.pdf

15. Aug 2016,
     LinuxCon, Toronto,
     What Can BPF Do For You?,
     Brenden Blanco,
     https://events.static.linuxfound.org/sites/events/files/slides/iovisor-lc-bof-2016.pdf

14. Aug 2016,
     LinuxCon, Toronto,
     Cilium - Fast IPv6 Container Networking with BPF and XDP,
     Thomas Graf,
     https://www.slideshare.net/ThomasGraf5/cilium-fast-ipv6-container-networking-with-bpf-and-xdp

13. Aug 2016,
     P4, EBPF and Linux TC Offload,
     Dinan Gunawardena, Jakub Kicinski,
     https://de.slideshare.net/Open-NFP/p4-epbf-and-linux-tc-offload

12. Jul 2016,
     Linux Meetup, Santa Clara,
     eXpress Data Path,
     Brenden Blanco,
     https://www.slideshare.net/IOVisor/express-data-path-linux-meetup-santa-clara-july-2016

11. Jul 2016,
     Linux Meetup, Santa Clara,
     CETH for XDP,
     Yan Chan, Yunsong Lu,
     https://www.slideshare.net/IOVisor/ceth-for-xdp-linux-meetup-santa-clara-july-2016

10. May 2016,
     P4 workshop, Stanford,
     P4 on the Edge,
     John Fastabend,
     https://schd.ws/hosted_files/2016p4workshop/1d/Intel%20Fastabend-P4%20on%20the%20Edge.pdf

9. Mar 2016,
    Performance @Scale 2016, Menlo Park,
    Linux BPF Superpowers,
    Brendan Gregg,
    https://www.slideshare.net/brendangregg/linux-bpf-superpowers

8. Mar 2016,
    eXpress Data Path,
    Tom Herbert, Alexei Starovoitov,
    https://raw.githubusercontent.com/iovisor/bpf-docs/master/Express_Data_Path.pdf

7. Feb 2016,
    NetDev1.1, Seville,
    On getting tc classifier fully programmable with cls_bpf,
    Daniel Borkmann,
    http://borkmann.ch/talks/2016_netdev.pdf
    https://netdevconf.info/1.1/proceedings/papers/On-getting-tc-classifier-fully-programmable-with-cls-bpf.pdf

6. Jan 2016,
    FOSDEM 2016, Brussels,
    Linux tc and eBPF,
    Daniel Borkmann,
    http://borkmann.ch/talks/2016_fosdem.pdf

5. Oct 2015,
    LinuxCon Europe, Dublin,
    eBPF on the Mainframe,
    Michael Holzheu,
    https://events.static.linuxfound.org/sites/events/files/slides/ebpf_on_the_mainframe_lcon_2015.pdf

4. Aug 2015,
    Tracing Summit, Seattle,
    LLTng's Trace Filtering and beyond (with some eBPF goodness, of course!),
    Suchakra Sharma,
    https://raw.githubusercontent.com/iovisor/bpf-docs/master/ebpf_excerpt_20Aug2015.pdf

3. Jun 2015,
    LinuxCon Japan, Tokyo,
    Exciting Developments in Linux Tracing,
    Elena Zannoni,
    https://events.static.linuxfound.org/sites/events/files/slides/tracing-linux-ezannoni-linuxcon-ja-2015_0.pdf

2. Feb 2015,
    Collaboration Summit, Santa Rosa,
    BPF: In-kernel Virtual Machine,
    Alexei Starovoitov,
    https://events.static.linuxfound.org/sites/events/files/slides/bpf_collabsummit_2015feb20.pdf

1. Feb 2015,
    NetDev 0.1, Ottawa,
    BPF: In-kernel Virtual Machine,
    Alexei Starovoitov,
    https://netdevconf.info/0.1/sessions/15.html

0. Feb 2014,
    DevConf.cz, Brno,
    tc and cls_bpf: lightweight packet classifying with BPF,
    Daniel Borkmann,
    http://borkmann.ch/talks/2014_devconf.pdf

Further Documents
-----------------

- Dive into BPF: a list of reading material,
  Quentin Monnet
  (https://qmonnet.github.io/whirl-offload/2016/09/01/dive-into-bpf/)

- XDP - eXpress Data Path,
  Jesper Dangaard Brouer
  (https://prototype-kernel.readthedocs.io/en/latest/networking/XDP/index.html)
