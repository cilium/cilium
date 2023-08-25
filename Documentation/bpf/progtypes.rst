.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _bpf_program:

Program Types
=============

At the time of this writing, there are eighteen different BPF program types
available, two of the main types for networking are further explained in below
subsections, namely XDP BPF programs as well as tc BPF programs. Extensive
usage examples for the two program types for LLVM, iproute2 or other tools
are spread throughout the toolchain section and not covered here. Instead,
this section focuses on their architecture, concepts and use cases.

XDP
---

XDP stands for eXpress Data Path and provides a framework for BPF that enables
high-performance programmable packet processing in the Linux kernel. It runs
the BPF program at the earliest possible point in software, namely at the moment
the network driver receives the packet.

At this point in the fast-path the driver just picked up the packet from its
receive rings, without having done any expensive operations such as allocating
an ``skb`` for pushing the packet further up the networking stack, without
having pushed the packet into the GRO engine, etc. Thus, the XDP BPF program
is executed at the earliest point when it becomes available to the CPU for
processing.

XDP works in concert with the Linux kernel and its infrastructure, meaning
the kernel is not bypassed as in various networking frameworks that operate
in user space only. Keeping the packet in kernel space has several major
advantages:

* XDP is able to reuse all the upstream developed kernel networking drivers,
  user space tooling, or even other available in-kernel infrastructure such
  as routing tables, sockets, etc in BPF helper calls itself.
* Residing in kernel space, XDP has the same security model as the rest of
  the kernel for accessing hardware.
* There is no need for crossing kernel / user space boundaries since the
  processed packet already resides in the kernel and can therefore flexibly
  forward packets into other in-kernel entities like namespaces used by
  containers or the kernel's networking stack itself. This is particularly
  relevant in times of Meltdown and Spectre.
* Punting packets from XDP to the kernel's robust, widely used and efficient
  TCP/IP stack is trivially possible, allows for full reuse and does not
  require maintaining a separate TCP/IP stack as with user space frameworks.
* The use of BPF allows for full programmability, keeping a stable ABI with
  the same 'never-break-user-space' guarantees as with the kernel's system
  call ABI and compared to modules it also provides safety measures thanks to
  the BPF verifier that ensures the stability of the kernel's operation.
* XDP trivially allows for atomically swapping programs during runtime without
  any network traffic interruption or even kernel / system reboot.
* XDP allows for flexible structuring of workloads integrated into
  the kernel. For example, it can operate in "busy polling" or "interrupt
  driven" mode. Explicitly dedicating CPUs to XDP is not required. There
  are no special hardware requirements and it does not rely on hugepages.
* XDP does not require any third party kernel modules or licensing. It is
  a long-term architectural solution, a core part of the Linux kernel, and
  developed by the kernel community.
* XDP is already enabled and shipped everywhere with major distributions
  running a kernel equivalent to 4.8 or higher and supports most major 10G
  or higher networking drivers.

As a framework for running BPF in the driver, XDP additionally ensures that
packets are laid out linearly and fit into a single DMA'ed page which is
readable and writable by the BPF program. XDP also ensures that additional
headroom of 256 bytes is available to the program for implementing custom
encapsulation headers with the help of the ``bpf_xdp_adjust_head()`` BPF helper
or adding custom metadata in front of the packet through ``bpf_xdp_adjust_meta()``.

The framework contains XDP action codes further described in the section
below which a BPF program can return in order to instruct the driver how
to proceed with the packet, and it enables the possibility to atomically
replace BPF programs running at the XDP layer. XDP is tailored for
high-performance by design. BPF allows to access the packet data through
'direct packet access' which means that the program holds data pointers
directly in registers, loads the content into registers, respectively
writes from there into the packet.

The packet representation in XDP that is passed to the BPF program as
the BPF context looks as follows:

.. code-block:: c

    struct xdp_buff {
        void *data;
        void *data_end;
        void *data_meta;
        void *data_hard_start;
        struct xdp_rxq_info *rxq;
    };

``data`` points to the start of the packet data in the page, and as the
name suggests, ``data_end`` points to the end of the packet data. Since XDP
allows for a headroom, ``data_hard_start`` points to the maximum possible
headroom start in the page, meaning, when the packet should be encapsulated,
then ``data`` is moved closer towards ``data_hard_start`` via ``bpf_xdp_adjust_head()``.
The same BPF helper function also allows for decapsulation in which case
``data`` is moved further away from ``data_hard_start``.

``data_meta`` initially points to the same location as ``data`` but
``bpf_xdp_adjust_meta()`` is able to move the pointer towards ``data_hard_start``
as well in order to provide room for custom metadata which is invisible to
the normal kernel networking stack but can be read by tc BPF programs since
it is transferred from XDP to the ``skb``. Vice versa, it can remove or reduce
the size of the custom metadata through the same BPF helper function by
moving ``data_meta`` away from ``data_hard_start`` again. ``data_meta`` can
also be used solely for passing state between tail calls similarly to the
``skb->cb[]`` control block case that is accessible in tc BPF programs.

This gives the following relation respectively invariant for the ``struct xdp_buff``
packet pointers: ``data_hard_start`` <= ``data_meta`` <= ``data`` < ``data_end``.

The ``rxq`` field points to some additional per receive queue metadata which
is populated at ring setup time (not at XDP runtime):

.. code-block:: c

    struct xdp_rxq_info {
        struct net_device *dev;
        u32 queue_index;
        u32 reg_state;
    } ____cacheline_aligned;

The BPF program can retrieve ``queue_index`` as well as additional data
from the netdevice itself such as ``ifindex``, etc.

**BPF program return codes**

After running the XDP BPF program, a verdict is returned from the program in
order to tell the driver how to process the packet next. In the ``linux/bpf.h``
system header file all available return verdicts are enumerated:

.. code-block:: c

    enum xdp_action {
        XDP_ABORTED = 0,
        XDP_DROP,
        XDP_PASS,
        XDP_TX,
        XDP_REDIRECT,
    };

``XDP_DROP`` as the name suggests will drop the packet right at the driver
level without wasting any further resources. This is in particular useful
for BPF programs implementing DDoS mitigation mechanisms or firewalling in
general. The ``XDP_PASS`` return code means that the packet is allowed to
be passed up to the kernel's networking stack. Meaning, the current CPU
that was processing this packet now allocates a ``skb``, populates it, and
passes it onwards into the GRO engine. This would be equivalent to the
default packet handling behavior without XDP. With ``XDP_TX`` the BPF program
has an efficient option to transmit the network packet out of the same NIC it
just arrived on again. This is typically useful when few nodes are implementing,
for example, firewalling with subsequent load balancing in a cluster and
thus act as a hairpinned load balancer pushing the incoming packets back
into the switch after rewriting them in XDP BPF. ``XDP_REDIRECT`` is similar
to ``XDP_TX`` in that it is able to transmit the XDP packet, but through
another NIC. Another option for the ``XDP_REDIRECT`` case is to redirect
into a BPF cpumap, meaning, the CPUs serving XDP on the NIC's receive queues
can continue to do so and push the packet for processing the upper kernel
stack to a remote CPU. This is similar to ``XDP_PASS``, but with the ability
that the XDP BPF program can keep serving the incoming high load as opposed
to temporarily spend work on the current packet for pushing into upper
layers. Last but not least, ``XDP_ABORTED`` which serves denoting an exception
like state from the program and has the same behavior as ``XDP_DROP`` only
that ``XDP_ABORTED`` passes the ``trace_xdp_exception`` tracepoint which
can be additionally monitored to detect misbehavior.

**Use cases for XDP**

Some of the main use cases for XDP are presented in this subsection. The
list is non-exhaustive and given the programmability and efficiency XDP
and BPF enables, it can easily be adapted to solve very specific use
cases.

* **DDoS mitigation, firewalling**

  One of the basic XDP BPF features is to tell the driver to drop a packet
  with ``XDP_DROP`` at this early stage which allows for any kind of efficient
  network policy enforcement with having an extremely low per-packet cost.
  This is ideal in situations when needing to cope with any sort of DDoS
  attacks, but also more general allows to implement any sort of firewalling
  policies with close to no overhead in BPF e.g. in either case as stand alone
  appliance (e.g. scrubbing 'clean' traffic through ``XDP_TX``) or widely
  deployed on nodes protecting end hosts themselves (via ``XDP_PASS`` or
  cpumap ``XDP_REDIRECT`` for good traffic). Offloaded XDP takes this even
  one step further by moving the already small per-packet cost entirely
  into the NIC with processing at line-rate.

..

* **Forwarding and load-balancing**

  Another major use case of XDP is packet forwarding and load-balancing
  through either ``XDP_TX`` or ``XDP_REDIRECT`` actions. The packet can
  be arbitrarily mangled by the BPF program running in the XDP layer,
  even BPF helper functions are available for increasing or decreasing
  the packet's headroom in order to arbitrarily encapsulate respectively
  decapsulate the packet before sending it out again. With ``XDP_TX``
  hairpinned load-balancers can be implemented that push the packet out
  of the same networking device it originally arrived on, or with the
  ``XDP_REDIRECT`` action it can be forwarded to another NIC for
  transmission. The latter return code can also be used in combination
  with BPF's cpumap to load-balance packets for passing up the local
  stack, but on remote, non-XDP processing CPUs.

..

* **Pre-stack filtering / processing**

  Besides policy enforcement, XDP can also be used for hardening the
  kernel's networking stack with the help of ``XDP_DROP`` case, meaning,
  it can drop irrelevant packets for a local node right at the earliest
  possible point before the networking stack sees them e.g. given we
  know that a node only serves TCP traffic, any UDP, SCTP or other L4
  traffic can be dropped right away. This has the advantage that packets
  do not need to traverse various entities like GRO engine, the kernel's
  flow dissector and others before it can be determined to drop them and
  thus this allows for reducing the kernel's attack surface. Thanks to
  XDP's early processing stage, this effectively 'pretends' to the kernel's
  networking stack that these packets have never been seen by the networking
  device. Additionally, if a potential bug in the stack's receive path
  got uncovered and would cause a 'ping of death' like scenario, XDP can be
  utilized to drop such packets right away without having to reboot the
  kernel or restart any services. Due to the ability to atomically swap
  such programs to enforce a drop of bad packets, no network traffic is
  even interrupted on a host.

  Another use case for pre-stack processing is that given the kernel has not
  yet allocated an ``skb`` for the packet, the BPF program is free to modify
  the packet and, again, have it 'pretend' to the stack that it was received
  by the networking device this way. This allows for cases such as having
  custom packet mangling and encapsulation protocols where the packet can be
  decapsulated prior to entering GRO aggregation in which GRO otherwise would
  not be able to perform any sort of aggregation due to not being aware of
  the custom protocol. XDP also allows to push metadata (non-packet data) in
  front of the packet. This is 'invisible' to the normal kernel stack, can
  be GRO aggregated (for matching metadata) and later on processed in
  coordination with a tc ingress BPF program where it has the context of
  a ``skb`` available for e.g. setting various skb fields.

..

* **Flow sampling, monitoring**

  XDP can also be used for cases such as packet monitoring, sampling or any
  other network analytics, for example, as part of an intermediate node in
  the path or on end hosts in combination also with prior mentioned use cases.
  For complex packet analysis, XDP provides a facility to efficiently push
  network packets (truncated or with full payload) and custom metadata into
  a fast lockless per CPU memory mapped ring buffer provided from the Linux
  perf infrastructure to an user space application. This also allows for
  cases where only a flow's initial data can be analyzed and once determined
  as good traffic having the monitoring bypassed. Thanks to the flexibility
  brought by BPF, this allows for implementing any sort of custom monitoring
  or sampling.

..

One example of XDP BPF production usage is Facebook's SHIV and Droplet
infrastructure which implement their L4 load-balancing and DDoS countermeasures.
Migrating their production infrastructure away from netfilter's IPVS
(IP Virtual Server) over to XDP BPF allowed for a 10x speedup compared
to their previous IPVS setup. This was first presented at the netdev 2.1
conference:

* Slides: https://netdevconf.info/2.1/slides/apr6/zhou-netdev-xdp-2017.pdf
* Video: https://youtu.be/YEU2ClcGqts

Another example is the integration of XDP into Cloudflare's DDoS mitigation
pipeline, which originally was using cBPF instead of eBPF for attack signature
matching through iptables' ``xt_bpf`` module. Due to use of iptables this
caused severe performance problems under attack where a user space bypass
solution was deemed necessary but came with drawbacks as well such as needing
to busy poll the NIC and expensive packet re-injection into the kernel's stack.
The migration over to eBPF and XDP combined best of both worlds by having
high-performance programmable packet processing directly inside the kernel:

* Slides: https://netdevconf.info/2.1/slides/apr6/bertin_Netdev-XDP.pdf
* Video: https://youtu.be/7OuOukmuivg

**XDP operation modes**

XDP has three operation modes where 'native' XDP is the default mode. When
talked about XDP this mode is typically implied.

* **Native XDP**

  This is the default mode where the XDP BPF program is run directly out
  of the networking driver's early receive path. Most widespread used NICs
  for 10G and higher support native XDP already.

..

* **Offloaded XDP**

  In the offloaded XDP mode the XDP BPF program is directly offloaded into
  the NIC instead of being executed on the host CPU. Thus, the already
  extremely low per-packet cost is pushed off the host CPU entirely and
  executed on the NIC, providing even higher performance than running in
  native XDP. This offload is typically implemented by SmartNICs
  containing multi-threaded, multicore flow processors where a in-kernel
  JIT compiler translates BPF into native instructions for the latter.
  Drivers supporting offloaded XDP usually also support native XDP for
  cases where some BPF helpers may not yet or only be available for the
  native mode.

..

* **Generic XDP**

  For drivers not implementing native or offloaded XDP yet, the kernel
  provides an option for generic XDP which does not require any driver
  changes since run at a much later point out of the networking stack.
  This setting is primarily targeted at developers who want to write and
  test programs against the kernel's XDP API, and will not operate at the
  performance rate of the native or offloaded modes. For XDP usage in a
  production environment either the native or offloaded mode is better
  suited and the recommended way to run XDP.

.. _xdp_drivers:

**Driver support**

**Drivers supporting native XDP**

A list of drivers supporting native XDP can be found in the table below. The
corresponding network driver name of an interface can be determined as follows:

.. code-block:: shell-session

    # ethtool -i eth0
    driver: nfp
    [...]

+-------------------+------------+-------------+
| Vendor            | Driver     | XDP Support |
+===================+============+=============+
| Amazon            | ena        | >= 5.6      |
+-------------------+------------+-------------+
| Broadcom          | bnxt_en    | >= 4.11     |
+-------------------+------------+-------------+
| Cavium            | thunderx   | >= 4.12     |
+-------------------+------------+-------------+
| Freescale         | dpaa2      | >= 5.0      |
+-------------------+------------+-------------+
| Intel             | ixgbe      | >= 4.12     |
|                   +------------+-------------+
|                   | ixgbevf    | >= 4.17     |
|                   +------------+-------------+
|                   | i40e       | >= 4.13     |
|                   +------------+-------------+
|                   | ice        | >= 5.5      |
+-------------------+------------+-------------+
| Marvell           | mvneta     | >= 5.5      |
+-------------------+------------+-------------+
| Mellanox          | mlx4       | >= 4.8      |
|                   +------------+-------------+
|                   | mlx5       | >= 4.9      |
+-------------------+------------+-------------+
| Microsoft         | hv_netvsc  | >= 5.6      |
+-------------------+------------+-------------+
| Netronome         | nfp        | >= 4.10     |
+-------------------+------------+-------------+
| Others            | virtio_net | >= 4.10     |
|                   +------------+-------------+
|                   | tun/tap    | >= 4.14     |
|                   +------------+-------------+
|                   | bond       | >= 5.15     |
+-------------------+------------+-------------+
| Qlogic            | qede       | >= 4.10     |
+-------------------+------------+-------------+
| Socionext         | netsec     | >= 5.3      |
+-------------------+------------+-------------+
| Solarflare        | sfc        | >= 5.5      |
+-------------------+------------+-------------+
| Texas Instruments | cpsw       | >= 5.3      |
+-------------------+------------+-------------+

**Drivers supporting offloaded XDP**

* **Netronome**

  * nfp [2]_

.. note::

    Examples for writing and loading XDP programs are included in the `bpf_dev` section under the respective tools.

.. [2] Some BPF helper functions such as retrieving the current CPU number
   will not be available in an offloaded setting.

tc (traffic control)
--------------------

Aside from other program types such as XDP, BPF can also be used out of the
kernel's tc (traffic control) layer in the networking data path. On a high-level
there are three major differences when comparing XDP BPF programs to tc BPF
ones:

* The BPF input context is a ``sk_buff`` not a ``xdp_buff``. When the kernel's
  networking stack receives a packet, after the XDP layer, it allocates a buffer
  and parses the packet to store metadata about the packet. This representation
  is known as the ``sk_buff``. This structure is then exposed in the BPF input
  context so that BPF programs from the tc ingress layer can use the metadata that
  the stack extracts from the packet. This can be useful, but comes with an
  associated cost of the stack performing this allocation and metadata extraction,
  and handling the packet until it hits the tc hook. By definition, the ``xdp_buff``
  doesn't have access to this metadata because the XDP hook is called before
  this work is done. This is a significant contributor to the performance
  difference between the XDP and tc hooks.

  Therefore, BPF programs attached to the tc BPF hook can, for instance, read or
  write the skb's ``mark``, ``pkt_type``, ``protocol``, ``priority``,
  ``queue_mapping``, ``napi_id``, ``cb[]`` array, ``hash``, ``tc_classid`` or
  ``tc_index``, vlan metadata, the XDP transferred custom metadata and various
  other information. All members of the ``struct __sk_buff`` BPF context used
  in tc BPF are defined in the ``linux/bpf.h`` system header.

  Generally, the ``sk_buff`` is of a completely different nature than
  ``xdp_buff`` where both come with advantages and disadvantages. For example,
  the ``sk_buff`` case has the advantage that it is rather straight forward to
  mangle its associated metadata, however, it also contains a lot of protocol
  specific information (e.g. GSO related state) which makes it difficult to
  simply switch protocols by solely rewriting the packet data. This is due to
  the stack processing the packet based on the metadata rather than having the
  cost of accessing the packet contents each time. Thus, additional conversion
  is required from BPF helper functions taking care that ``sk_buff`` internals
  are properly converted as well. The ``xdp_buff`` case however does not
  face such issues since it comes at such an early stage where the kernel
  has not even allocated an ``sk_buff`` yet, thus packet rewrites of any
  kind can be realized trivially. However, the ``xdp_buff`` case has the
  disadvantage that ``sk_buff`` metadata is not available for mangling
  at this stage. The latter is overcome by passing custom metadata from
  XDP BPF to tc BPF, though. In this way, the limitations of each program
  type can be overcome by operating complementary programs of both types
  as the use case requires.

..

* Compared to XDP, tc BPF programs can be triggered out of ingress and also
  egress points in the networking data path as opposed to ingress only in
  the case of XDP.

  The two hook points ``sch_handle_ingress()`` and ``sch_handle_egress()`` in
  the kernel are triggered out of ``__netif_receive_skb_core()`` and
  ``__dev_queue_xmit()``, respectively. The latter two are the main receive
  and transmit functions in the data path that, setting XDP aside, are triggered
  for every network packet going in or coming out of the node allowing for
  full visibility for tc BPF programs at these hook points.

..

* The tc BPF programs do not require any driver changes since they are run
  at hook points in generic layers in the networking stack. Therefore, they
  can be attached to any type of networking device.

  While this provides flexibility, it also trades off performance compared
  to running at the native XDP layer. However, tc BPF programs still come
  at the earliest point in the generic kernel's networking data path after
  GRO has been run but **before** any protocol processing, traditional iptables
  firewalling such as iptables PREROUTING or nftables ingress hooks or other
  packet processing takes place. Likewise on egress, tc BPF programs execute
  at the latest point before handing the packet to the driver itself for
  transmission, meaning **after** traditional iptables firewalling hooks like
  iptables POSTROUTING, but still before handing the packet to the kernel's
  GSO engine.

  One exception which does require driver changes however are offloaded tc
  BPF programs, typically provided by SmartNICs in a similar way as offloaded
  XDP just with differing set of features due to the differences in the BPF
  input context, helper functions and verdict codes.

..

BPF programs run in the tc layer are run from the ``cls_bpf`` classifier.
While the tc terminology describes the BPF attachment point as a "classifier",
this is a bit misleading since it under-represents what ``cls_bpf`` is
capable of. That is to say, a fully programmable packet processor being able
not only to read the ``skb`` metadata and packet data, but to also arbitrarily
mangle both, and terminate the tc processing with an action verdict. ``cls_bpf``
can thus be regarded as a self-contained entity that manages and executes tc
BPF programs.

``cls_bpf`` can hold one or more tc BPF programs. In the case where Cilium
deploys ``cls_bpf`` programs, it attaches only a single program for a given hook
in ``direct-action`` mode. Typically, in the traditional tc scheme, there is a
split between classifier and action modules, where the classifier has one
or more actions attached to it that are triggered once the classifier has a
match. In the modern world for using tc in the software data path this model
does not scale well for complex packet processing. Given tc BPF programs
attached to ``cls_bpf`` are fully self-contained, they effectively fuse the
parsing and action process together into a single unit. Thanks to ``cls_bpf``'s
``direct-action`` mode, it will just return the tc action verdict and
terminate the processing pipeline immediately. This allows for implementing
scalable programmable packet processing in the networking data path by avoiding
linear iteration of actions. ``cls_bpf`` is the only such "classifier" module
in the tc layer capable of such a fast-path.

Like XDP BPF programs, tc BPF programs can be atomically updated at runtime
via ``cls_bpf`` without interrupting any network traffic or having to restart
services.

Both the tc ingress and the egress hook where ``cls_bpf`` itself can be
attached to is managed by a pseudo qdisc called ``sch_clsact``. This is a
drop-in replacement and proper superset of the ingress qdisc since it
is able to manage both, ingress and egress tc hooks. For tc's egress hook
in ``__dev_queue_xmit()`` it is important to stress that it is not executed
under the kernel's qdisc root lock. Thus, both tc ingress and egress hooks
are executed in a lockless manner in the fast-path. In either case, preemption
is disabled and execution happens under RCU read side.

Typically on egress there are qdiscs attached to netdevices such as ``sch_mq``,
``sch_fq``, ``sch_fq_codel`` or ``sch_htb`` where some of them are classful
qdiscs that contain subclasses and thus require a packet classification
mechanism to determine a verdict where to demux the packet. This is handled
by a call to ``tcf_classify()`` which calls into tc classifiers if present.
``cls_bpf`` can also be attached and used in such cases. Such operation usually
happens under the qdisc root lock and can be subject to lock contention. The
``sch_clsact`` qdisc's egress hook comes at a much earlier point however which
does not fall under that and operates completely independent from conventional
egress qdiscs. Thus for cases like ``sch_htb`` the ``sch_clsact`` qdisc could
perform the heavy lifting packet classification through tc BPF outside of the
qdisc root lock, setting the ``skb->mark`` or ``skb->priority`` from there such
that ``sch_htb`` only requires a flat mapping without expensive packet
classification under the root lock thus reducing contention.

Offloaded tc BPF programs are supported for the case of ``sch_clsact`` in
combination with ``cls_bpf`` where the prior loaded BPF program was JITed
from a SmartNIC driver to be run natively on the NIC. Only ``cls_bpf``
programs operating in ``direct-action`` mode are supported to be offloaded.
``cls_bpf`` only supports offloading a single program and cannot offload
multiple programs. Furthermore only the ingress hook supports offloading
BPF programs.

One ``cls_bpf`` instance is able to hold multiple tc BPF programs internally.
If this is the case, then the ``TC_ACT_UNSPEC`` program return code will
continue execution with the next tc BPF program in that list. However, this
has the drawback that several programs would need to parse the packet over
and over again resulting in degraded performance.

**BPF program return codes**

Both the tc ingress and egress hook share the same action return verdicts
that tc BPF programs can use. They are defined in the ``linux/pkt_cls.h``
system header:

.. code-block:: c

    #define TC_ACT_UNSPEC         (-1)
    #define TC_ACT_OK               0
    #define TC_ACT_SHOT             2
    #define TC_ACT_STOLEN           4
    #define TC_ACT_REDIRECT         7

There are a few more action ``TC_ACT_*`` verdicts available in the system
header file which are also used in the two hooks. However, they share the
same semantics with the ones above. Meaning, from a tc BPF perspective,
``TC_ACT_OK`` and ``TC_ACT_RECLASSIFY`` have the same semantics, as well as
the three ``TC_ACT_STOLEN``, ``TC_ACT_QUEUED`` and ``TC_ACT_TRAP`` opcodes.
Therefore, for these cases we only describe ``TC_ACT_OK`` and the ``TC_ACT_STOLEN``
opcode for the two groups.

Starting out with ``TC_ACT_UNSPEC``. It has the meaning of "unspecified action"
and is used in three cases, i) when an offloaded tc BPF program is attached
and the tc ingress hook is run where the ``cls_bpf`` representation for the
offloaded program will return ``TC_ACT_UNSPEC``, ii) in order to continue
with the next tc BPF program in ``cls_bpf`` for the multi-program case. The
latter also works in combination with offloaded tc BPF programs from point i)
where the ``TC_ACT_UNSPEC`` from there continues with a next tc BPF program
solely running in non-offloaded case. Last but not least, iii) ``TC_ACT_UNSPEC``
is also used for the single program case to simply tell the kernel to continue
with the ``skb`` without additional side-effects. ``TC_ACT_UNSPEC`` is very
similar to the ``TC_ACT_OK`` action code in the sense that both pass the
``skb`` onwards either to upper layers of the stack on ingress or down to
the networking device driver for transmission on egress, respectively. The
only difference to ``TC_ACT_OK`` is that ``TC_ACT_OK`` sets ``skb->tc_index``
based on the classid the tc BPF program set. The latter is set out of the
tc BPF program itself through ``skb->tc_classid`` from the BPF context.

``TC_ACT_SHOT`` instructs the kernel to drop the packet, meaning, upper
layers of the networking stack will never see the ``skb`` on ingress and
similarly the packet will never be submitted for transmission on egress.
``TC_ACT_SHOT`` and ``TC_ACT_STOLEN`` are both similar in nature with few
differences: ``TC_ACT_SHOT`` will indicate to the kernel that the ``skb``
was released through ``kfree_skb()`` and return ``NET_XMIT_DROP`` to the
callers for immediate feedback, whereas ``TC_ACT_STOLEN`` will release
the ``skb`` through ``consume_skb()`` and pretend to upper layers that
the transmission was successful through ``NET_XMIT_SUCCESS``. The perf's
drop monitor which records traces of ``kfree_skb()`` will therefore
also not see any drop indications from ``TC_ACT_STOLEN`` since its
semantics are such that the ``skb`` has been "consumed" or queued but
certainly not "dropped".

Last but not least the ``TC_ACT_REDIRECT`` action which is available for
tc BPF programs as well. This allows to redirect the ``skb`` to the same
or another's device ingress or egress path together with the ``bpf_redirect()``
helper. Being able to inject the packet into another device's ingress or
egress direction allows for full flexibility in packet forwarding with
BPF. There are no requirements on the target networking device other than
being a networking device itself, there is no need to run another instance
of ``cls_bpf`` on the target device or other such restrictions.

**tc BPF FAQ**

This section contains a few miscellaneous question and answer pairs related to
tc BPF programs that are asked from time to time.

* **Question:** What about ``act_bpf`` as a tc action module, is it still relevant?
* **Answer:** Not really. Although ``cls_bpf`` and ``act_bpf`` share the same
  functionality for tc BPF programs, ``cls_bpf`` is more flexible since it is a
  proper superset of ``act_bpf``. The way tc works is that tc actions need to be
  attached to tc classifiers. In order to achieve the same flexibility as ``cls_bpf``,
  ``act_bpf`` would need to be attached to the ``cls_matchall`` classifier. As the
  name says, this will match on every packet in order to pass them through for attached
  tc action processing. For ``act_bpf``, this is will result in less efficient packet
  processing than using ``cls_bpf`` in ``direct-action`` mode directly. If ``act_bpf``
  is used in a setting with other classifiers than ``cls_bpf`` or ``cls_matchall``
  then this will perform even worse due to the nature of operation of tc classifiers.
  Meaning, if classifier A has a mismatch, then the packet is passed to classifier
  B, reparsing the packet, etc, thus in the typical case there will be linear
  processing where the packet would need to traverse N classifiers in the worst
  case to find a match and execute ``act_bpf`` on that. Therefore, ``act_bpf`` has
  never been largely relevant. Additionally, ``act_bpf`` does not provide a tc
  offloading interface either compared to ``cls_bpf``.

..

* **Question:** Is it recommended to use ``cls_bpf`` not in ``direct-action`` mode?
* **Answer:** No. The answer is similar to the one above in that this is otherwise
  unable to scale for more complex processing. tc BPF can already do everything needed
  by itself in an efficient manner and thus there is no need for anything other than
  ``direct-action`` mode.

..

* **Question:** Is there any performance difference in offloaded ``cls_bpf`` and
  offloaded XDP?
* **Answer:** No. Both are JITed through the same compiler in the kernel which
  handles the offloading to the SmartNIC and the loading mechanism for both is
  very similar as well. Thus, the BPF program gets translated into the same target
  instruction set in order to be able to run on the NIC natively. The two tc BPF
  and XDP BPF program types have a differing set of features, so depending on the
  use case one might be picked over the other due to availability of certain helper
  functions in the offload case, for example.

**Use cases for tc BPF**

Some of the main use cases for tc BPF programs are presented in this subsection.
Also here, the list is non-exhaustive and given the programmability and efficiency
of tc BPF, it can easily be tailored and integrated into orchestration systems
in order to solve very specific use cases. While some use cases with XDP may overlap,
tc BPF and XDP BPF are mostly complementary to each other and both can also be
used at the same time or one over the other depending which is most suitable for a
given problem to solve.

* **Policy enforcement for containers**

  One application which tc BPF programs are suitable for is to implement policy
  enforcement, custom firewalling or similar security measures for containers or
  pods, respectively. In the conventional case, container isolation is implemented
  through network namespaces with veth networking devices connecting the host's
  initial namespace with the dedicated container's namespace. Since one end of
  the veth pair has been moved into the container's namespace whereas the other
  end remains in the initial namespace of the host, all network traffic from the
  container has to pass through the host-facing veth device allowing for attaching
  tc BPF programs on the tc ingress and egress hook of the veth. Network traffic
  going into the container will pass through the host-facing veth's tc egress
  hook whereas network traffic coming from the container will pass through the
  host-facing veth's tc ingress hook.

  For virtual devices like veth devices XDP is unsuitable in this case since the
  kernel operates solely on a ``skb`` here and generic XDP has a few limitations
  where it does not operate with cloned ``skb``'s. The latter is heavily used
  from the TCP/IP stack in order to hold data segments for retransmission where
  the generic XDP hook would simply get bypassed instead. Moreover, generic XDP
  needs to linearize the entire ``skb`` resulting in heavily degraded performance.
  tc BPF on the other hand is more flexible as it specializes on the ``skb``
  input context case and thus does not need to cope with the limitations from
  generic XDP.

..

* **Forwarding and load-balancing**

  The forwarding and load-balancing use case is quite similar to XDP, although
  slightly more targeted towards east-west container workloads rather than
  north-south traffic (though both technologies can be used in either case).
  Since XDP is only available on ingress side, tc BPF programs allow for
  further use cases that apply in particular on egress, for example, container
  based traffic can already be NATed and load-balanced on the egress side
  through BPF out of the initial namespace such that this is done transparent
  to the container itself. Egress traffic is already based on the ``sk_buff``
  structure due to the nature of the kernel's networking stack, so packet
  rewrites and redirects are suitable out of tc BPF. By utilizing the
  ``bpf_redirect()`` helper function, BPF can take over the forwarding logic
  to push the packet either into the ingress or egress path of another networking
  device. Thus, any bridge-like devices become unnecessary to use as well by
  utilizing tc BPF as forwarding fabric.

..

* **Flow sampling, monitoring**

  Like in XDP case, flow sampling and monitoring can be realized through a
  high-performance lockless per-CPU memory mapped perf ring buffer where the
  BPF program is able to push custom data, the full or truncated packet
  contents, or both up to a user space application. From the tc BPF program
  this is realized through the ``bpf_skb_event_output()`` BPF helper function
  which has the same function signature and semantics as ``bpf_xdp_event_output()``.
  Given tc BPF programs can be attached to ingress and egress as opposed to
  only ingress in XDP BPF case plus the two tc hooks are at the lowest layer
  in the (generic) networking stack, this allows for bidirectional monitoring
  of all network traffic from a particular node. This might be somewhat related
  to the cBPF case which tcpdump and Wireshark makes use of, though, without
  having to clone the ``skb`` and with being a lot more flexible in terms of
  programmability where, for example, BPF can already perform in-kernel
  aggregation rather than pushing everything up to user space as well as
  custom annotations for packets pushed into the ring buffer. The latter is
  also heavily used in Cilium where packet drops can be further annotated
  to correlate container labels and reasons for why a given packet had to
  be dropped (such as due to policy violation) in order to provide a richer
  context.

..

* **Packet scheduler pre-processing**

  The ``sch_clsact``'s egress hook which is called ``sch_handle_egress()``
  runs right before taking the kernel's qdisc root lock, thus tc BPF programs
  can be utilized to perform all the heavy lifting packet classification
  and mangling before the packet is transmitted into a real full blown
  qdisc such as ``sch_htb``. This type of interaction of ``sch_clsact``
  with a real qdisc like ``sch_htb`` coming later in the transmission phase
  allows to reduce the lock contention on transmission since ``sch_clsact``'s
  egress hook is executed without taking locks.

..

One concrete example user of tc BPF but also XDP BPF programs is Cilium.
Cilium is open source software for transparently securing the network
connectivity between application services deployed using Linux container
management platforms like Docker and Kubernetes and operates at Layer 3/4
as well as Layer 7. At the heart of Cilium operates BPF in order to
implement the policy enforcement as well as load balancing and monitoring.

* Slides: https://www.slideshare.net/ThomasGraf5/dockercon-2017-cilium-network-and-application-security-with-bpf-and-xdp
* Video: https://youtu.be/ilKlmTDdFgk
* Github: https://github.com/cilium/cilium

**Driver support**

Since tc BPF programs are triggered from the kernel's networking stack
and not directly out of the driver, they do not require any extra driver
modification and therefore can run on any networking device. The only
exception listed below is for offloading tc BPF programs to the NIC.

**Drivers supporting offloaded tc BPF**

* **Netronome**

  * nfp [2]_

.. note::

    Examples for writing and loading tc BPF programs are included in the `bpf_dev` section under the respective tools.
