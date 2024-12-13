.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _xfrm_guide:

********************
XFRM Reference Guide
********************

.. note:: This documentation section is targeted at developers and users who
          want to understand the Linux XFRM subsystem. While reading this
          reference guide may help broaden your understanding of Cilium, it is
          not a requirement to use Cilium. Please refer to the
          :ref:`getting_started` guide and :ref:`ebpf_datapath` for a higher
          level introduction.

Overview
========

IPsec encryption in the Linux kernel relies on `XFRM`_. XFRM is an IP framework intended for packet
transformations, from encryption to compression. It is configured via a set of *policy* and *state*
objects, which for IPsec, correspond to Security Policies and Security Associations.

.. _XFRM: https://man7.org/linux/man-pages/man8/ip-xfrm.8.html

XFRM Policies and States
------------------------

At a high-level, XFRM policies define what traffic to accept and reject, whereas states define how to
perform the encryption and decryption. Policies can match on the direction (``out``, ``in``, or
``fwd``), the source and destination IP addresses with CIDRs, and the packet mark. As an example,
the following policy matches egressing packets with any source IP address, 10.56.1.X destination IP
addresses, and ``0xcb93eXX`` packet marks. Policies default to allowing traffic as done here.

.. code-block:: text

    src 0.0.0.0/0 dst 10.56.1.0/24 
        dir out priority 0 
        mark 0xcb93e00/0xffffff00 
        [...]

States are relatively similar, except that they are agnostic to the direction and can only match on
exact IP addresses (or 0.0.0.0 to match all). The following state will apply to packets with IP
addresses 10.56.0.17 -> 10.56.1.238, the same packet marks as above. In the case of tunnel-mode
IPsec, these IP addresses correspond to the outer IP addresses. For ingressing, encrypted packets,
the SPI will also be used (discussed below).

.. code-block:: text

    src 10.56.0.17 dst 10.56.1.238
        proto esp spi 0x00000003 reqid 1 mode tunnel
        replay-window 0 
        mark 0xcb93e00/0xffffff00 output-mark 0xe00/0xffffff00
        aead rfc4106(gcm(aes)) 0x6254fced5f7a5ea9401b9015ecf10d65eac51a69 128
        anti-replay context: seq 0x0, oseq 0x36, bitmap 0x00000000
        sel src 0.0.0.0/0 dst 0.0.0.0/0

You may notice that nothing specifies if this state should perform encryption or decryption. That's
because it can actually do both. As said above, states are agnostic to the direction of traffic so
the same state may theoretically be used for both encryption and decryption. What to do will be
determined based on where in the stack the state is matched (ex., decryption on ingress).

Policy Templates
----------------

XFRM policies also typically define a template, as below:

.. code-block:: text

    src 0.0.0.0/0 dst 10.56.1.0/24 
        dir out priority 0 
        mark 0xcb93e00/0xffffff00 
        tmpl src 10.56.0.17 dst 10.56.1.238
            proto esp spi 0x00000003 reqid 1 mode tunnel

How this template is used depends on the direction. For egressing traffic, the template defines the
encoding to perform. For example, the above template will encapsulate packets with an IP header and
an ESP header. The IP header will have IP addresses 10.56.0.17 and 10.56.1.238. The ESP header will
have SPI 3.

For ingressing and forwarded traffic however, the template acts as an additional filter. The
following XFRM policy for example will only allow packets if they are ESP packets with outer IP
addresses 10.56.1.238 and 10.56.0.17, in addition to having a packet mark matching ``0xd00/0xf00``.

.. code-block:: text

    src 0.0.0.0/0 dst 10.56.0.0/24 
        dir in priority 0 
        mark 0xd00/0xf00 
        tmpl src 10.56.1.238 dst 10.56.0.17
            proto esp reqid 1 mode tunnel

Note that when using tunnel mode as is the case here, we should always see XFRM states matching the
template of XFRM OUT policies. That is because, on egress, the states are matched after the
template is applied. The IP addresses, the SPI, the protocol, the mode, and the reqid should all
match between the XFRM state and the template in that case.


XFRM Packet Flows
=================

The following diagram represents the usual Netfilter packet flow with the XFRM elements in purple:

.. image:: /images/netfilter-with-xfrm.png
    :align: center


Egress Packet Flow
------------------

On egress, packets will first hit one of the "XFRM OUT policy" blocks. At this point, a lookup is
performed against the XFRM OUT policies. If a match is found, the packet goes to the "XFRM encode"
block, any template is applied (ex., encapsulation), and the packet is then matched against XFRM
states. If a state is found, its information is used to encrypt the packet.

The encrypted packet will then navigate again through the OUTPUT and POSTROUTING chains.

Ingress Packet Flow
-------------------

On ingress, encrypted packets (ex., ESP packets) will hit the "XFRM decode" after they navigate
through the INPUT chain.

In tunnel mode, encrypted packets will typically have one of the server's IP addresses as the outer
destination address, so they should automatically be routed through the INPUT chain. If not, it may
be necessary to add IP routes to redirect packets to the INPUT chain. As an example, Cilium
identifies IPsec traffic on tc-bpf ingress and marks them with a special value which is then used
to reroute those packets to the INPUT chain.

At the "XFRM decode", if packets match an XFRM state, they will be decoded (i.e., decapsulated and
decrypted) using the state's information. The match is based on the source & destination addresses,
the mark, the SPI, and the protocol. In case of any decode error (ex., wrong key), the packet is
dropped and an error counter is increased.

As illustrated on the diagram, an XFRM policy matching the packet isn't required for the decoding
to happen (it goes directly to "XFRM decode"), but is required for the packet to proceed to a
local process or through the FORWARD chain. An XFRM policy with an optional template (i.e.,
``level use``) will allow all decoded packets through. Traffic that was never encrypted, and
therefore does not come from "XFRM decode", is allowed by default.

After a packet is decoded, it is recirculated in the stack, as if coming from the interface it was
initially received on. More specifically, packets are recirculated before the tc layer, such that
they are visible on the tc-bpf hook a second time (once before decryption, once after). The packet
mark is preserved when recirculated, so it's possible to identify and trace packets that have been
decrypted and recirculated.


Output Description of ``ip xfrm``
=================================

Outputs are from iproute2-6.1.0. More fields will likely appear in newer versions. For example,
XFRM states have a ``dir`` field in newer kernels (v6.10+), which will likely appear in the
``ip xfrm state`` output at some point.

In the ``ip xfrm`` output, policies are ordered by date of creation, with newer policies at the
top. This is important because, in case two policies match a packet and have the same priority,
the newest one is used.

.. code-block:: bash

    $ ip xfrm policy
    # - `src 0.0.0.0/0` is the CIDR to match against the source IP address
    # - `dst 0.0.0.0/0` is the CIDR to match against the destination IP address
    src 0.0.0.0/0 dst 0.0.0.0/0 uid 0
        # - `dir fwd` states the direction. It defines where in the Linux stack this policy will be
        #   used, between ingress, egress, and forwarding.
        # - `action allow` is the action to take on matching packets. Packets can only be allowed
        #   through (by default) or dropped.
        # - `index 18` is used to differentiate between different policies which might have the
        #   same or overlapping selectors. If not given or if it already exists, it is
        #   automatically (re-)generated (cf., `xfrm_gen_index`). The three LSBs encode the
        #   direction (ex., 1 for `XFRM_POLICY_OUT`). The MSBs are simply incremented by one (that
        #   is, the index is incremented by 8) until a free index is found.
        # - `priority 2975` states the priority for this policy in case multiple could match the
        #   packet. 0 is the highest priority.
        # - `share any` is always set to `any` and unused today
        #    (https://elixir.bootlin.com/linux/v6.9.5/source/net/xfrm/xfrm_user.c#L1914).
        # - `flag (0x00000000)` set of flags for XFRM policies. Only `XFRM_POLICY_ICMP` (0x2) is
        #   supported at the moment; `XFRM_POLICY_LOCALOK` (0x1) is not implemented (anymore?).
        #   When `XFRM_POLICY_ICMP` is given, the policy will also apply to ICMP packet with a
        #   payload packet that matches the policy's selector.
        dir fwd action allow index 18 priority 2975 share any flag  (0x00000000)
        lifetime config:
          # Various limits and expiration times for the policy, based on the number of bytes
          # received, the number of packets received, the time since the policy was added, or the
          # time since the policy was last matched by a packet. When a soft limit or expiration
          # time is reached, a notification is sent to userspace via netlink
          # (`struct xfrm_user_expire`). When a hard limit or expiration time is reached, the
          # policy is deleted.
          limit: soft (INF)(bytes), hard (INF)(bytes)
          limit: soft (INF)(packets), hard (INF)(packets)
          expire add: soft 0(sec), hard 0(sec)
          expire use: soft 0(sec), hard 0(sec)
        lifetime current:
          # Counters for bytes and packets matched by this policy, to be used if limits have
          # been set.
          0(bytes), 0(packets)
          # Timestamps for when the policy was added and when it was last matched by a packet, to
          # be used if expiration times have been set.
          add 2024-06-17 11:24:49 use 2024-06-17 11:25:01
        # - `src 0.0.0.0` See Policy Templates for how this field is used.
        # - `dst 10.92.0.164` See Policy Templates for how this field is used.
        tmpl src 0.0.0.0 dst 10.92.0.164
            # - `proto esp` See Policy Templates for how this field is used.
            # - `spi 0x00000000(0)` See Policy Templates for how this field is used.
            # - `reqid 1(0x00000001)` See Policy Templates for how this field is used.
            # - `mode tunnel` See Policy Templates for how this field is used.
            proto esp spi 0x00000000(0) reqid 1(0x00000001) mode tunnel
            # - `level use` is the nonsensical way to indicate this template is optional, the
            #   alternative being `level required`. If no XFRM state matching the template is
            #   found, the template will be skipped if optional. Otherwise, the packet will be
            #   dropped with `XfrmInTmplMismatch`.
            # - `share any` is not implemented and will always be `any`.
            level use share any
            # - `enc-mask ffffffff` Bit mask defining the list of allowed encryption algorithms.
            #   See Encryption algorithms in include/uapi/linux/pfkeyv2.h for the list of possible
            #   values.
            # - `auth-mask ffffffff` Bit mask defining the list of allowed authentication
            #   algorithms. See Authentication algorithms in include/uapi/linux/pfkeyv2.h for the
            #   list of possible values.
            # - `comp-mask ffffffff` Non-implemented bit mask (was probably defined for compression
            #   algorithms).
            enc-mask ffffffff auth-mask ffffffff comp-mask ffffffff


.. code-block:: bash 

    $ ip xfrm state
    # - `src 10.92.1.189` is the IP address to match against the packets' source IP addresses.
    # - `dst 10.92.0.164` is the IP address to match against the packets' destination IP addresses.
    src 10.92.1.189 dst 10.92.0.164
        # - `proto esp` states the IPsec protocol to use.
        # - `spi 0x00000000(0)` is the Security Parameter Index. A tag to distinguish between
        #   multiple IPsec streams that may be using different algorithms and/or keys. Particularly
        #   useful during key rotations.
        # - `reqid 1(0x00000001)` is an ID only used to ensure the XFRM policy template and the
        #   state match. It doesn't seem to be used for anything else in the kernel.
        # - `mode tunnel` states whether the packet is encapsulated (`tunnel`) or if the ESP header
        #   is simply added to the existing packet (`transport`).
        proto esp spi 0x00000003(3) reqid 1(0x00000001) mode tunnel
        # - `replay-window 0` size of the replay window used for the anti-replay checks (i.e.,
        #   toleration setting).
        # - `seq 0x000000000`
        # - `flag (0x000000000)` holds various flags including `XFRM_STATE_ESN` (0x80) for ESN
        #   mode.
        replay-window 0 seq 0x00000000 flag  (0x00000000)
        # - `mark 0x4db50d00/0xffff0f00` are the value and mask used to match against the packets'
        #   marks.
        # - `output-mark 0xd00/0xffffff00` are the value and mask to apply to the packets' marks
        #   after they have been encrypted or decrypted.
        mark 0x4db50d00/0xffff0f00 output-mark 0xd00/0xffffff00
        # - `aead rfc4106(gcm(aes))` are the type and name of algorithm in use.
        # - `0x856f15d0ccabe682286b4286bccf5d595b88b168 (160 bits)` is the key and its size. It's
        #   of course sensitive information that should be treated as such.
        # - `128` is the ICV length. Which lengths are supported depends on the algorithm in use.
        aead rfc4106(gcm(aes)) 0x856f15d0ccabe682286b4286bccf5d595b88b168 (160 bits) 128
        # - `seq 0x0` holds the current receive-side sequence number, for the anti-replay check.
        # - `oseq 0x0` is the last emitted sequence number. If this number overflows (on 32-bits),
        #   packets are dropped and the error counter `XfrmOutStateSeqError` is increased. In ESN
        #   mode, this sequence number is coded on 64-bits.
        # - `bitmap 0x00000000` tracks the sequence numbers that have already been seen in the replay
        #   window.
        anti-replay context: seq 0x0, oseq 0x0, bitmap 0x00000000
        # - `sel src 0.0.0.0/0 dst 0.0.0.0/0` is an additional filter applying to the decrypted
        #   packets, to ensure the inner packets are coming and going where you expect.
        # - `uid 0` this field appears to be unused (`user` in `struct xfrm_selector`).
        sel src 0.0.0.0/0 dst 0.0.0.0/0 uid 0
        lifetime config:
          # Various limits and expiration times for the state, based on the number of bytes
          # received, the number of packets received, the time since the state was added, or the
          # time since the state was last used for a packet. When a soft limit or expiration time
          # is reached, a notification is sent to userspace via netlink
          # (`struct xfrm_user_expire`). When a hard limit or expiration time is reached, the state
          # is deleted.
          limit: soft (INF)(bytes), hard (INF)(bytes)
          limit: soft (INF)(packets), hard (INF)(packets)
          expire add: soft 0(sec), hard 0(sec)
          expire use: soft 0(sec), hard 0(sec)
        lifetime current:
          # Counters for bytes and packets matched by this policy, to be used if limits have been
          # set.
          20124(bytes), 83(packets)
          # Timestamps for when the policy was added and when it was last matched by a packet, to
          # be used if expiration times have been set.
          add 2024-06-17 11:15:48 use 2024-06-17 11:16:02
        stats:
          # - `replay-window 0` is incremented whenever a packet is received with a sequence number
          #   outside the window.
          # - `replay 0` is incremented whenever a packet is received with a sequence number in the
          #   replay window that was already observed.
          # - `failed 0` (full name `integrity_failed` on kernel's side) is incremented when the
          #   checksums for authentication or encryption headers are incorrect.
          #   `XfrmInStateProtoError` is always incremented when this counter is incremented.
          replay-window 0 replay 0 failed 0


XFRM Errors
===========

All XFRM errors correspond to packet drops. Some of them may also be associated with per-state
counters increasing. ``CONFIG_XFRM_STATISTICS`` is required to see these error counters in
``/proc/net/xfrm_stat``.

- **XfrmInError:** If the kernel fails to allocate memory during encryption.
- **XfrmInBufferError:**
    - If a packet is going through too many XFRM states. The maximum is set to
      ``XFRM_MAX_DEPTH`` (6).
    - If too many XFRM policy templates apply to a packet. The maximum is also set to
      ``XFRM_MAX_DEPTH`` (6).
- **XfrmInHdrError:**
    - If the SPI portion of the packet is malformed.
    - If the outer IP header is malformed.
- **XfrmInNoStates:** If no XFRM IN state was found that matches the AH or ESP packet ingressing on
  the INPUT chain.
- **XfrmInStateProtoError:**
    - If the AH or ESP checksum is incorrect.
    - If the packet's IPsec protocol (ex., AH, ESP) doesn't match the protocol specified by the
      XFRM state.
    - Also includes all protocol specific errors (ex., from ``esp_input``) listed below:
    - If decryption/encryption fails (ex., because the key specified in the XFRM IN state doesn't
      match the key with which the packet was encrypted).
    - If the protocol headers (ex., ESP) or trailers are malformed.
    - If there is not enough memory to perform encryption/decryption.
- **XfrmInStateModeError:** If the packet is in IPsec tunnel mode, but the matched XFRM state is in
  transport mode.
- **XfrmInStateSeqError:** If the anti-replay check rejected the packet. If the check failed
  because the sequence number was outside the window, the ``replay-window`` counter of the
  associated XFRM state will be incremented. If it failed because the sequence number was seen
  already, the ``replay`` counter is incremented instead.
- **XfrmInStateExpired:** There can be a delay between when a state expires (hard limits) and when
  it's actually deleted. During that time, matching packets are dropped with ``XfrmInStateExpired``
  on ingress.
- **XfrmInStateMismatch:**
    - If the encapsulation protocol of the XFRM state (ex., ``espinudp`` in ``encap`` field of
      ``ip xfrm state``) doesn't match the encapsulation protocol of the packet.
    - If the decrypted packet doesn't match the selector (``sel`` field) of the used XFRM state. 
- **XfrmInStateInvalid:** If received packet matched an XFRM state that is being deleted or that
  expired.
- **XfrmInTmplMismatch:**
    - If a packet matches an XFRM policy with a non-optional template, but the template doesn't
      match any of the XFRM states used to decrypt the packet (yes, a packet can be decoded
      multiple times).
    - If an XFRM state with ``mode tunnel`` was used on the packet and it doesn't match any XFRM
      policy template.
- **XfrmInNoPols:** If the ingressing packet doesn't match any XFRM policy and the default action
  is set to ``block``. See ``ip xfrm policy {get,set}default`` to view and set the default XFRM
  policy actions.
- **XfrmInPolBlock:** If the packet matches an XFRM IN policy with ``action block``.
- **XfrmOutError:**
    - If the kernel fails to allocate memory during encryption.
    - In some cases, if the packet to encrypt is malformed.
- **XfrmOutBundleCheckError:** Unused.
- **XfrmOutNoStates:** If the packet matched an XFRM OUT policy, but no XFRM state was found that
  matches the policy's template.
- **XfrmOutStateProtoError:** If a protocol-specific (ex., ESP) encryption error happens.
- **XfrmOutStateModeError:** If the packet exceeds the MTU once encapsulated and it shouldn't be
  fragmented.
- **XfrmOutStateSeqError:** The output sequence number (``oseq``) of an XFRM state reached its
  maximum value, ``UINT32_MAX`` when not using ESN mode.
- **XfrmOutStateExpired:** There can be a delay between when a state expires (hard limits) and when
  it's actually deleted. During that time, matching packets are dropped with
  ``XfrmOutStateExpired`` on egress.
- **XfrmOutPolBlock:** If the packet matches an XFRM OUT policy with ``action block``.
- **XfrmOutPolDead:** Unused. ``XfrmOutStateInvalid`` is reported instead for XFRM states that in
  the process of being deleted.
- **XfrmOutPolError:**
    - If too many XFRM policy templates apply to a packet. The maximum is also set to
      ``XFRM_MAX_DEPTH`` (6).
    - If no XFRM state is found for a non-optional template of the matching XFRM policy.
- **XfrmFwdHdrError:** If the packet is malformed when going through the FWD policy check.
- **XfrmOutStateInvalid:** If egressing packet matched an XFRM state that is being deleted or that
  expired.
- **XfrmOutStateDirError:** If the direction of the XFRM state found during the lookup is defined
  and isn't ``XFRM_SA_DIR_OUT``. Only on kernels v6.10 and newer.
- **XfrmInStateDirError:** If the direction of the XFRM state found during the lookup is defined
  and isn't ``XFRM_SA_DIR_IN``. Only on kernels v6.10 and newer.



Performance Considerations
==========================

This section describes the data structures used to hold the XFRM policies and states. This is
useful to understand when dealing with a large number of states and policies as the information
they hold can help improve indexing and speed up the lookups. When dealing with thousands of
policies and states, the lookup cost can become non-negligible even when compared to the
encryption/decryption cost.

Data Structure for XFRM Policies
--------------------------------

XFRM policies are stored in a rather complex data structure made of multiple red-black trees and
hash tables. At the root, everything is contained in a `resizable hashtable`_ indexed by network
namespace, IP family, direction, and interface (in case XFRM interfaces are used). Each entry in
this resizable hash table contains several black-red trees, which themselves hold the XFRM
policies. Those entries are represented by the structure ``xfrm_pol_inexact_bin``.

.. _resizable hashtable: https://lwn.net/Articles/751974

.. image:: /images/xfrm_policies_data_structure.png
    :align: center

Once ``xfrm_pol_inexact_bin`` has been retrieved (based on current IP family, namespace, and
direction), each of its red-black trees is looked up using the source and destination IP addresses.
The ``root_s`` tree contains policies sorted by source IP addresses; the ``root_d`` tree contains
policies sorted by destination IP addresses. In addition, leaf nodes of the ``root_d`` tree also
contain another tree with policies sorted by source IP addresses. That allows the lookups into
``root_s`` and ``root_d`` to return three lists of candidate ``(src_ip; dst_ip)`` policies from the
leaf nodes:

  - A list of ``(src_ip; any)`` candidates from ``root_s``.
  - A list of ``(any; dst_ip)`` candidates from ``root_d``.
  - A list of ``(src_ip; dst_ip)`` candidates from the trees pointed by the leaf nodes of
    ``root_d``.

These three lists of candidate XFRM policies are completed by a list of ``(any; any)`` candidates
directly stored in the ``xfrm_pol_inexact_bin`` entry.

Note that an XFRM policy will only be present in one of the four candidate lists, according to its
source and destination CIDRs.

These four lists of candidate XFRM policies are then evaluated. The kernel iterates through each
list, looking for the highest-priority (lowest ``priority`` number) candidate that matches the
packet. If two policies match and have the same priority, the newest one is preferred. It's also
only during this linear evaluation of candidates that the packet mark is compared with the policy
marks.

Data Structure for XFRM States
------------------------------

XFRM states are organized in four hash tables, with different XFRM fields used for indexing and
different purposes:

  - ``net->xfrm.state_bydst`` is indexed by source and destination IP addresses as well as reqid.
  - ``net->xfrm.state_bysrc`` is indexed only by source and destination IP addresses.
  - ``net->xfrm.state_byspi`` is indexed by destination IP address, SPI, and protocol.
  - ``net->xfrm.state_byseq`` is indexed by sequence number only.

``net->xfrm.state_byspi`` is used when looking up an XFRM state for ingressing packets. This makes
sense to speed up the search as each XFRM state is encouraged to have its own SPI (cf., `RFC4301`_,
section 4.1) and the encrypted packets carry the SPI.

.. _RFC4301: https://datatracker.ietf.org/doc/html/rfc4301

When searching for the XFRM state that corresponds to an XFRM policy template (before encryption),
``net->xfrm.state_bydst`` is used. That makes sense because the indexing information is what the
XFRM policy template provides. That hash table is typically also the one being used when iterating
through all XFRM states (ex., when flushing them), but any hash table would do the job for that.

``net->xfrm.state_bysrc`` and ``net->xfrm.state_byseq`` are used for various other management
tasks, such as looking up an XFRM state to update, answering a netlink query from the user, or
checking for existing states before adding a new one.
