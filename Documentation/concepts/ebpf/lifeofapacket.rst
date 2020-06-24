.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

################
Life of a Packet
################

Endpoint to Endpoint
====================

First we show the local endpoint to endpoint flow with optional L7 Policy on
egress and ingress. Followed by the same endpoint to endpoint flow with
socket layer enforcement enabled. With socket layer enforcement enabled for TCP
traffic the
handshake initiating the connection will traverse the endpoint policy object until TCP state
is ESTABLISHED. Then after the connection is ESTABLISHED only the L7 Policy
object is still required.

.. image:: _static/cilium_bpf_endpoint.svg

Egress from Endpoint
====================

Next we show local endpoint to egress with optional overlay network. In the
optional overlay network traffic is forwarded out the Linux network interface
corresponding to the overlay. In the default case the overlay interface is
named cilium_vxlan. Similar to above, when socket layer enforcement is enabled
and a L7 proxy is in use we can avoid running the endpoint policy block between
the endpoint and the L7 Policy for TCP traffic. An optional L3 encryption block
will encrypt the packet if enabled.

.. image:: _static/cilium_bpf_egress.svg

Ingress to Endpoint
===================

Finally we show ingress to local endpoint also with optional overlay network.
Similar to above socket layer enforcement can be used to avoid a set of
policy traversals between the proxy and the endpoint socket. If the packet
is encrypted upon receive it is first decrypted and then handled through
the normal flow.

.. image:: _static/cilium_bpf_ingress.svg

veth-based versus ipvlan-based datapath
=======================================

.. include:: ../../tech-preview.rst

By default Cilium CNI operates in veth-based datapath mode which allows for
more flexibility in that all BPF programs are managed by Cilium out of the host
network namespace such that containers can be granted privileges for their
namespaces like CAP_NET_ADMIN without affecting security since BPF enforcement
points in the host are unreachable for the container. Given BPF programs are
attached from the host's network namespace, BPF also has the ability to take
over and efficiently manage most of the forwarding logic between local containers
and host since there always is a networking device reachable. However, this
also comes at a latency cost as in veth-based mode the network stack internally
needs to be re-traversed when handing the packet from one veth device to its
peer device in the other network namespace. This egress-to-ingress switch needs
to be done twice when communicating between local Cilium endpoints, and once
for packets that are arriving or sent out of the host.

For a more latency optimized datapath, Cilium CNI also supports ipvlan L3/L3S mode
with a number of restrictions. In order to support older kernel's without ipvlan's
hairpin mode, Cilium attaches BPF programs at the ipvlan slave device inside
the container's network namespace on the tc egress layer, which means that
this datapath mode can only be used for containers which are not running with
CAP_NET_ADMIN and CAP_NET_RAW privileges! ipvlan uses an internal forwarding
logic for direct slave-to-slave or slave-to-master redirection and therefore
forwarding to devices is not performed from the BPF program itself. The network
namespace switching is more efficient in ipvlan mode since the stack does not
need to be re-traversed as in veth-based datapath case for external packets.
The host-to-container network namespace switch happens directly at L3 layer
without having to queue and reschedule the packet for later ingress processing.
In case of communication among local endpoints, the egress-to-ingress switch
is performed once instead of having to perform it twice.

For Cilium in ipvlan mode there are a number of additional restrictions in
the current implementation which are to be addressed in upcoming work: NAT64
cannot be enabled at this point as well as L7 policy enforcement via proxy.
Service load-balancing to local endpoints is currently not enabled as well
as container to host-local communication. If one of these features are needed,
then the default veth-based datapath mode is recommended instead.

The ipvlan mode in Cilium's CNI can be enabled by running the Cilium daemon
with e.g. ``--datapath-mode=ipvlan --ipvlan-master-device=bond0`` where the
latter typically specifies the physical networking device which then also acts
as the ipvlan master device. Note that in case ipvlan datapath mode is deployed
in L3S mode with Kubernetes, make sure to have a stable kernel running with the
following ipvlan fix included: `d5256083f62e <https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git/commit/?id=d5256083f62e2720f75bb3c5a928a0afe47d6bc3>`_.

This completes the datapath overview. More BPF specifics can be found in the
:ref:`bpf_guide`. Additional details on how to extend the L7 Policy
exist in the :ref:`envoy` section.
