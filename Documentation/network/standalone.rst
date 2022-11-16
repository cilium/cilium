.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _standalone-gateway:

*************************
Cilium Standalone Gateway
*************************

Cilium has a standalone mode where it can be operated outside of Kubernetes
as a standalone gateway. The gateway is designed to reside at the edge of the
cluster, potentially replacing dedicated hardware components, and handling
high-traffic load from a north-south direction going into the cluster(s).

The Cilium Standalone Gateway includes functionality such as a high performance
eBPF-based layer 4 load-balancer and a NAT46/64 gateway. There is a wide range
of use cases, for example, the Cilium Standalone Gateway could be used to
frontend DNS resolvers, it can be used as a load-balancer for legacy VM-based
workloads, as a gateway in front of IPv6 single stack Kubernetes clusters to
allow for interconnection with IPv4, as a load-balancer for kubeapi-server, to
replace legacy IPVS-based load-balancers, and many more.

Cilium provides a programmable API for its agent which is exposed through a
unix domain socket on the local node such that it can be integrated into
third party management software on the node.

This guide explains how to provision Cilium as a standalone gateway along with
various use-cases and configuration examples.

Quick-Start
===========

Given the Cilium Standalone Gateway can be operated outside of a Kubernetes
cluster, this guide provides a minimal Docker-based step-by-step instructions.

As a one-time prerequisite, ensure that the BPF file system is mounted under
``/sys/fs/bpf``. If this is not the case already, a mount unit file can be set
up under ``/etc/systemd/system/sys-fs-bpf.mount`` ...

.. parsed-literal::

   [Unit]
   Description=BPF mounts
   DefaultDependencies=no
   Before=local-fs.target umount.target
   After=swap.target

   [Mount]
   What=bpffs
   Where=/sys/fs/bpf
   Type=bpf

   [Install]
   WantedBy=multi-user.target

... and brought up through ``systemctl start sys-fs-bpf.mount``.

.. note::

  The above step is only required for distributions with older systemd versions.
  For most modern distributions this step is not required as systemd will
  automatically mount the BPF file system at its default location. See also
  `GH-10955 <https://github.com/cilium/cilium/issues/10955>`_ for details.

In this Quick-Start example we enable the standalone layer 4 load-balancer
functionality for both IPv4 and IPv6, as a load-balancing algorithm we
utilize Maglev consistent hashing, and the networking device for the
load-balancer in this case is called ``bond0``. Multi-device setups are
supported as well, and can be specified via ``--devices=bond0,eth0`` or
through a device name regex. Furthermore, we enable XDP acceleration for
maximum efficiency.

The vast majority of modern network drivers for 10/40/100G and beyond support
XDP today. If you are unsure whether your network driver supports native XDP,
then simply set ``--bpf-lb-acceleration=disabled`` instead and Cilium loads
its programs into the tc BPF layer instead of XDP.

.. parsed-literal::

   docker run --name cilium-gateway -td \\
     -v /sys/fs/bpf:/sys/fs/bpf \\
     -v /lib/modules:/lib/modules \\
     --privileged=true \\
     --network=host \\
     quay.io/cilium/cilium:|IMAGE_TAG| \\
     cilium-agent \\
     --enable-ipv4=true \\
     --enable-ipv6=true \\
     --datapath-mode=lb-only \\
     --bpf-lb-algorithm=maglev \\
     --bpf-lb-acceleration=native \\
     --devices=bond0

By default, the layer 4 load-balancer operates in SNAT mode, meaning replies from
backends will reach the load-balancer again which then performs reverse NAT and
sends the reply back to the client. Advanced options such as direct server return
(DSR) are supported as well and described in later sections of this guide.

Validate the Setup
==================

After deploying Cilium Standalone Gateway with above Quick-Start guide, we can first
validate that the Cilium agent is running in the desired mode:

.. parsed-literal::

   docker exec cilium-gateway cilium status --verbose
   [...]
   Kubernetes:             Disabled
   KubeProxyReplacement Details:
     Status:                 Partial
     Socket LB:              Enabled
     Socket LB Protocols:    TCP, UDP
     Devices:                bond0 86.109.5.207 2604:1380:4091:cf00::1 (Direct Routing)
     Mode:                   SNAT
     Backend Selection:      Maglev (Table Size: 16381)
     Session Affinity:       Disabled
     Graceful Termination:   Enabled
     NAT46/64 Support:       Enabled
     XDP Acceleration:       Native
   [...]

As an optional next step, we will create a simple service entry for testing purpose.
Then we validate that Cilium installed the service correctly.

Cilium exposes its programmable API under ``unix:///var/run/cilium/cilium.sock``.
Cilium's `service command-line interface <https://github.com/cilium/cilium/blob/master/cilium/cmd/service_update.go>`_
communicates to the agent through this API. For simplicity, we use the
command-line tool in this example, but third party orchestration tooling can use
the API by connecting to the unix domain socket directly. For the latter, it is
recommended to expose Cilium's runtime directory to the host via Docker volumes
(``-v /var/run/cilium/:/var/run/cilium/``), so that other control plane software
can talk to ``/var/run/cilium/cilium.sock``.

After initial deployment the load-balancer service table is empty:

.. parsed-literal::

  docker exec cilium-gateway cilium service list
  ID   Frontend   Service Type   Backend

As a next step, we create a new dummy service with two backends:

.. parsed-literal::

  docker exec cilium-gateway cilium service update --id 1 --frontend "86.109.5.207:8080" --backends "1.1.1.1:80,1.0.0.1:80" --k8s-external
  Creating new service with id '1'
  Added service with 2 backends

Running the service dump confirms that both have been created:

.. parsed-literal::

  docker exec cilium-gateway cilium service list
  ID   Frontend            Service Type   Backend
  1    86.109.5.207:8080   ExternalIPs    1 => 1.1.1.1:80 (active)
                                          2 => 1.0.0.1:80 (active)

In this case the frontend address is the publicly accessible IP address of
the node itself. If a service VIP is being used, then these need to be
announced to the network through BGP daemons such as FRR.

The service is now reachable from an external client node:

.. parsed-literal::

  curl --verbose 86.109.5.207:8080
  *   Trying 86.109.5.207...
  * TCP_NODELAY set
  * Connected to 86.109.5.207 (86.109.5.207) port 8080 (#0)
  > GET / HTTP/1.1
  > Host: 86.109.5.207:8080
  > User-Agent: curl/7.64.0
  > Accept: */*
  >
  < HTTP/1.1 403 Forbidden
  [...]

An IPv6 equivalent can be configured similarly:

.. parsed-literal::

  docker exec cilium-gateway cilium service update --id 2 --frontend "[2604:1380:4091:cf00::1]:8080" --backends "[2606:4700:4700::1111]:80,[2606:4700:4700::1001]:80" --k8s-external
  Creating new service with id '2'
  Added service with 2 backends

Running the service dump confirms that the new entry has been created:

.. parsed-literal::

  docker exec cilium-gateway cilium service list
  ID   Frontend                        Service Type   Backend
  1    86.109.5.207:8080               ExternalIPs    1 => 1.1.1.1:80 (active)
                                                      2 => 1.0.0.1:80 (active)
  2    [2604:1380:4091:cf00::1]:8080   ExternalIPs    1 => [2606:4700:4700::1111]:80 (active)
                                                      2 => [2606:4700:4700::1001]:80 (active)

The service is now reachable from an external client node:

.. parsed-literal::

  curl --verbose "[2604:1380:4091:cf00::1]:8080"
  *   Trying 2604:1380:4091:cf00::1:8080...
  * TCP_NODELAY set
  * Connected to 2604:1380:4091:cf00::1 (2604:1380:4091:cf00::1) port 8080 (#0)
  > GET / HTTP/1.1
  > Host: [2604:1380:4091:cf00::1]:8080
  > User-Agent: curl/7.68.0
  > Accept: */*
  >
  * Mark bundle as not supporting multiuse
  < HTTP/1.1 403 Forbidden
  [...]

For sake of completeness, an existing service can be altered through ``cilium service update``
as well:

.. parsed-literal::

  docker exec cilium-gateway cilium service update --id 2 --frontend "[2604:1380:4091:cf00::1]:8080" --backends "[2606:4700:4700::1111]:80" --k8s-external
  Updating existing service with id '2'
  Updated service with 1 backends

  docker exec cilium-gateway cilium service list
  ID   Frontend                        Service Type   Backend
  1    86.109.5.207:8080               ExternalIPs    1 => 1.1.1.1:80 (active)
                                                      2 => 1.1.1.2:80 (active)
  2    [2604:1380:4091:cf00::1]:8080   ExternalIPs    1 => [2606:4700:4700::1111]:80 (active)

And last but not least deleted through its identifier:

.. parsed-literal::

  docker exec cilium-gateway cilium service delete 2
  Service 2 deleted successfully

  docker exec cilium-gateway cilium service list
  ID   Frontend            Service Type   Backend
  1    86.109.5.207:8080   ExternalIPs    1 => 1.1.1.1:80 (active)
                                          2 => 1.1.1.2:80 (active)

Each of these operations communicate to the agent through its programmable API
which for third party integrations can be used directly.

This concludes the initial bootstrapping. More advanced configuration options
for the Cilium Standalone Gateway can be found in subsequent sections below.

Advanced Configuration
======================

The Cilium Standalone Gateway offers various load-balancer configuration options
as well as NAT46/64 gateway features. Each of the features are also supported under
XDP in order to sustain high packet rates such that the Cilium Standalone Gateway
can be used to handle north-south type traffic. The NAT46/64 gateway has been
implemented with the goal to ease deployment of IPv6 single stack clusters in
Kubernetes.

Layer 4 Load-Balancer
---------------------

This section covers load-balancer-specific configuration, use-cases, and
discussions.

Direct Server Return (DSR)
~~~~~~~~~~~~~~~~~~~~~~~~~~

By default, Cilium's load-balancer implementation operates in SNAT mode. That is,
when node-external traffic arrives which is destined to a service VIP, then the
node is redirecting the request to the remote backend on its behalf by performing
SNAT. This does not require any additional MTU changes. The cost is that replies
from the backend need to make the extra hop back to the load-balancer node to
perform the reverse SNAT translation before returning the packet directly
to the external client. Additionally, the original client IP is not preserved at
the time the packet reaches the backend. The SNAT mode has been used in the
Quick-Start example above.

The extra hop on the reply can be avoided through Direct Server Return (DSR) where
the backend replies directly to the external client. The Cilium Standalone Gateway
supports IPIP and IP6IP6 encapsulation for DSR such that it can be used as a `drop-in
replacement <https://cilium.io/blog/2022/04/12/cilium-standalone-L4LB-XDP/>`_ for
existing setups relying on netfilter/IPVS or dedicated hardware load-balancers with
IPIP encapsulation support. While the SNAT mode is the most straight forward mode
to configure and run and there are no underlying constraints on the network, the
DSR mode might have limitations with regards to the underlying fabric when run off-prem
in cloud provider networks.

The original Quick-Start example has been slightly modified to run in DSR mode:

.. parsed-literal::

   docker run --name cilium-gateway -td \\
     -v /sys/fs/bpf:/sys/fs/bpf \\
     -v /lib/modules:/lib/modules \\
     --privileged=true \\
     --network=host \\
     quay.io/cilium/cilium:|IMAGE_TAG| \\
     cilium-agent \\
     --enable-ipv4=true \\
     --enable-ipv6=true \\
     --datapath-mode=lb-only \\
     --bpf-lb-algorithm=maglev \\
     --bpf-lb-acceleration=native \\
     --bpf-lb-mode=dsr \\
     --bpf-lb-dsr-dispatch=ipip \\
     --devices=bond0

In this case the original packet will be preserved in the inner header, and therefore this
mechanism preserves the original client IP address all the way to the backend nodes. The
outer IP header will contain the load-balancer address as a source address and the selected
backend address as a destination address.

There are two modes for the encapsulation which can be toggled through ``--bpf-lb-dsr-l4-xlate``.
The default mode is also the more common scenario, that is, ``--bpf-lb-dsr-l4-xlate=frontend``.
Both ``frontend`` and ``backend`` options determine how the inner packet is L4 DNATed, for example:

.. parsed-literal::

  docker exec cilium-gateway cilium service list
  ID   Frontend             Service Type   Backend
  1    192.168.160.3:8080   ExternalIPs    1 => 192.168.0.3:4444

With the default ``--bpf-lb-dsr-l4-xlate=frontend``, the inbound and outbound packet look
as follows:

.. parsed-literal::

   -> IP 192.168.160.4.38036 > 192.168.160.3.8080: Flags [S], [...]
   <- IP 192.168.160.3 > 192.168.0.3: IP 192.168.160.4.38036 > 192.168.160.3.8080: Flags [S], [...] (ipip-proto-4)

In short, the original request is preserved in the inner packet. The outer source is set to
the load-balancer address, and the outer destination to the backend address. The backend port
is not used anywhere in this case.

With the ``--bpf-lb-dsr-l4-xlate=backend``, the inbound and outbound packet look as
follows in terms of L4 DNAT:

.. parsed-literal::

   -> IP 192.168.160.4.38040 > 192.168.160.3.8080: Flags [S], [...]
   <- IP 192.168.160.3 > 192.168.0.3: IP 192.168.160.4.38040 > 192.168.160.3.4444: Flags [S], [...] (ipip-proto-4)

The original request is preserved in the inner packet and the destination port has been replaced
with the backend port. The outer source is set to the load-balancer address, and the outer
destination to the backend address. The service port is not used anywhere in this case.

RSS Steering
~~~~~~~~~~~~

Given the outer IP header becomes fairly static with DSR, RSS-steering on backend nodes
could perform sub-optimal if network adapters cannot parse deeper into IPIP/IP6IP6 headers
to gain more entropy. In such cases the load-balancer can be configured to hash L3/L4
information from the inner packet into an outer source IP address which can be configured
with a custom well-known IP prefix.

.. parsed-literal::

   docker run --name cilium-gateway -td \\
     -v /sys/fs/bpf:/sys/fs/bpf \\
     -v /lib/modules:/lib/modules \\
     --privileged=true \\
     --network=host \\
     quay.io/cilium/cilium:|IMAGE_TAG| \\
     cilium-agent \\
     --enable-ipv4=true \\
     --enable-ipv6=true \\
     --datapath-mode=lb-only \\
     --bpf-lb-algorithm=maglev \\
     --bpf-lb-acceleration=native \\
     --bpf-lb-mode=dsr \\
     --bpf-lb-dsr-dispatch=ipip \\
     --bpf-lb-rss-ipv4-src-cidr=192.168.0.0/16 \\
     --bpf-lb-rss-ipv6-src-cidr=fd00::/96 \\
     --devices=bond0

In this example, the outer source IPv4 contains a ``192.168.0.0/16`` prefix and the last
two quads are populated based on the hash of the inner packet. Similarly for IPv6, the
source address holds a prefix of ``fd00::/96`` where the remaining 32 bits are populated
based on the hash of the inner packet. The static prefix vs dynamic number of bits can be
selected flexibly in order to accommodate for ACLs in the underlying network.

Path MTU Discovery
~~~~~~~~~~~~~~~~~~

Given the IPIP/IP6IP6 encapsulation reduces the available MTU from the load-balancer to
the node with the backend, Cilium supports client-side PMTU discovery. Meaning, the
load-balancer responds with an IPv4 ICMP ``destination unreachable`` message with sub-type
``fragmentation needed``, so that clients are able to cache this path information and
to adjust their packet sizes for future transmissions. The IPv6 counterpart emits an
ICMPv6 ``Packet Too Big`` message back to the sender. Both is auto-enabled under XDP
mode.

Maglev Consistent Hashing
~~~~~~~~~~~~~~~~~~~~~~~~~

Cilium's eBPF load-balancer supports consistent hashing by implementing a variant
of `the Maglev paper <https://storage.googleapis.com/pub-tools-public-publication-data/pdf/44824.pdf>`_
hashing for backend selection. This option is selected through ``--bpf-lb-algorithm=maglev``
and is in contrast to the default ``--bpf-lb-algorithm=random`` setting, which is picking
a random backend for a new connection.

Maglev improves resiliency in case of failures and provides better load-balancing
properties as adding more load-balancers to a load-balancer group will make consistent
backend selection throughout the group for a given 5-tuple without having to
synchronize state with each group member. Therefore it is in particular suited
for handling inbound north-south traffic with ECMP-based load-balancing in front.

Similarly, upon backend removal the Maglev backend lookup tables are reprogrammed with
minimal disruption for unrelated backends, for example, depending on the configuration,
at most 1% difference in the reassignments for the given service.

The ``--bpf-lb-maglev-hash-seed`` option is recommended to be set in order for Cilium
to not rely on the fixed built-in seed. The seed is a base64-encoded 12 byte-random
number, and can be generated once through ``head -c12 /dev/urandom | base64 -w0``,
for example. If you have a group of load-balancers which all share the same set of
services and backends, then every instance in that group must use the same hash
seed for Maglev to work. Small example generated once which is later used for the
subsequent Cilium configuration:

.. parsed-literal::

   SEED=$(head -c12 /dev/urandom | base64 -w0)
   echo $SEED
   DFTTgNYuodmggDl6

The ``--bpf-lb-maglev-table-size`` option specifies the size of the Maglev lookup
table for each single service. See details in the `Maglev <https://storage.googleapis.com/pub-tools-public-publication-data/pdf/44824.pdf>`__
paper for the table size (``M``). Cilium uses a default size of ``16381`` for ``M``.

The below deployment example based upon the original Quick-Start one is setting the
Maglev table size to ``65521`` to allow for ``~650`` maximum backends for a given
service (with the property of at most 1% difference on backend reassignments). It
also initializes the table with the prior generated hash seed:

.. parsed-literal::

   docker run --name cilium-gateway -td \\
     -v /sys/fs/bpf:/sys/fs/bpf \\
     -v /lib/modules:/lib/modules \\
     --privileged=true \\
     --network=host \\
     quay.io/cilium/cilium:|IMAGE_TAG| \\
     cilium-agent \\
     --enable-ipv4=true \\
     --enable-ipv6=true \\
     --datapath-mode=lb-only \\
     --bpf-lb-algorithm=maglev \\
     --bpf-lb-maglev-table-size=65521 \\
     --bpf-lb-maglev-hash-seed=DFTTgNYuodmggDl6 \\
     --bpf-lb-acceleration=native \\
     --devices=bond0

The Maglev selection consumes significantly more memory due to the needed lookup tables.
If the use case for Cilium Standalone Gateway is to just act as a proxy for translating
from one service VIP to another service VIP (e.g. IPv4 to IPv6 one) such that per service
only one backend is required, then sticking with the Random mode (default) is sufficient.

Introspecting the raw Maglev lookup tables from BPF side can be achieved through
``docker exec cilium-gateway cilium bpf lb maglev list``.

Backend State Management
~~~~~~~~~~~~~~~~~~~~~~~~

For maintenance, quarantining or other purposes it can be necessary to drain traffic
from a given backend. In such case, the load-balancer will not consider those backends
for traffic forwarding, meaning, they are excluded for new connections. Ongoing connections
are still kept in-tact until a backend is removed from the given service entirely. Once
the backend is removed from the service, then (still) ongoing traffic will be dropped.

The backend state is presented in the service dump, and can be one of ``active`` (default),
``terminating``, ``quarantined``, ``maintenance``:

.. parsed-literal::

  docker exec cilium-gateway cilium service list
  ID   Frontend            Service Type   Backend
  1    86.109.5.207:8080   ExternalIPs    1 => 1.1.1.1:80 (active)
                                          2 => 1.1.1.2:80 (active)

Semantically the three states ``terminating``, ``quarantined`` and ``maintenance`` are
the same and all of them exclude the provided backend for new connections. However, third
party software built on top of this framework may use them for different purposes:

- ``quarantined``: An out-of-band health checking mechanism determined that the backend
  was flaky, and therefore briefly puts the backend out of service.
- ``maintenance``: The backend is taken out of service for maintenance purpose such as
  for updating the backend software.
- ``terminating``: The backend is taken out of service indefinitely.

States can transition from:

- ``active`` into ``terminating``, ``quarantined`` or ``maintenance``
- ``quarantined`` into ``active`` or ``terminating``
- ``maintenance`` into ``active``
- ``terminating`` is a final state

The above backend state management is supported for both Random and Maglev backend selection.

The state for a given backend can be updated as follows:

.. parsed-literal::

  docker exec cilium-gateway cilium service update --backends 1.1.1.2:80 --states maintenance
  Updating backend states
  Updated service with 1 backends

  docker exec cilium-gateway cilium service list
  ID   Frontend            Service Type   Backend
  1    86.109.5.207:8080   ExternalIPs    1 => 1.1.1.1:80 (active)
                                          2 => 1.1.1.2:80 (maintenance)

The backend state is global, meaning, if a backend IP:port is part of multiple services,
then all of them are updated accordingly:

.. parsed-literal::

  docker exec cilium-gateway cilium service list
  ID   Frontend                        Service Type   Backend
  1    86.109.5.207:8080               ExternalIPs    1 => 1.1.1.1:80 (active)
                                                      2 => 1.1.1.2:80 (active)
  2    [2604:1380:4091:cf00::1]:8080   ExternalIPs    1 => 1.1.1.1:80 (active)
                                                      2 => 1.1.1.2:80 (active)

  docker exec cilium-gateway cilium service update --backends 1.1.1.2:80 --states maintenance
  Updating backend states
  Updated service with 1 backends

  docker exec cilium-gateway cilium service list
  ID   Frontend                        Service Type   Backend
  1    86.109.5.207:8080               ExternalIPs    1 => 1.1.1.1:80 (active)
                                                      2 => 1.1.1.2:80 (maintenance)
  2    [2604:1380:4091:cf00::1]:8080   ExternalIPs    1 => 1.1.1.1:80 (active)
                                                      2 => 1.1.1.2:80 (maintenance)

Moreover, the API also allows for batch-updates, that is, multiple backends can be updated
at once when needed:

.. parsed-literal::

  docker exec cilium-gateway cilium service update --backends 1.1.1.1:80,1.1.1.2:80 --states active
  Updating backend states
  Updated service with 2 backends

  docker exec cilium-gateway cilium service list
  ID   Frontend                        Service Type   Backend
  1    86.109.5.207:8080               ExternalIPs    1 => 1.1.1.1:80 (active)
                                                      2 => 1.1.1.2:80 (active)
  2    [2604:1380:4091:cf00::1]:8080   ExternalIPs    1 => 1.1.1.1:80 (active)
                                                      2 => 1.1.1.2:80 (active)

Backend Weights
~~~~~~~~~~~~~~~

Weighted backend selection is supported and in particular useful for scenarios
such as canary testing of backend applications.

Without explicitly specifying a backend weight for a service, all backends have
a weight of ``1`` by default. The weight value can range from ``0`` up to ``255``.
Further, the backend weight is not a global property such as the backend state,
but rather a per service property. Meaning, a given backend can have different
weights for different services.

The following example doubles the weight of the first backend. Meaning, the first
backend receives a weight value of ``2``, the second backend a weight of ``1``.
The sum of all weights is ``3``, therefore, assuming random, equally distributed
client source tuples, ``2/3`` (66%) of traffic will be routed to the first and
``1/3`` (33%) of traffic will be routed to the second backend:

.. parsed-literal::

  docker exec cilium-gateway cilium service update --id 1 --frontend "86.109.5.207:8080" --backends "1.1.1.1:80,1.1.1.2:80" --backend-weights 2,1 --k8s-external
  Updating existing service with id '1'
  Updated service with 2 backends

For a canary deployment of the second backend, a combination of ``--backend-weights 95,5``
could be used to load-balance 5% of traffic assuming random, equally distributed
client source tuples.

The backend weights can be adjusted on the fly without disrupting ongoing connections.

From the service dump command-line interface side, the weights details are currently
exposed through the ``yaml`` or ``json`` dump:

.. parsed-literal::

  docker exec cilium-gateway cilium service list -o=yaml
  [...]
  status:
    realized:
      backendaddresses:
      - ip: 1.1.1.1
        nodename: ""
        port: 80
        preferred: false
        state: active
        weight: 2
      - ip: 1.1.1.2
        nodename: ""
        port: 80
        preferred: false
        state: active
        weight: 1
  [...]

Backend Probe
~~~~~~~~~~~~~

Neighbor Management
~~~~~~~~~~~~~~~~~~~

Cilium's eBPF load-balancer does not manage direct neighbors residing in the same
L2 domain. Given such traffic would not be directed through the default gateway,
the load-balancer needs to be made aware in case backends are direct neighbors.
Out of XDP it is not possible to resolve L2 addresses given packets cannot be
queued. Therefore the third-party control plane software built on top of this
framework may need to install neighbor entries.

In order to ease periodic neighbor resolution, we extended the kernel with so-called
`managed neighbor entries <https://lore.kernel.org/netdev/20211011121238.25542-1-daniel@iogearbox.net/>`_.

PCAP Recorder
~~~~~~~~~~~~~

As XDP operates below the regular networking stack, existing tooling such as tcpdump
is not available. Even if it was, its internal filter generation would also not be
efficient enough for a larger set of IPs or prefixes since they would need to be
processed linearly.

For the Cilium Standalone Gateway's datapath we therefore included two observation
points in order to filter and record the load-balancer inbound traffic with its
corresponding outbound traffic. This allows for further correlation to reconstruct
the path taken from the fabric to the L4 load-balancer to the subsequent backends.

For the PCAP recorder, a wildcarded n-tuple filtering for IPv4 and IPv6 has been
implemented and exposed as a Hubble API. This allows for building wildcard-filter
rules with:

- Arbitrary source address prefix
- Arbitrary destination address prefix
- Individual source port number or all ports
- Individual destination port number or all ports
- Individual protocols (TCP/UDP) or all protocols

From the installed rules, masks are derived and filter rules are inserted into
a hash table. While there may be a small set of individual masks, there can be
millions of filter entries in the hash table which fit the constraint of
the masks. The set of masks is small and limited to a maximum of 32, as the
more masks are necessary, the slower the fast-path becomes given classifying and
subsequently capturing traffic might incur processing overhead.

The datapath iterates through the masks to create a temporary tuple and performs
a subsequent hash table lookup to find a matching entry. The filters match for the
inbound packet. If there has been a match, then the outbound packet is marked to
be pushed to the recorder as well.

The PCAP recorder works with both DSR as well as SNAT operation modes.

In order to enable the PCAP recorder in the agent, it must be built into
the datapath (``--enable-recorder=true``).

Hubble can be used to access the recorder and expose a recorder API under
``unix:///var/run/cilium/hubble.sock`` for local clients to connect to:

.. parsed-literal::

   docker run --name cilium-gateway -td \\
     -v /sys/fs/bpf:/sys/fs/bpf \\
     -v /lib/modules:/lib/modules \\
     --privileged=true \\
     --network=host \\
     quay.io/cilium/cilium:|IMAGE_TAG| \\
     cilium-agent \\
     --enable-ipv4=true \\
     --enable-ipv6=true \\
     --datapath-mode=lb-only \\
     --bpf-lb-acceleration=native \\
     --enable-recorder=true \\
     --enable-hubble=true \\
     --enable-hubble-recorder-api=true \\
     --devices=bond0

Hubble's `recorder command-line interface <https://github.com/cilium/hubble/blob/master/cmd/record/record.go>`_
communicates to the agent through this exposed API. For simplicity, we use the
command-line tool in this example, but third party orchestration tooling can
use the API by connecting to the unix domain socket directly in order to build
a distributed PCAP recorder infrastructure among a group of load-balancers.

For the latter, it is recommended to expose Cilium's runtime directory to the host
via Docker volumes (``-v /var/run/cilium/:/var/run/cilium/``), so that other control
plane software can talk to ``unix:///var/run/cilium/hubble.sock``.

By default, Hubble stores recorded PCAPs for post-analysis under ``/var/run/cilium/pcaps/``.

Example for recording all TCP-based traffic for the node for a time of one second:

.. parsed-literal::

  docker exec cilium-gateway hubble record "0.0.0.0/0 0 0.0.0.0/0 0 TCP" --time-limit 1s
  Started recording. Press CTRL+C to stop.
  2022-12-12T12:39:14Z Status: 0 packets (0 bytes) written
  2022-12-12T12:39:15Z Status: 1 packets (66 bytes) written
  2022-12-12T12:39:15Z Status: 2 packets (132 bytes) written
  2022-12-12T12:39:15Z Status: 3 packets (198 bytes) written
  2022-12-12T12:39:15Z Status: 4 packets (264 bytes) written
  2022-12-12T12:39:15Z Status: 5 packets (330 bytes) written
  2022-12-12T12:39:15Z Status: 6 packets (396 bytes) written
  2022-12-12T12:39:15Z Status: 7 packets (462 bytes) written
  2022-12-12T12:39:15Z Status: 8 packets (528 bytes) written
  2022-12-12T12:39:15Z Status: 9 packets (594 bytes) written
  2022-12-12T12:39:15Z Status: 10 packets (660 bytes) written
  [...]
  2022-12-12T12:39:15Z Result: 77 packets (5082 bytes) written
  2022-12-12T12:39:15Z Output: /var/run/cilium/pcaps/hubble_1670848754_1823804162_c3-small-x86-01.pcap

Another example for recording TCP or UDP-based traffic with a source CIDR
of ``10.4.0.0/16`` and any port, a destrination CIDR of ``1.1.1.1/32`` and
port ``80``:

.. parsed-literal::

  docker exec cilium-gateway hubble record "10.4.0.0/16 0 1.1.1.1/32 80 ANY" --time-limit 5s
  Started recording. Press CTRL+C to stop.
  2022-12-12T13:36:45Z Status: 0 packets (0 bytes) written
  [...]
  2022-12-12T13:37:35Z Output: /var/run/cilium/pcaps/hubble_1670852201_281908850_c3-small-x86-01.pcap

Currently active recorders with wildcard masks and filters can be queried on the agent
itself as follows:

.. parsed-literal::

  docker exec cilium-gateway cilium recorder list
  ID      Capture Length   Wildcard Filters
  10479   full             10.5.0.0/16:0      ->   1.1.1.1/32:8080   ANY
  12365   full             10.4.0.0/16:0      ->   1.1.1.1/32:80     ANY
  31782   full             0.0.0.0/0:0        ->   1.2.3.4/32:0      ANY

  Users   Priority      Wildcard Masks
  2       64            ffff0000:0       ->   ffffffff:ffff   0
  1       32            00000000:0       ->   ffffffff:0      0

The command-line interface tool via ``hubble record`` also implements further options, for
example, to limit the packet capture length via ``--max-capture-len`` and to have a custom
file name prefix via ``--max-capture-len``:

.. parsed-literal::

  docker exec cilium-gateway hubble record "10.4.0.0/16 0 1.1.1.1/32 80 ANY" --time-limit 5s --max-capture-len 100 --file-prefix recorder
  Started recording. Press CTRL+C to stop.
  2022-12-12T13:55:59Z Status: 0 packets (0 bytes) written
  [...]
  2022-12-12T13:56:00Z Output: /var/run/cilium/pcaps/recorder_1670853355_3494557023_c3-small-x86-01.pcap

The resulting PCAP files can be used for later analysis with familiar tools such as
Wireshark and tcpdump.

NAT46 Gateway
-------------

The Cilium Standalone Gateway supports both NAT46 and NAT64 with the primary
goal to ease deployment of IPv6 single stack Kubernetes clusters. Note that
NAT46/64 transformations were so far only possible through out-of-tree kernel
modules or userspace-only networking appliances. Cilium Standalone Gateway
implements NAT46 and NAT64 with the help of eBPF through a stock kernel,
therefore in general none of such workarounds are necessary anymore.

In this section here the primary focus is on NAT46. The main use-case for NAT46
is to connect external IPv4-based clients or workloads to an IPv6-only cluster.

In this guide we use Kubernetes clusters as an example, however, the gateway
can operate also in any other environment.

There are two options for operating the NAT46 Gateway, stateful and stateless.
Both have their own advantages and disadvantages which are discussed below.

The NAT46 and NAT64 gateway can be operated alongside the load-balancer. A
minimal configuration to enable the NAT46/64 gateway is as follows:

.. parsed-literal::

   docker run --name cilium-gateway -td \\
     -v /sys/fs/bpf:/sys/fs/bpf \\
     -v /lib/modules:/lib/modules \\
     --privileged=true \\
     --network=host \\
     quay.io/cilium/cilium:|IMAGE_TAG| \\
     cilium-agent \\
     --enable-ipv4=true \\
     --enable-ipv6=true \\
     --datapath-mode=lb-only \\
     --bpf-lb-acceleration=native \\
     --enable-nat46x64-gateway=true \\
     --devices=bond0

Stateful Gateway
~~~~~~~~~~~~~~~~

Consider an IPv6-only single stack Kubernetes cluster as the target for the NAT46
gateway to let external IPv4 traffic ingress into the pure IPv6-only cluster.

While the Kubernetes cluster itself is IPv6-only single stack, the Cilium Standalone
Gateway at the edge of the cluster is operating outside of Kubernetes realm as a dual
stack component given it needs to translate between IPv4 and IPv6.

Consider ``[2606:4700:4700::1111]:80`` as an example VIP:port which has been exposed
natively by the IPv6-only single stack Kubernetes as a ``LoadBalancer`` service.

The stateful NAT46 gateway then exposes an IPv4 VIP:port in order to then map it to
the IPv6 VIP:port as a 1:1 translation entry. Thus for IPv4 access, one gateway hop
is necessary.

.. parsed-literal::

  docker exec cilium-gateway cilium service update --id 1 --frontend "86.109.5.207:8080" --backends "[2606:4700:4700::1111]:80"  --k8s-external
  Creating new service with id '1'
  Added service with 1 backends

  docker exec cilium-gateway cilium service list
  ID   Frontend            Service Type   Backend
  1    86.109.5.207:8080   ExternalIPs    1 => [2606:4700:4700::1111]:80 (active)

The IPv6 cluster can then be accessed from an external IPv4 client:

.. parsed-literal::

  curl --verbose 86.109.5.207:8080
  *   Trying 86.109.5.207...
  * TCP_NODELAY set
  * Connected to 86.109.5.207 (86.109.5.207) port 8080 (#0)
  > GET / HTTP/1.1
  > Host: 86.109.5.207:8080
  > User-Agent: curl/7.64.0
  > Accept: */*
  >
  < HTTP/1.1 403 Forbidden
  [...]

In this case the frontend address is the publicly accessible IP address of
the gateway node itself. If a different IPv4 VIP is being used, then these
need to be announced to the network through BGP daemons such as FRR.

The NAT46 gateway node translates the original IPv4 inbound request to the
IPv6 VIP:port as a destination and masquerades the request with its own
IPv6 address as source such that replies are directed back to the NAT46
gateway node where it then reverse translates everything.

Packet flow diagram:

.. parsed-literal::

     Internet       │                    │  K8s IPv6 Cluster
                    │                    │
     ---------------+-----(request)------+---------->>>>>
     <<<<<----------+------(reply)-------+---------------
                    │                    │
    ┌──────────┐    │    ┌──────────┐    │    ┌──────────┐
    │External  │    │    │Cilium    │    │    │K8s Node  │
    │Client    │    │    │Standalone│    │    │          │
    │          │    │    │Gateway   │    │    │          │
    │          │    │    │          │    │    │          │
    │IPv4_C    │    │    │IPv4_G    │    │    │-         │
    │-         │    │    │IPv6_G    │    │    │IPv6_N    │
    └──────────┘    │    └──────────┘    │    └──────────┘
                    │    IPv4_S:pS4      │     IPv6_S:pS6
                    │                    │
    Legend:

     - IPv4_S:pS4 is the IPv4 service VIP:port on the gateway. IPv4_S
       can be the same as IPv4_G, but this is not required.
       If IPv4_S != IPv4_G, then IPv4_S needs to be announced via BGP.
     - IPv6_S:pS6 is the IPv6 service VIP:port for the LoadBalancer
       service. Port pS4 can be the same as pS6, but this is not
       required.
     - pC and pG denote the source port of the client and gateway node.
       Depending on masquerading they can be the same or mapped to a
       different port.

    Request:

     1.  IPv4_C:pC -> IPv4_S:pS4
     2.                       IPv6_G:pG -> IPv6_S:pS6
     3.                       IPv6_G:pG <- IPv6_S:pS6
     4.  IPv4_C:pC <- IPv4_S:pS4

This approach has the upside that:

- It's easy to configure and the NAT46 gateway node can even reside anywhere
  on the Internet.
- The exposed IPv4 VIP:port is completely decoupled from the Kubernetes
  cluster and the cluster does not need to have any awareness of the gateway.
- Features from the layer 4 load-balancer can be reused, and the gateway
  could load-balance across multiple IPv6 VIP:ports e.g. residing in different
  clusters.

This approach has the downside that:

- It's stateful due to the L4-based NAT translation/masquerading, and therefore
  high-availability/fail-over cannot be done transparently for ongoing connections.
- The original client's source IPv4 information is lost when requests reach
  the target cluster.
- Extra control plane operations are needed to program VIP to VIP mappings
  through the exposed API.

Stateless Gateway
~~~~~~~~~~~~~~~~~

For the stateless gateway example, we reuse the Kubernetes cluster with IPv6-only
single stack. The Cilium Standalone Gateway is again at the edge of the cluster,
operating outside of Kubernetes realm as the only dual stack component.

This time, the stateless gateway requires no extra configuration compared to the
stateful one. Consider an inbound request of ``1.2.3.4:port-a -> 5.6.7.8:port-b``
towards the gateway. The gateway will then L3-translate this IPv4 request into an
IPv6 request of format ``[64:ff9b::1.2.3.4]:port-a -> [64:ff9b::5.6.7.8]:port-b``
and forwards the packet into the Kubernetes cluster. The ``64:ff9b::/96`` is a
well-known IPv6 prefix dedicated for NAT46/64 translations.

The Kubernetes cluster itself must have a ``LoadBalancer`` service exposed to the
local network with a VIP:port of ``[64:ff9b::5.6.7.8]:port-b``. Such specific
``LoadBalancer`` service pools can for example be configured through using
Cilium for Kubernetes where :ref:`lb_ipam` pools can be defined for services.
The IPv4 encoded addresses for the ``64:ff9b::`` prefixed VIP must be a publicly
routable address.

In this case the service table is empty:

.. parsed-literal::

  docker exec cilium-gateway cilium service list
  ID   Frontend            Service Type   Backend
  [ empty ]

For the gateway, the publicly routable IPv4 frontend VIPs must be announced to the
network through BGP daemons such as FRR to attract traffic destined to them onto
the stateless gateway nodes.

The stateless gateway functionality is automatically engaged upon reception of
IPv4 traffic where the destination address is not targeted at the node itself.
If the gateway also exposes IPv4 VIP:port in its service table, then these are
served first. In fact, the stateful and stateless gateway can even be operated
at the same time.

Packet flow diagram:

.. parsed-literal::

     Internet       │                    │  K8s IPv6 Cluster
                    │                    │
     ---------------+-----(request)------+---------->>>>>
     <<<<<----------+------(reply)-------+---------------
                    │                    │
    ┌──────────┐    │    ┌──────────┐    │    ┌──────────┐
    │External  │    │    │Cilium    │    │    │K8s Node  │
    │Client    │    │    │Standalone│    │    │          │
    │          │    │    │Gateway   │    │    │          │
    │          │    │    │          │    │    │          │
    │IPv4_C    │    │    │IPv4_G    │    │    │-         │
    │-         │    │    │IPv6_G    │    │    │IPv6_N    │
    └──────────┘    │    └──────────┘    │    └──────────┘
                    │    IPv4_S:pS       │     IPv6_S:pS
                    │                    │
    Legend:

     - IPv6_S:pS is the IPv6 service VIP:port for the LoadBalancer
       service. IPv6_S must be crafted as [64:ff9b::IPv4_S] through
       a load-balancer IPAM pool in Kubernetes.
     - IPv4_S:pS is the IPv4 service VIP:port exposed to the outside
       world for IPv4 connectivity. It is likely that IPv4_S != IPv4_G,
       so IPv4_S needs to be announced via BGP.
     - pS denotes the source port of the service and is the same port
       for both IPv4_S:pS and IPv6_S:pS tuples.
     - pC denotes the source port of the client.

    Request:

     1.  IPv4_C:pC -> IPv4_S:pS
     2.                [64:ff9b::IPv4_C]:pC -> [64:ff9b::IPv4_S]:pS
     3.                [64:ff9b::IPv4_C]:pC <- [64:ff9b::IPv4_S]:pS
     4.  IPv4_C:pC <- IPv4_S:pS

This approach has the upside that:

- No extra control plane operations are needed for programming VIPs on the gateway
  node.
- The original client's source IPv4 information is preserved and encoded in the
  IPv6 source address. This allows for better analytics inside the cluster.
- It's stateless due to the L3-based NAT translation, and therefore suited for
  high-availability as fail-over can be done transparently for ongoing connections.

This approach has the downside that:

- Involved to set up and the NAT46 gateway node cannot reside anywhere on the
  Internet, but must be in the same network. This might only work for on-prem
  environments.
- The Kubernetes cluster needs cooperation, that is, specific ``64:ff9b::``-prefixed
  IPv6 ``LoadBalancer`` service addresses are needed, and a next hop route is
  needed on each cluster node to direct replies for all ``64:ff9b::/96``-destined
  traffic towards the gateway nodes for reverse translation.

Toy example on a Cilium Kubernetes cluster:

We configure a ``5.5.5.0/24`` service CIDR which all contain publicly routable
IPv4 addresses and embed this into a ``64:ff9b::`` prefix:

.. parsed-literal::

  apiVersion: "cilium.io/v2alpha1"
  kind: CiliumLoadBalancerIPPool
  metadata:
    name: "nat64-pool"
  spec:
    cidrs:
    - cidr: "64:ff9b::5.5.5.0/120"
    serviceSelector:
      matchLabels:
        color: red

Then, for the cluster a ``LoadBalancer`` service is created to pick an address from
this pool based on the matching ``color`` label:

.. parsed-literal::

  apiVersion: v1
  kind: Service
  metadata:
    name: nat64-service
    labels:
      color: red
  spec:
    selector:
      app: example
    type: LoadBalancer
    ports:
    - port: 1234

For the reply traffic on cluster nodes, a route needs to be installed such that
``64:ff9b::/96``-destined traffic is pushed towards the Cilium Standalone Gateway
residing under ``2604:1380:4091:cf00::1``:

.. parsed-literal::

   ip -6 r add 64:ff9b::/96 via 2604:1380:4091:cf00::1 dev eth0

Multi-path routes are supported as well given the gateway does not hold connection
state. In future, Cilium for Kubernetes will provide a CRD to ease this configuration.

On the Cilium Standalone Gateway, the CIDR of ``5.5.5.0/24`` needs to be announced
via BGP that it is reachable through the gateway node.

Assuming the service received an IPv6 address of ``64:ff9b::505:501``, it would
then correspond to an IPv4 address of ``5.5.5.1`` for the gateway.

From the client, the service can be reached now:

.. parsed-literal::

  curl --verbose 5.5.5.1
  *   Trying 5.5.5.1:80...
  * Connected to 5.5.5.1 (5.5.5.1) port 80 (#0)
  > GET / HTTP/1.1
  > Host: 5.5.5.1
  > User-Agent: curl/7.81.0
  > Accept: */*
  >
  * Mark bundle as not supporting multiuse
  < HTTP/1.1 200 OK
  [...]

NAT64 Gateway
-------------

In this section here the primary focus is on NAT64. The main use-case for NAT64
is to allow an IPv6-only cluster to connect to the outside world to IPv4 endpoints.

Again, in this guide we use Kubernetes clusters as an example, however, the gateway
can operate also with any other environment.

One additional component in the NAT64 case which is crucial for the cluster is DNS64.
There are `public DNS64 resolver <https://developers.google.com/speed/public-dns/docs/dns64>`_,
but also tools such as `CoreDNS support DNS64 <https://coredns.io/plugins/dns64/>`_.
The purpose of the DNS64 is that when asked for a domain's AAAA records but only
A records can be found, then the proxy synthesizes AAAA records from the A records.
The synthesized AAAA records have the IPv4 addresses encoded as ``[64:ff9b::IPv4]``.

There are two options for operating the NAT64 Gateway, stateful and stateless.
Both have their own advantages and disadvantages which are discussed below.

Both the NAT46 and NAT64 gateway can be operated alongside the load-balancer. The
minimal configuration needed to enable the NAT46/64 gateway is as follows:

.. parsed-literal::

   docker run --name cilium-gateway -td \\
     -v /sys/fs/bpf:/sys/fs/bpf \\
     -v /lib/modules:/lib/modules \\
     --privileged=true \\
     --network=host \\
     quay.io/cilium/cilium:|IMAGE_TAG| \\
     cilium-agent \\
     --enable-ipv4=true \\
     --enable-ipv6=true \\
     --datapath-mode=lb-only \\
     --bpf-lb-acceleration=native \\
     --enable-nat46x64-gateway=true \\
     --devices=bond0

Stateful Gateway
~~~~~~~~~~~~~~~~

Consider an IPv6-only single stack Kubernetes cluster as the target for the NAT64
gateway to allow the pure IPv6-only cluster to communicate with external IPv4
endpoints.

While the Kubernetes cluster itself is IPv6-only single stack, the Cilium Standalone
Gateway at the edge of the cluster is operating outside of Kubernetes realm as a dual
stack component given it needs to translate between IPv6 and IPv4.

The stateful gateway functionality is automatically engaged upon reception of
IPv6 traffic where the destination address is of type ``[64:ff9b::a.b.c.d]``
but the source address of the packet is a regular CIDR outside of the ``64:ff9b::/96``
range.

Packet flow diagram:

.. parsed-literal::

     Internet       │                    │  K8s IPv6 Cluster
                    │                    │
     <<<<<----------+-----(request)------+---------------
     ---------------+------(reply)-------+---------->>>>>
                    │                    │
    ┌──────────┐    │    ┌──────────┐    │    ┌──────────┐
    │External  │    │    │Cilium    │    │    │K8s Node  │
    │Endpoint  │    │    │Standalone│    │    │          │
    │          │    │    │Gateway   │    │    │          │
    │          │    │    │          │    │    │          │
    │IPv4_E    │    │    │IPv4_G    │    │    │-         │
    │-         │    │    │IPv6_G    │    │    │IPv6_NP   │
    └──────────┘    │    └──────────┘    │    └──────────┘
      foo.com       │                    │
                    │                    │
    Legend:

     - IPv6_NP is the regular IPv6 address of a node or Pod in the
       cluster which initiated the request. pNP denotes the
       corresponding source port.
     - IPv4_E:pE is the external IPv4 address:port.
     - pG denotes the source port of the gateway node. Depending on
       masquerading it can be the same as pNP or mapped to a different
       port when necessary.

    Step 1: DNS resolution:

     1. The K8s Node/Pod triggers a DNS resolution for foo.com
     2. The DNS resolver for the K8s cluster is a DNS64 capable resolver
     3. The AAAA request goes to the DNS64 proxy at the edge of the
        cluster. The DNS64 proxy is a dual stack component like the gateway.
     4. The DNS64 proxy translates the IPv6 AAAA request into an
        IPv4 A request.
     5. IPv4 A record with IPv4_E is returned to the DNS64 proxy as reply.
     6. The DNS64 proxy proxy translates the IPv4 A record into an
        IPv6 AAAA record with address [64:ff9b::IPv4_E].

    Step 2: Actual Request:

     1.                [64:ff9b::IPv4_E]:pE <- IPv6_NP:pNP
     2.  IPv4_E:pE <- IPv4_G:pG
     3.  IPv4_E:pE -> IPv4_G:pG
     4.                [64:ff9b::IPv4_E]:pE -> IPv6_NP:pNP

This approach has the upside that:

- This approach generically works for any IPv4 address returned/embedded
  from the AAAA record.
- It's easy to configure, the NAT64 gateway node does not need any special
  configuration for a given IPv4 destination.
- The Kubernetes cluster does not need any special node/Pod IPAM addressing
  and can just use regular IPv6 addresses as source address.

This approach has the downside that:

- It's stateful due to the L4-based NAT translation/masquerading, and therefore
  high-availability/fail-over cannot be done transparently for ongoing connections.
- The cluster needs to be configured with DNS64 in order to return ``64:ff9b::``-prefixed
  AAAA records.
- A next hop route is needed on each cluster node to direct replies for all
  ``64:ff9b::/96``-destined traffic towards the gateway nodes for translation.

Toy example on a cluster node:

.. parsed-literal::

  git clone --ipv6 https://github.com/cilium/cilium.git
  Cloning into 'cilium'...
  fatal: unable to access 'https://github.com/cilium/cilium.git/': Could not resolve host: github.com

Now with a DNS64 setup and a route to point ``64:ff9b::/96``-destined traffic towards
the Cilium Standalone Gateway residing under ``2604:1380:4091:cf00::1``:

.. parsed-literal::

   cat /etc/resolv.conf
   nameserver 2001:4860:4860::6464

   ip -6 r add 64:ff9b::/96 via 2604:1380:4091:cf00::1 dev eth0

The same command now succeeds:

.. parsed-literal::

  git clone --ipv6 https://github.com/cilium/cilium.git
  Cloning into 'cilium'...
  remote: Enumerating objects: 331311, done.
  remote: Counting objects: 100% (154/154), done.
  remote: Compressing objects: 100% (105/105), done.
  remote: Total 331311 (delta 86), reused 66 (delta 46), pack-reused 331157
  Receiving objects: 100% (331311/331311), 240.51 MiB | 22.48 MiB/s, done.
  Resolving deltas: 100% (240079/240079), done.

Independent of the above but related to NAT64, another use-case which is supported by
the Cilium Standalone Gateway would be to expose any IPv6 VIP:port and then map it to
an IPv4 VIP:port as a 1:1 translation entry. This is essentially similar to the stateful
NAT46 gateway just in reverse for NAT64.

The use-case here would be if an existing IPv4 single stack Kubernetes cluster must
be exposed to the outside world such that it becomes accessible for other IPv6 external
clients without having to migrate the IPv4 single stack Kubernetes cluster to a dual
stack one.

.. parsed-literal::

  docker exec cilium-gateway cilium service update --id 1 --frontend "[2604:1380:4091:cf00::1]:8080" --backends "1.1.1.1:80"  --k8s-external
  Creating new service with id '1'
  Added service with 1 backends

  docker exec cilium-gateway cilium service list
  ID   Frontend                        Service Type   Backend
  1    [2604:1380:4091:cf00::1]:8080   ExternalIPs    1 => 1.1.1.1:80 (active)

The IPv6 cluster can then access the IPv4 endpoint through the IPv6 service VIP:port:

.. parsed-literal::

  curl --verbose "[2604:1380:4091:cf00::1]:8080"
  *   Trying 2604:1380:4091:cf00::1:8080...
  * TCP_NODELAY set
  * Connected to 2604:1380:4091:cf00::1 (2604:1380:4091:cf00::1) port 8080 (#0)
  > GET / HTTP/1.1
  > Host: [2604:1380:4091:cf00::1]:8080
  > User-Agent: curl/7.68.0
  > Accept: */*
  >
  * Mark bundle as not supporting multiuse
  < HTTP/1.1 403 Forbidden
  [...]

In this case the frontend address is the publicly accessible IPv6 address of
the gateway node itself. If a different IPv6 VIP is being used, then these
need to be announced to the network through BGP daemons such as FRR.

Packet flow diagram:

.. parsed-literal::

     Internet       │                    │  K8s IPv4 Cluster
                    │                    │
     ---------------+-----(request)------+---------->>>>>
     <<<<<----------+------(reply)-------+---------------
                    │                    │
    ┌──────────┐    │    ┌──────────┐    │    ┌──────────┐
    │External  │    │    │Cilium    │    │    │K8s Node  │
    │Client    │    │    │Standalone│    │    │          │
    │          │    │    │Gateway   │    │    │          │
    │          │    │    │          │    │    │          │
    │IPv6_C    │    │    │IPv4_G    │    │    │-         │
    │-         │    │    │IPv6_G    │    │    │IPv4_N    │
    └──────────┘    │    └──────────┘    │    └──────────┘
                    │    IPv6_S:pS6      │     IPv4_S:pS4
                    │                    │
    Legend:

     - IPv6_S:pS6 is the IPv6 service VIP:port on the gateway. IPv6_S
       can be the same as IPv6_G, but this is not required.
       If IPv6_S != IPv6_G, then IPv6_S needs to be announced via BGP.
     - IPv4_S:pS4 is the IPv4 service VIP:port for the LoadBalancer
       service. Port pS6 can be the same as pS4, but this is not
       required.
     - pC and pG denote the source port of the client and gateway node.
       Depending on masquerading they can be the same or mapped to a
       different port.

    Request:

     1.  IPv6_C:pC -> IPv6_S:pS6
     2.                       IPv4_G:pG -> IPv4_S:pS4
     3.                       IPv4_G:pG <- IPv4_S:pS4
     4.  IPv6_C:pC <- IPv6_S:pS6

This approach has the same up- and downsides as the stateful NAT46 gateway.
Moreover, for this specific use-case, there is no alternative stateless
design possible.

Stateless Gateway
~~~~~~~~~~~~~~~~~

Again, consider an IPv6-only single stack Kubernetes cluster as the target for
the stateless NAT64 gateway to allow the pure IPv6-only cluster to communicate
with external IPv4 endpoints.

The stateless gateway functionality is automatically engaged upon reception of
IPv6 traffic where both source and destination addresses are of the
format ``[64:ff9b::a.b.c.d]``. The stateful and stateless gateway can even be
operated at the same time.

Packet flow diagram:

.. parsed-literal::

     Internet       │                    │  K8s IPv6 Cluster
                    │                    │
     <<<<<----------+-----(request)------+---------------
     ---------------+------(reply)-------+---------->>>>>
                    │                    │
    ┌──────────┐    │    ┌──────────┐    │    ┌──────────┐
    │External  │    │    │Cilium    │    │    │K8s Node  │
    │Endpoint  │    │    │Standalone│    │    │          │
    │          │    │    │Gateway   │    │    │          │
    │          │    │    │          │    │    │          │
    │IPv4_E    │    │    │IPv4_G    │    │    │-         │
    │-         │    │    │IPv6_G    │    │    │IPv6_NP1  │
    │          │    │    │          │    │    │IPv6_NP2  │
    └──────────┘    │    └──────────┘    │    └──────────┘
      foo.com       │                    │     IPv6_NP2 := [64:ff9b::IPv4_NP]
                    │                    │
    Legend:

     - IPv6_NP1 is the primary IPv6 address of a node or Pod in
       the cluster.
     - IPv6_NP2 is a secondary IPv6 address of a node or Pod in
       the cluster, which is used here to initiate the request.
     - While the node or Pod does not have any IPv4 address assigned,
       the IPv6_NP2 is constructed by an IPAM as [64:ff9b::IPv4_NP].
       The encoded IPv4_NP is a publicly routable adress. pNP denotes
       the corresponding source port.
     - IPv4_E:pE is the external IPv4 address:port.

    Step 1: DNS resolution (same steps as in earlier example):

     1. The K8s Node/Pod triggers a DNS resolution for foo.com
     2. The DNS resolver for the K8s cluster is a DNS64 capable resolver
     3. The AAAA request goes to the DNS64 proxy at the edge of the
        cluster. The DNS64 proxy is a dual stack component like the gateway.
     4. The DNS64 proxy translates the IPv6 AAAA request into an
        IPv4 A request.
     5. IPv4 A record with IPv4_E is returned to the DNS64 proxy as reply.
     6. The DNS64 proxy proxy translates the IPv4 A record into an
        IPv6 AAAA record with address [64:ff9b::IPv4_E].

    Step 2: Actual Request:

     1.                [64:ff9b::IPv4_E]:pE <- IPv6_NP2:pNP that is
                       [64:ff9b::IPv4_E]:pE <- [64:ff9b::IPv4_NP]:pNP
     2.  IPv4_E:pE <- IPv4_NP:pNP
     3.  IPv4_E:pE -> IPv4_NP:pNP
     4.                [64:ff9b::IPv4_E]:pE -> [64:ff9b::IPv4_NP]:pNP
               that is [64:ff9b::IPv4_E]:pE <- IPv6_NP2:pNP

This approach has the upside that:

- It's stateless due to the L3-based NAT translation, and therefore suited for
  high-availability as fail-over can be done transparently for ongoing connections.
- This approach also generically works for any IPv4 address returned/embedded
  from the AAAA record.

This approach has the downside that:

- Involved to set up. The Kubernetes cluster needs a special IPAM where nodes or Pods
  get a secondary IPv6 address in the form of ``[64:ff9b::IPv4_NP]``.
  The CNI needs to install a routing rule into Pods to select ``[64:ff9b::IPv4_NP]`` as
  a source address for all ``64:ff9b::/96``-destined traffic.
- Due to the ``[64:ff9b::IPv4_NP]`` format, the benefits of a highly scalable IPv6 IPAM
  may be limited since routable IPv4 CIDRs are needed. This may be less of a problem if
  not all Pods are in need for connecting to IPv4.
- A next hop route is needed on each cluster node to direct replies for all
  ``64:ff9b::/96``-destined traffic towards the gateway nodes for translation.
- The cluster needs to be configured with DNS64 in order to return ``64:ff9b::``-prefixed
  AAAA records.

Cilium for Kubernetes currently does not support such an IPAM mode where Pods
receive addressing from two different IPAM pools, but this is something that
is planned to resolve in next Cilium releases so that for Kubernetes this
scenario will be supported, too.

Tuning Considerations
---------------------

For optimal performance, we recommend the following:

    * Enable native XDP for the gateway: ``--bpf-lb-acceleration=native``
    * Enable faster access to clock for the gateway: ``--enable-bpf-clock-probe=true``
    * Have a recent, up-to-date kernel and consider building it
      with ``CONFIG_PREEMPT_NONE=y`` for server-type workloads.
    * Stop ``irqbalance`` and pin the NIC's RX/TX IRQs to CPUs with
      a 1:1 affinity mapping for maximum isolation/siloing. In case
      of multi-socket nodes, it is advisable to ensure to pin the IRQs
      to the NUMA node where the NIC slot is connected to in order to
      lower inter-node transfers and to use only local node memory.
    * If necessary, set the CPU governor to performance profile.
    * Consider larger map sizes than the default, depending on your
      scale needs. Please refer to the :ref:`bpf_map_limitations` guide.

Some of these are elaborated further on in our general :ref:`performance_tuning`
document.

Limitations
===========

The following limitations below apply at this point in time:

    * Cilium's eBPF load-balancer does not yet support XDP multi-buffer mode
      for supporting 9k MTUs.
    * Backend weights is currently only supported under Maglev and not yet
      Random mode.
    * Upon Cilium restart the backend weights are preserved as-is, however, the
      displayed weights value in the ``cilium service list`` json/yaml dump is
      currently not preserved and will display ``1``. See further details
      in `GH-18306 <https://github.com/cilium/cilium/pull/18306>`_. This does
      not affect operations in the datapath, however it is planned to get fixed.
    * PMTU discovery with ICMPv4/ICMPv6 replies is currently only supported
      under XDP mode.
    * Cilium's eBPF load-balancer does not support the SCTP transport protocol.
      Only TCP and UDP is supported as a transport for services at this point.
    * Wildcard-filter rules with port ranges are currently not supported by the
      PCAP recorder
    * The PCAP recorder currently supports up to 32 mask rules. However, within
      the set of installed masks, millions of filter entries can be added.
    * The PCAP recorder is currently only enabled under XDP acceleration.

Further Readings
================

The following resources contain further details on the standalone gateway or
related features and functionality:

- `XDP-based Standalone Load Balancer
  <https://cilium.io/blog/2021/05/20/cilium-110/#standalonelb>`_
  (Cilium 1.10 release announcement)
- `Cilium Standalone Layer 4 Load Balancer XDP
  <https://cilium.io/blog/2022/04/12/cilium-standalone-L4LB-XDP/>`_
- `NAT46/NAT64 support for Load Balancer
  <https://isovalent.com/blog/post/cilium-release-112/#nat46-nat64>`_
- `Cilium Standalone XDP L4 Load Balancer
  <https://www.youtube.com/watch?v=0YqF45Kaapo&t=7259s>`_
  (eBPF Summit 2022)
- `100Gbit/s Clusters With Cilium: Building Tomorrow’s Networking Data Plane
  <https://sched.co/182DB>`_
- `Graceful Backend Termination
  <https://isovalent.com/blog/post/cilium-release-112/#quarantining>`_
- `Managed IPv4/IPv6 Neighbor Discovery
  <https://isovalent.com/blog/post/2021-12-release-111/#managed-ipv4-ipv6-discovery>`_
- `XDP Multi-Device Load-Balancer Support
  <https://isovalent.com/blog/post/2021-12-release-111/#xdp-multi-dev>`_
- `Transparent XDP Bonding Support
  <https://isovalent.com/blog/post/2021-12-release-111/#transparent-xdp-bonding-support>`_
- `eCHO Episode 9: XDP and Load Balancing
  <https://www.youtube.com/watch?v=OIyPm6K4ooY>`_
- `A BPF map for online packet classification
  <https://lpc.events/event/16/contributions/1356/>`_
