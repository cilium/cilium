Installation
============

.. toctree::

   vagrant

This section describes the installation procedure in various environments.
Please choose a guide that fits your needs:

Cilium consists of an agent plus additional optional integration plugins
which must be installed on all servers which will run containers.

Simple Installation
-------------------

Most initial users may prefer to use the pre built Docker images in
combination with compose files or Kubernetes specs. Instructions on how
to use these can be found here: \* `Tutorial with Docker
compose <../examples/docker-compose/README.md>`__

Networking Requirements
-----------------------

Cilium can operate in multiple modes to meet different integration
requirements with existing networks.

Manual Installation
-------------------

Running ``make install`` will install cilium binaries in your ``bindir``
and all required additional runtime files in ``libdir/cilium``.

Templates for integration into service management systems such as
systemd and upstart can be found in the ```contrib`` <../contrib>`__
directory.

::

    service cilium start

Integration with existing networking
------------------------------------

The minimal requirements are networking with IPv6 connectivity on the
node cilium is being run on. IPv6 forwarding must be enabled as well:

::

    sysctl -w net.ipv6.conf.all.forwarding=1

Connectivity can be tested with:

::

    ip -6 route get `host -t aaaa www.google.com | awk '{print $5}'`
    ping6 www.google.com

If the default route is missing, your VM may not be receiving router
advertisements. In this case, the default route can be added manually:

::

    ip -6 route add default via beef::1

The following tests connectivity from a container to the outside world:

::

    $ sudo docker run --rm -ti --net cilium -l client noironetworks/nettools ping6 www.google.com
    PING www.google.com(zrh04s07-in-x04.1e100.net) 56 data bytes
    64 bytes from zrh04s07-in-x04.1e100.net: icmp_seq=1 ttl=56 time=7.84 ms
    64 bytes from zrh04s07-in-x04.1e100.net: icmp_seq=2 ttl=56 time=8.63 ms
    64 bytes from zrh04s07-in-x04.1e100.net: icmp_seq=3 ttl=56 time=8.83 ms

Note that an appropriate policy must be loaded or policy enforcement
will drop the relevant packets. An example policy can be found in
```examples/policy/test/`` <../examples/policy/test>`__ which will allow
the above container with the label ``io.cilium`` to be reached from
world scope. To load and test:

::

    $ cilium policy import examples/policy/test/test.policy
    $ cilium policy allowed -s reserved:world -d io.cilium

Announce the IPv6 container prefix on each host
-----------------------------------------------

To make containers reachable across multiple hosts, each local prefix of
each node must be announced on the network and configured on all other
nodes. This can be achieved by running a routing daemon such as bird,
zebra or radvd. Alternatively routes can be configured statically:

::

    ip -6 route add beef::c0a8:79aa:0/112 via $NODE_ADDRESS

Private IPv6 addresses for containers
-------------------------------------

If privates IPv6 addresses are being used to address containers. The
addresses must be masquaraded. This can be done on each node or at the
gateway/edge as the packets leave the internal network. An example
ip6tables rule to achieve this is:

::

    ip6tables -t nat -I POSTROUTING -s beef::/64 -o em1 -j MASQUERADE

This will masquerade all packets with a source of ``beef::/64`` with the
public IPv6 address of ``em1`` as they leave ``em1``
