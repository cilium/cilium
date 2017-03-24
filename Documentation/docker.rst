Cilium Docker Plugin
====================

The Cilium docker plugin provides integration of Cilium with Docker. The
plugin will provide both, address allocation (IPAM) and connectivity
(plumbing).

Installation
------------

The plugin requires a running Cilium daemon to manage BPF programs, see
`installation <installation.md>`__ for detailed instructions on how to
install the daemon itself.

The plugin consists of a single binary ``cilium-docker`` which can be
installed in any location. The ``make install`` target will install it
in ``bindir``. For connectivity to the Cilium daemon, the UNIX domain
socket of the daemon (``/var/run/cilium.sock``) must be accessible for
the plugin.

Various templates for integration with service management tools such as
upstart or systemd can be found in the ```contrib/`` <../contrib>`__
directory.

NOTE: Docker libnetwork is currently not capable of running IPv6 only
containers via the libnetwork abstraction. A `pull
request <https://github.com/docker/libnetwork/pull/826>`__ is pending to
resolve this.

Usage
-----

As isolation and segmentation is enforced based on container labels. It
is not required to create multiple networks. You may do so but it will
not impact any segmentation rules. It is suggested to create a single
Docker network. Please note that IPv6 must be enabled on the network as
the IPv6 address is also the unique identifier for each container:

::

    $ docker network create --ipv6 --subnet ::1/112 --driver cilium --ipam-driver cilium cilium
    $ docker run --net cilium hello-world

Address Management (IPAM)
-------------------------

The ``cilium-docker`` plugin will allocate an unique IPv6 address out of
the address prefix assigned to the container host. See
`here <model.md#prefix-list>`__ for additional information on the
addressing model of Cilium.
