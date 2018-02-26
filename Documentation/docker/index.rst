******
Docker
******

Cilium can be integrated with Docker in two ways:

* via the `CNI` interface. This is the method chosen by `Kubernetes` and :ref:`Mesos`.
* via Docker's `libnetwork`_ plugin interface if networking is to be managed by
  the Docker runtime. This method is used for example by Docker compose.

When using Cilium with Docker's libnetwork, one creates a single logical Docker
network of type ``cilium`` and with an IPAM-driver of type ``cilium``, which
delegates control over IP address management and network connectivity to Cilium
for all containers attached to this network for both IPv4 and IPv6
connectivity.  Each Docker container gets an IP address from the node prefix of
the node running the container.

When deployed with Docker, each Linux node runs a ``cilium-docker`` agent,
which receives libnetwork calls from Docker and then communicates with the
Cilium Agent to control container networking.

Security policies controlling connectivity between the Docker containers can be
written in terms of the Docker container labels passed to Docker while creating
the container.  These policies can be created/updated via communication
directly with the Cilium agent, either via API or by using the Cilium CLI
client.

The the following guide for a step by step introduction on how to use Cilium with
Docker compose:

.. toctree::
   :maxdepth: 1
   :glob:

   ../gettingstarted/docker


.. _libnetwork: https://github.com/docker/libnetwork/blob/master/docs/design.md
