.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

******
Docker
******

Cilium can be integrated with Docker in two ways:

* via the `CNI` interface. This method is used by `Kubernetes` and :ref:`Mesos`.
* via Docker's `libnetwork`_ plugin interface, if networking is to be managed by
  the Docker runtime. This method is used, for example, by `Docker Compose`_.

To run Cilium with Docker's libnetwork, it needs a single logical Docker
network of type ``cilium`` with an IPAM-driver of type ``cilium``. The
IPAM-driver delegates control over IPv4 and IPv6 address management and network
connectivity to Cilium for all containers attached to this network. Each Docker
container is allocated an IP address from the node prefix of the node running
that container.

When deployed with Docker, each Linux node must also run a ``cilium-docker``
agent that receives libnetwork calls from Docker and then communicates with the
Cilium Agent to control container networking.

Security policies controlling connectivity between the Docker containers can be
written in terms of the Docker container labels passed to Docker when creating
the container. These policies can be created and updated via the Cilium agent
API or by using the Cilium CLI client.

Follow this guide for a step by step introduction on how to use Cilium with
`Docker Compose`_:

.. toctree::
   :maxdepth: 1
   :glob:

   ../gettingstarted/docker


.. _libnetwork: https://github.com/docker/libnetwork/blob/master/docs/design.md
.. _`Docker Compose`: https://docs.docker.com/compose/
