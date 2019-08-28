|logo|

|cii| |build-status| |pulls| |slack| |go-report| |go-doc| |rtd| |apache| |gpl|

Cilium is open source software for providing and transparently securing network
connectivity and loadbalancing between application workloads such as
application containers or processes. Cilium operates at Layer 3/4 to provide
traditional networking and security services as well as Layer 7 to protect and
secure use of modern application protocols such as HTTP, gRPC and Kafka. Cilium
is integrated into common orchestration frameworks such as Kubernetes and Mesos.

A new Linux kernel technology called BPF is at the foundation of Cilium. It
supports dynamic insertion of BPF bytecode into the Linux kernel at various
integration points such as: network IO, application sockets, and tracepoints to
implement security, networking and visibility logic. BPF is highly efficient
and flexible. To learn more about BPF, read more in our extensive
`BPF and XDP Reference Guide`_.

.. image:: https://cdn.rawgit.com/cilium/cilium/master/Documentation/images/cilium-arch.png
    :align: center

Functionality Overview
======================

.. begin-functionality-overview

Protect and secure APIs transparently
-------------------------------------

Ability to secure modern application protocols such as REST/HTTP, gRPC and
Kafka. Traditional firewalls operates at Layer 3 and 4. A protocol running on a
particular port is either completely trusted or blocked entirely. Cilium
provides the ability to filter on individual application protocol requests such
as:

- Allow all HTTP requests with method ``GET`` and path ``/public/.*``. Deny all
  other requests.
- Allow ``service1`` to produce on Kafka topic ``topic1`` and ``service2`` to
  consume on ``topic1``. Reject all other Kafka messages.
- Require the HTTP header ``X-Token: [0-9]+`` to be present in all REST calls.

See the section `Layer 7 Policy`_ in our documentation for the latest list of
supported protocols and examples on how to use it.

Secure service to service communication based on identities
-----------------------------------------------------------

Modern distributed applications rely on technologies such as application
containers to facilitate agility in deployment and scale out on demand. This
results in a large number of application containers to be started in a short
period of time. Typical container firewalls secure workloads by filtering on
source IP addresses and destination ports. This concept requires the firewalls
on all servers to be manipulated whenever a container is started anywhere in
the cluster.

In order to avoid this situation which limits scale, Cilium assigns a security
identity to groups of application containers which share identical security
policies. The identity is then associated with all network packets emitted by
the application containers, allowing to validate the identity at the receiving
node. Security identity management is performed using a key-value store.

Secure access to and from external services
-------------------------------------------

Label based security is the tool of choice for cluster internal access control.
In order to secure access to and from external services, traditional CIDR based
security policies for both ingress and egress are supported. This allows to
limit access to and from application containers to particular IP ranges.

Simple Networking
-----------------

A simple flat Layer 3 network with the ability to span multiple clusters
connects all application containers. IP allocation is kept simple by using host
scope allocators. This means that each host can allocate IPs without any
coordination between hosts.

The following multi node networking models are supported:

* **Overlay:** Encapsulation based virtual network spawning all hosts.
  Currently VXLAN and Geneve are baked in but all encapsulation formats
  supported by Linux can be enabled.

  When to use this mode: This mode has minimal infrastructure and integration
  requirements. It works on almost any network infrastructure as the only
  requirement is IP connectivity between hosts which is typically already
  given.

* **Native Routing:** Use of the regular routing table of the Linux host.
  The network is required to be capable to route the IP addresses of the
  application containers.

  When to use this mode: This mode is for advanced users and requires some
  awareness of the underlying networking infrastructure. This mode works well
  with:

  - Native IPv6 networks
  - In conjunction with cloud network routers
  - If you are already running routing daemons

Load balancing
--------------

Distributed load balancing for traffic between application containers and to
external services. The loadbalancing is implemented using BPF using efficient
hashtables allowing for almost unlimited scale and supports direct server
return (DSR) if the loadbalancing operation is not performed on the source
host.
*Note: load balancing requires connection tracking to be enabled. This is the
default.*

Monitoring and Troubleshooting
------------------------------

The ability to gain visibility and to troubleshoot issues is fundamental to the
operation of any distributed system. While we learned to love tools like
``tcpdump`` and ``ping`` and while they will always find a special place in our
hearts, we strive to provide better tooling for troubleshooting. This includes
tooling to provide:

- Event monitoring with metadata: When a packet is dropped, the tool doesn't
  just report the source and destination IP of the packet, the tool provides
  the full label information of both the sender and receiver among a lot of
  other information.

- Policy decision tracing: Why is a packet being dropped or a request rejected.
  The policy tracing framework allows to trace the policy decision process for
  both, running workloads and based on arbitrary label definitions.

- Metrics export via Prometheus: Key metrics are exported via Prometheus for
  integration with your existing dashboards.

Integrations
------------

* Network plugin integrations: CNI_, libnetwork_
* Container runtime events: containerd_
* Kubernetes: NetworkPolicy_, Labels_, Ingress_, Service_

.. _CNI: https://github.com/containernetworking/cni
.. _libnetwork: https://github.com/docker/libnetwork
.. _containerd: https://github.com/containerd/containerd
.. _service: https://kubernetes.io/docs/concepts/services-networking/service/
.. _Ingress: https://kubernetes.io/docs/concepts/services-networking/ingress/
.. _NetworkPolicy: https://kubernetes.io/docs/concepts/services-networking/network-policies/
.. _Labels: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/
.. _`Layer 7 Policy`: http://docs.cilium.io/en/stable/policy/#layer-7

.. end-functionality-overview

Getting Started
===============

* `Why Cilium?`_
* `Getting Started`_
* `Architecture and Concepts`_
* `Installing Cilium`_
* `Frequently Asked Questions`_
* Contributing_

What is eBPF and XDP?
=====================

Berkeley Packet Filter (BPF) is a Linux kernel bytecode interpreter originally
introduced to filter network packets, e.g. for tcpdump and socket filters. The
BPF instruction set and surrounding architecture has recently been
significantly reworked with additional data structures such as hash tables and
arrays for keeping state as well as additional actions to support packet
mangling, forwarding, encapsulation, etc. Furthermore, a compiler back end for
LLVM allows for programs to be written in C and compiled into BPF instructions.
An in-kernel verifier ensures that BPF programs are safe to run and a JIT
compiler converts the BPF bytecode to CPU architecture specific instructions
for native execution efficiency. BPF programs can be run at various hooking
points in the kernel such as for incoming packets, outgoing packets, system
calls, kprobes, uprobes, tracepoints, etc.

BPF continues to evolve and gain additional capabilities with each new Linux
release. Cilium leverages BPF to perform core data path filtering, mangling,
monitoring and redirection, and requires BPF capabilities that are in any Linux
kernel version 4.8.0 or newer (the latest current stable Linux kernel is
4.14.x).

Many Linux distributions including CoreOS, Debian, Docker's LinuxKit, Fedora,
openSUSE and Ubuntu already ship kernel versions >= 4.8.x. You can check your Linux
kernel version by running ``uname -a``. If you are not yet running a recent
enough kernel, check the Documentation of your Linux distribution on how to run
Linux kernel 4.9.x or later.

To read up on the necessary kernel versions to run the BPF runtime, see the
section Prerequisites_.

.. image:: https://cdn.rawgit.com/cilium/cilium/master/Documentation/images/bpf-overview.png
    :align: center

XDP is a further step in evolution and enables to run a specific flavor of BPF
programs from the network driver with direct access to the packet's DMA buffer.
This is, by definition, the earliest possible point in the software stack,
where programs can be attached to in order to allow for a programmable, high
performance packet processor in the Linux kernel networking data path.

Further information about BPF and XDP targeted for developers can be found in
the `BPF and XDP Reference Guide`_.


Further Reading
===============

.. further-reading-begin

Related Material
----------------

* `k8s-snowflake: Configs and scripts for bootstrapping an opinionated
  Kubernetes cluster anywhere using Cilium plugin
  <https://github.com/jessfraz/k8s-snowflake>`_
* `Using Cilium for NetworkPolicy: Kubernetes documentation on how to use Cilium
  to implement NetworkPolicy
  <https://kubernetes.io/docs/tasks/administer-cluster/cilium-network-policy/>`_

Presentations
-------------

* DockerCon, Austin TX, Apr 2017 - Cilium - Network and Application Security with BPF and XDP: `Slides
  <https://www.slideshare.net/ThomasGraf5/dockercon-2017-cilium-network-and-application-security-with-bpf-and-xdp>`__, `Video <https://www.youtube.com/watch?v=ilKlmTDdFgk>`__
* CNCF/KubeCon Meetup, Berlin, Mar 2017 - Linux Native, HTTP Aware Network Security:
  `Slides <https://www.slideshare.net/ThomasGraf5/linux-native-http-aware-network-security>`__, `Video <https://www.youtube.com/watch?v=Yf_INdTWIHI>`__
* Docker Distributed Systems Summit, Berlin, Oct 2016:
  `Slides <http://www.slideshare.net/Docker/cilium-bpf-xdp-for-containers-66969823>`__, `Video <https://www.youtube.com/watch?v=TnJF7ht3ZYc&list=PLkA60AVN3hh8oPas3cq2VA9xB7WazcIgs&index=7>`__
* NetDev1.2, Tokyo, Sep 2016 - cls_bpf/eBPF updates since netdev 1.1: `Slides <http://borkmann.ch/talks/2016_tcws.pdf>`__, `Video <https://youtu.be/gwzaKXWIelc?t=12m55s>`__
* NetDev1.2, Tokyo, Sep 2016 - Advanced programmability and recent updates with tc’s cls_bpf: `Slides <http://borkmann.ch/talks/2016_netdev2.pdf>`__, `Video <https://www.youtube.com/watch?v=GwT9hRiqdUo>`__
* ContainerCon NA, Toronto, Aug 2016 - Fast IPv6 container networking with BPF & XDP: `Slides <http://www.slideshare.net/ThomasGraf5/cilium-fast-ipv6-container-networking-with-bpf-and-xdp>`__

Podcasts
--------

* Software Gone Wild by Ivan Pepelnjak, Oct 2016: `Blog <http://blog.ipspace.net/2016/10/fast-linux-packet-forwarding-with.html>`__, `MP3 <http://media.blubrry.com/ipspace/stream.ipspace.net/nuggets/podcast/Show_64-Cilium_with_Thomas_Graf.mp3>`__
* OVS Orbit by Ben Pfaff, May 2016: `Blog <https://ovsorbit.benpfaff.org/#e4>`__, `MP3 <https://ovsorbit.benpfaff.org/episode-4.mp3>`__

Community blog posts
--------------------

* `Cilium for Network and Application Security with BPF and XDP, Apr 2017
  <https://blog.scottlowe.org/2017/04/18/black-belt-cilium/>`_
* `Cilium, BPF and XDP, Google Open Source Blog, Nov 2016
  <https://opensource.googleblog.com/2016/11/cilium-networking-and-security.html>`_

.. further-reading-end

Community
=========

Slack
-----

Join the Cilium `Slack channel <https://cilium.herokuapp.com/>`_ to chat with
Cilium developers and other Cilium users. This is a good place to learn about
Cilium, ask questions, and share your experiences.

Special Interest Groups (SIG)
-----------------------------

See `Special Interest groups
<https://docs.cilium.io/en/stable/community/#special-interest-groups>`_ for a list of all SIGs and their meeting times.

Weekly Developer meeting
------------------------
* The developer community is hanging out on zoom on a weekly basis to chat.
  Everybody is welcome.
* Weekly, Monday, 9:00 am PT, 12:00 pm (noon) ET, 6:00 pm CEST
* `Join zoom <https://zoom.us/j/328820525>`_

License
=======

The cilium user space components are licensed under the
`Apache License, Version 2.0 <LICENSE>`_. The BPF code templates are licensed
under the `General Public License, Version 2.0 <bpf/COPYING>`_.

.. _`Why Cilium?`: http://docs.cilium.io/en/stable/intro/#why-cilium
.. _`Getting Started`: http://docs.cilium.io/en/stable/gettingstarted/
.. _`Architecture and Concepts`: http://docs.cilium.io/en/stable/concepts/
.. _`Installing Cilium`: http://docs.cilium.io/en/stable/gettingstarted/#installation
.. _`Frequently Asked Questions`: https://github.com/cilium/cilium/issues?utf8=%E2%9C%93&q=is%3Aissue+label%3Akind%2Fquestion+
.. _Contributing: http://docs.cilium.io/en/stable/contributing/contributing/
.. _Prerequisites: http://docs.cilium.io/en/doc-1.0/install/system_requirements
.. _`BPF and XDP Reference Guide`: http://docs.cilium.io/en/stable/bpf/

.. |logo| image:: https://cdn.rawgit.com/cilium/cilium/master/Documentation/images/logo.svg
    :alt: Cilium Logo
    :width: 350px

.. |build-status| image:: https://jenkins.cilium.io/job/cilium-ginkgo/job/cilium/job/master/badge/icon
    :alt: Build Status
    :scale: 100%
    :target: https://jenkins.cilium.io/job/cilium-ginkgo/job/cilium/job/master/

.. |go-report| image:: https://goreportcard.com/badge/github.com/cilium/cilium
    :alt: Go Report Card
    :target: https://goreportcard.com/report/github.com/cilium/cilium

.. |go-doc| image:: https://godoc.org/github.com/cilium/cilium?status.svg
    :alt: GoDoc
    :target: https://godoc.org/github.com/cilium/cilium

.. |rtd| image:: https://readthedocs.org/projects/docs/badge/?version=latest
    :alt: Read the Docs
    :target: http://docs.cilium.io/

.. |apache| image:: https://img.shields.io/badge/license-Apache-blue.svg
    :alt: Apache licensed
    :target: https://github.com/cilium/cilium/blob/master/LICENSE

.. |gpl| image:: https://img.shields.io/badge/license-GPL-blue.svg
    :alt: GPL licensed
    :target: https://github.com/cilium/cilium/blob/master/bpf/COPYING

.. |slack| image:: https://cilium.herokuapp.com/badge.svg
    :alt: Join the Cilium slack channel
    :target: https://cilium.herokuapp.com/

.. |cii| image:: https://bestpractices.coreinfrastructure.org/projects/1269/badge
    :alt: CII Best Practices
    :target: https://bestpractices.coreinfrastructure.org/projects/1269

.. |pulls| image:: https://img.shields.io/docker/pulls/cilium/cilium.svg
    :alt: Cilium pulls
    :target: https://hub.docker.com/r/cilium/cilium/tags/
