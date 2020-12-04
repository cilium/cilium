|logo|

|cii| |build-status| |pulls| |slack| |go-report| |go-doc| |rtd| |apache| |gpl|

Cilium is open source software for providing and transparently securing network
connectivity and loadbalancing between application workloads such as
application containers or processes. Cilium operates at Layer 3/4 to provide
traditional networking and security services as well as Layer 7 to protect and
secure use of modern application protocols such as HTTP, gRPC and Kafka. Cilium
is integrated into common orchestration frameworks such as Kubernetes and Mesos.

A new Linux kernel technology called eBPF_ is at the foundation of Cilium. It
supports dynamic insertion of eBPF bytecode into the Linux kernel at various
integration points such as: network IO, application sockets, and tracepoints to
implement security, networking and visibility logic. eBPF is highly efficient
and flexible. To learn more about eBPF, visit `eBPF.io`_.

.. image:: https://cdn.jsdelivr.net/gh/cilium/cilium@master/Documentation/images/cilium_overview.png
    :align: center

Stable Releases
===============

The Cilium community maintains minor stable releases for the last three major
Cilium versions. Older Cilium stable versions from major releases prior to that
are considered EOL.

For upgrades to new major releases please consult the `Cilium Upgrade Guide
<https://docs.cilium.io/en/stable/operations/upgrade/>`_.

Listed below are the actively maintained release branches along with their latest
minor release, corresponding image pull tags and their release notes:

+-------------------------------------------------------+------------+--------------------------------------+---------------------------------------------------------------------------+------------------------------------------------------------------------+
| `v1.9 <https://github.com/cilium/cilium/tree/v1.9>`__ | 2020-12-04 | ``docker.io/cilium/cilium:v1.9.1``   | `Release Notes <https://github.com/cilium/cilium/releases/tag/v1.9.1>`__  | `General Announcement <https://cilium.io/blog/2020/11/10/cilium-19>`__ |
+-------------------------------------------------------+------------+--------------------------------------+---------------------------------------------------------------------------+------------------------------------------------------------------------+
| `v1.8 <https://github.com/cilium/cilium/tree/v1.8>`__ | 2020-12-04 | ``docker.io/cilium/cilium:v1.8.6``   | `Release Notes <https://github.com/cilium/cilium/releases/tag/v1.8.6>`__  | `General Announcement <https://cilium.io/blog/2020/06/22/cilium-18>`__ |
+-------------------------------------------------------+------------+--------------------------------------+---------------------------------------------------------------------------+------------------------------------------------------------------------+
| `v1.7 <https://github.com/cilium/cilium/tree/v1.7>`__ | 2020-12-04 | ``docker.io/cilium/cilium:v1.7.12``  | `Release Notes <https://github.com/cilium/cilium/releases/tag/v1.7.12>`__ | `General Announcement <https://cilium.io/blog/2020/02/18/cilium-17>`__ |
+-------------------------------------------------------+------------+--------------------------------------+---------------------------------------------------------------------------+------------------------------------------------------------------------+

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

* **Overlay:** Encapsulation-based virtual network spanning all hosts.
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

Load Balancing
--------------

Cilium implements distributed load balancing for traffic between application
containers and to external services and is able to fully replace components
such as kube-proxy. The load balancing is implemented in eBPF using efficient
hashtables allowing for almost unlimited scale.

For north-south type load balancing, Cilium's eBPF implementation is optimized
for maximum performance, can be attached to XDP (eXpress Data Path), and supports
direct server return (DSR) as well as Maglev consistent hashing if the load
balancing operation is not performed on the source host.

For east-west type load balancing, Cilium performs efficient service-to-backend
translation right in the Linux kernel's socket layer (e.g. at TCP connect time)
such that per-packet NAT operations overhead can be avoided in lower layers.

Bandwidth Management
--------------------

Cilium implements bandwidth management through efficient EDT-based (Earliest Departure
Time) rate-limiting with eBPF for container traffic that is egressing a node. This
allows to significantly reduce transmission tail latencies for applications and to
avoid locking under multi-queue NICs compared to traditional approaches such as HTB
(Hierarchy Token Bucket) or TBF (Token Bucket Filter) as used in the bandwidth CNI
plugin, for example.

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

- Hubble_: An observability platform specifically written for Cilium. It
  provides service dependency maps, operational monitoring and alerting,
  and application and security visibility based on flow logs.

.. _Hubble: https://github.com/cilium/hubble/

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

.. image:: https://cdn.jsdelivr.net/gh/cilium/cilium@master/Documentation/images/bpf-overview.png
    :align: center

XDP is a further step in evolution and enables to run a specific flavor of BPF
programs from the network driver with direct access to the packet's DMA buffer.
This is, by definition, the earliest possible point in the software stack,
where programs can be attached to in order to allow for a programmable, high
performance packet processor in the Linux kernel networking data path.

Further information about BPF and XDP targeted for developers can be found in
the `BPF and XDP Reference Guide`_.

To know more about Cilium, it's extensions and use cases around Cilium and BPF
take a look at `Further Readings <FURTHER_READINGS.rst>`_ section.

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
* Weekly, Monday, 8:00 am PT, 11:00 am ET, 5:00 pm CEST
* `Join zoom <https://zoom.us/j/596609673>`_

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
.. _Contributing: http://docs.cilium.io/en/stable/contributing/development/
.. _Prerequisites: http://docs.cilium.io/en/stable/operations/system_requirements
.. _`BPF and XDP Reference Guide`: http://docs.cilium.io/en/stable/bpf/
.. _`eBPF`: https://ebpf.io
.. _`eBPF.io`: https://ebpf.io

.. |logo| image:: https://cdn.jsdelivr.net/gh/cilium/cilium@master/Documentation/images/logo.svg
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
