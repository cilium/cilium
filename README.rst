.. raw:: html

   <picture>
      <source media="(prefers-color-scheme: light)" srcset="https://cdn.jsdelivr.net/gh/cilium/cilium@main/Documentation/images/logo.png" width="350" alt="Cilium Logo">
      <img src="https://cdn.jsdelivr.net/gh/cilium/cilium@main/Documentation/images/logo-dark.png" width="350" alt="Cilium Logo">
   </picture>

|cii| |go-report| |clomonitor| |artifacthub| |slack| |go-doc| |rtd| |apache| |bsd| |gpl| |fossa| |gateway-api| |codespaces|

Cilium is a networking, observability, and security solution with an eBPF-based
dataplane. It provides a simple flat Layer 3 network with the ability to span
multiple clusters in either a native routing or overlay mode. It is L7-protocol
aware and can enforce network policies on L3-L7 using an identity based security
model that is decoupled from network addressing.

Cilium implements distributed load balancing for traffic between pods and to
external services, and is able to fully replace kube-proxy, using efficient
hash tables in eBPF allowing for almost unlimited scale. It also supports
advanced functionality like integrated ingress and egress gateway, bandwidth
management and service mesh, and provides deep network and security visibility and monitoring.

A new Linux kernel technology called eBPF_ is at the foundation of Cilium. It
supports dynamic insertion of eBPF bytecode into the Linux kernel at various
integration points such as: network IO, application sockets, and tracepoints to
implement security, networking and visibility logic. eBPF is highly efficient
and flexible. To learn more about eBPF, visit `eBPF.io`_.

.. image:: Documentation/images/cilium-overview.png
   :alt: Overview of Cilium features for networking, observability, service mesh, and runtime security

.. raw:: html

   <a href="https://cncf.io/">
      <picture>
         <source media="(prefers-color-scheme: light)" srcset="https://github.com/cncf/artwork/blob/main/other/cncf-member/graduated/color/cncf-graduated-color.svg" />
         <img src="https://github.com/cncf/artwork/blob/main/other/cncf-member/graduated/white/cncf-graduated-white.svg" alt="CNCF Graduated Project" height="80" />
      </picture>
   </a>
   <a href="https://ebpf.io/">
      <picture>
         <source media="(prefers-color-scheme: light)" srcset=".github/assets/ebpf-horizontal.svg" />
         <img src=".github/assets/ebpf-horizontal-dark-back.svg" alt="eBPF Logo" height="80" align="right" />
      </picture>
   </a>

Stable Releases
===============

The Cilium community maintains minor stable releases for the last three minor
Cilium versions. Older Cilium stable versions from minor releases prior to that
are considered EOL.

For upgrades to new minor releases please consult the `Cilium Upgrade Guide`_.

Listed below are the actively maintained release branches along with their latest
patch release, corresponding image pull tags and their release notes:

+---------------------------------------------------------+------------+------------------------------------+----------------------------------------------------------------------------+
| `v1.19 <https://github.com/cilium/cilium/tree/v1.19>`__ | 2026-02-04 | ``quay.io/cilium/cilium:v1.19.0``  | `Release Notes <https://github.com/cilium/cilium/releases/tag/v1.19.0>`__  |
+---------------------------------------------------------+------------+------------------------------------+----------------------------------------------------------------------------+
| `v1.18 <https://github.com/cilium/cilium/tree/v1.18>`__ | 2026-01-13 | ``quay.io/cilium/cilium:v1.18.6``  | `Release Notes <https://github.com/cilium/cilium/releases/tag/v1.18.6>`__  |
+---------------------------------------------------------+------------+------------------------------------+----------------------------------------------------------------------------+
| `v1.17 <https://github.com/cilium/cilium/tree/v1.17>`__ | 2026-01-13 | ``quay.io/cilium/cilium:v1.17.12`` | `Release Notes <https://github.com/cilium/cilium/releases/tag/v1.17.12>`__ |
+---------------------------------------------------------+------------+------------------------------------+----------------------------------------------------------------------------+

Architectures
-------------

Cilium images are distributed for AMD64 and AArch64 architectures.

Software Bill of Materials
--------------------------

Starting with Cilium version 1.13.0, all images include a Software Bill of
Materials (SBOM). The SBOM is generated in `SPDX`_ format. More information
on this is available on `Cilium SBOM`_.

.. _`SPDX`: https://spdx.dev/
.. _`Cilium SBOM`: https://docs.cilium.io/en/latest/configuration/sbom/

Development
===========

For development and testing purpose, the Cilium community publishes snapshots,
early release candidates (RC) and CI container images build from the `main
branch <https://github.com/cilium/cilium/commits/main>`_. These images are
not for use in production.

For testing upgrades to new development releases please consult the latest
development build of the `Cilium Upgrade Guide`_.

Listed below are branches for testing along with their snapshots or RC releases,
corresponding image pull tags and their release notes where applicable:

+----------------------------------------------------------------------------+------------+-----------------------------------------+---------------------------------------------------------------------------------+
| `main <https://github.com/cilium/cilium/commits/main>`__                   | daily      | ``quay.io/cilium/cilium-ci:latest``     | N/A                                                                             |
+----------------------------------------------------------------------------+------------+-----------------------------------------+---------------------------------------------------------------------------------+

Functionality Overview
======================

.. begin-functionality-overview

CNI (Container Network Interface)
---------------------------------

`Cilium as a CNI plugin <https://cilium.io/use-cases/cni/>`_ provides a
fast, scalable, and secure networking layer for Kubernetes clusters. Built
on eBPF, it offers several deployment options:

* **Overlay networking:** encapsulation-based virtual network spanning all
  hosts with support for VXLAN and Geneve. It works on almost any network
  infrastructure as the only requirement is IP connectivity between hosts
  which is typically already given.

* **Native routing mode:** Use of the regular routing table of the Linux
  host. The network is required to be capable of routing the IP addresses
  of the application containers. It integrates with cloud routers, routing
  daemons, and IPv6-native infrastructure.

* **Flexible routing options:** Cilium can automate route learning and
  advertisement in common topologies such as using L2 neighbor discovery
  when nodes share a layer 2 domain, or BGP when routing across layer 3
  boundaries.

Each mode is designed for maximum interoperability with existing
infrastructure while minimizing operational burden.

Load Balancing
--------------

Cilium implements distributed load balancing for traffic between application
containers and to/from external services. The load balancing is implemented
in eBPF using efficient hashtables enabling high service density and low
latency at scale.

* **East-west load balancing** rewrites service connections at the socket
  level (``connect()``), avoiding the overhead of per-packet NAT and fully
  `replacing kube-proxy <https://cilium.io/use-cases/kube-proxy/>`_.

* **North-south load balancing** supports XDP for high-throughput scenarios
  and `layer 4 load balancing <https://cilium.io/use-cases/load-balancer/>`_
  including Direct Server Return (DSR), and Maglev consistent hashing.

Cluster Mesh
------------

Cilium `Cluster Mesh <https://cilium.io/use-cases/cluster-mesh/>`_ enables
secure, seamless connectivity across multiple Kubernetes clusters. For
operators running hybrid or multi-cloud environments, Cluster Mesh ensures
a consistent security and connectivity experience.

* **Global service discovery**: Workloads across clusters can discover and
  connect to services as if they were local. This enables fault tolerance,
  like automatically failing over to backends in another cluster, and
  exposes shared services like logging, auth, or databases across
  environments.

* **Unified identity model:** Security policies are enforced based on
  identity, not IP address, across all clusters.

Network Policy
--------------

Cilium `Network Policy <https://cilium.io/use-cases/network-policy/>`_
provides identity-aware enforcement across L3-L7. Typical container
firewalls secure workloads by filtering on source IP addresses and
destination ports. This concept requires the firewalls on all servers to be
manipulated whenever a container is started anywhere in the cluster.

In order to avoid this situation which limits scale, Cilium assigns a
security identity to groups of application containers which share identical
security policies. The identity is then associated with all network packets
emitted by the application containers, allowing to validate the identity at
the receiving node.

* **Identity-based security** removes reliance on brittle IP addresses.

* **L3/L4 policies** restrict traffic based on labels, protocols, and ports.

* **DNS-based policies:** Allow or deny traffic to FQDNs or wildcard domains
   (e.g., ``api.example.com``, ``*.trusted.com``). This is especially useful
   for securing egress traffic to third-party services.

* **L7-aware policies** allow filtering by HTTP method, URL path, gRPC call,
  and more:

  * Example: Allow only GET requests to ``/public/.*``.

  * Enforce the presence of headers like ``X-Token: [0-9]+``.

CIDR-based egress and ingress policies are also supported for controlling
access to external IPs, ideal for integrating with legacy systems or
regulatory boundaries.

Service Mesh
------------

With Cilium `Service Mesh <https://cilium.io/use-cases/service-mesh/>`_,
operators gain the benefits of fine-grained traffic control, encryption, observability,
access control, without the cost and complexity of traditional proxy-based
designs. Key features include:

* **Mutual authentication** with automatic identity-based encryption between
  workloads using IPSec or WireGuard.

* **L7-aware policy enforcement** for security and compliance.

* **Deep integration with the Kubernetes Gateway API :** Acts as a
  `Gateway API <https://cilium.io/use-cases/gateway-api/>`_ compliant data
  plane, allowing you to declaratively manage ingress, traffic splitting, and
  routing behavior using Kubernetes-native CRDs.

Observability and Troubleshooting
---------------------------------

Observability is built into Cilium from the ground up, providing rich
visibility that helps operators diagnose and understand system behavior
including:

* **Hubble**: A fully integrated observability platform that offers
  real-time service maps, flow visibility with identity and label metadata,
  and DNS-aware filtering and protocol-specific insights

* **Metrics and alerting**: Integration with Prometheus, Grafana, and other
  monitoring systems.

* **Drop reasons and audit trails**: Get actionable insights into why traffic
  was dropped, including policy or port violations and issues like failed
  DNS lookups.

.. end-functionality-overview

Getting Started
===============

* `Why Cilium?`_
* `Getting Started`_
* `Architecture and Concepts`_
* `Installing Cilium`_
* `Frequently Asked Questions`_
* Contributing_

Community
=========

Slack
-----

Join the Cilium `Slack channel <https://slack.cilium.io>`_ to chat with
Cilium developers and other Cilium users. This is a good place to learn about
Cilium, ask questions, and share your experiences.

Special Interest Groups (SIG)
-----------------------------

See `Special Interest groups
<https://github.com/cilium/community/blob/main/sigs.yaml>`_ for a list of all SIGs and their meeting times.

Developer meetings
------------------
The Cilium developer community hangs out on Zoom to chat. Everybody is welcome.

* Weekly, Wednesday,
  5:00 pm `Europe/Zurich time <https://time.is/Canton_of_Zurich>`__ (CET/CEST),
  usually equivalent to 8:00 am PT, or 11:00 am ET. `Meeting Notes and Zoom Info`_
* Third Wednesday of each month, 9:00 am `Japan time <https://time.is/Tokyo>`__ (JST). `APAC Meeting Notes and Zoom Info`_

eBPF & Cilium Office Hours livestream
-------------------------------------
We host a weekly community `YouTube livestream called eCHO <https://www.youtube.com/channel/UCJFUxkVQTBJh3LD1wYBWvuQ>`_ which (very loosely!) stands for eBPF & Cilium Office Hours. Join us live, catch up with past episodes, or head over to the `eCHO repo <https://github.com/isovalent/eCHO>`_ and let us know your ideas for topics we should cover.

Governance
----------
The Cilium project is governed by a group of `Maintainers and Committers <https://raw.githubusercontent.com/cilium/cilium/main/MAINTAINERS.md>`__.
How they are selected and govern is outlined in our `governance document <https://github.com/cilium/community/blob/main/GOVERNANCE.md>`__.

Adopters
--------
A list of adopters of the Cilium project who are deploying it in production, and of their use cases,
can be found in file `USERS.md <https://github.com/cilium/cilium/blob/main/USERS.md>`__.

License
=======

.. _apache-license: LICENSE
.. _bsd-license: bpf/LICENSE.BSD-2-Clause
.. _gpl-license: bpf/LICENSE.GPL-2.0

The Cilium user space components are licensed under the
`Apache License, Version 2.0 <apache-license_>`__.
The BPF code templates are dual-licensed under the
`General Public License, Version 2.0 (only) <gpl-license_>`__
and the `2-Clause BSD License <bsd-license_>`__
(you can use the terms of either license, at your option).

.. _`Cilium Upgrade Guide`: https://docs.cilium.io/en/stable/operations/upgrade/
.. _`Why Cilium?`: https://docs.cilium.io/en/stable/overview/intro
.. _`Getting Started`: https://docs.cilium.io/en/stable/#getting-started
.. _`Architecture and Concepts`: https://docs.cilium.io/en/stable/overview/component-overview/
.. _`Installing Cilium`: https://docs.cilium.io/en/stable/gettingstarted/k8s-install-default/
.. _`Frequently Asked Questions`: https://github.com/cilium/cilium/issues?utf8=%E2%9C%93&q=is%3Aissue+label%3Akind%2Fquestion+
.. _Contributing: https://docs.cilium.io/en/stable/contributing/development/
.. _Prerequisites: https://docs.cilium.io/en/stable/operations/system_requirements/
.. _`eBPF`: https://ebpf.io
.. _`eBPF.io`: https://ebpf.io
.. _`Meeting Notes and Zoom Info`: https://docs.google.com/document/d/1Y_4chDk4rznD6UgXPlPvn3Dc7l-ZutGajUv1eF0VDwQ/edit#
.. _`APAC Meeting Notes and Zoom Info`: https://docs.google.com/document/d/1egv4qLydr0geP-GjQexYKm4tz3_tHy-LCBjVQcXcT5M/edit#

.. |go-report| image:: https://goreportcard.com/badge/github.com/cilium/cilium
    :alt: Go Report Card
    :target: https://goreportcard.com/report/github.com/cilium/cilium

.. |go-doc| image:: https://godoc.org/github.com/cilium/cilium?status.svg
    :alt: GoDoc
    :target: https://godoc.org/github.com/cilium/cilium

.. |rtd| image:: https://readthedocs.org/projects/docs/badge/?version=latest
    :alt: Read the Docs
    :target: https://docs.cilium.io/

.. |apache| image:: https://img.shields.io/badge/license-Apache-blue.svg
    :alt: Apache licensed
    :target: apache-license_

.. |bsd| image:: https://img.shields.io/badge/license-BSD-blue.svg
    :alt: BSD licensed
    :target: bsd-license_

.. |gpl| image:: https://img.shields.io/badge/license-GPL-blue.svg
    :alt: GPL licensed
    :target: gpl-license_

.. |slack| image:: https://img.shields.io/badge/slack-cilium-brightgreen.svg?logo=slack
    :alt: Join the Cilium slack channel
    :target: https://slack.cilium.io

.. |cii| image:: https://bestpractices.coreinfrastructure.org/projects/1269/badge
    :alt: CII Best Practices
    :target: https://bestpractices.coreinfrastructure.org/projects/1269

.. |clomonitor| image:: https://img.shields.io/endpoint?url=https://clomonitor.io/api/projects/cncf/cilium/badge
    :alt: CLOMonitor
    :target: https://clomonitor.io/projects/cncf/cilium

.. |artifacthub| image:: https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/cilium
    :alt: Artifact Hub
    :target: https://artifacthub.io/packages/helm/cilium/cilium

.. |fossa| image:: https://app.fossa.com/api/projects/custom%2B162%2Fgit%40github.com%3Acilium%2Fcilium.git.svg?type=shield
    :alt: FOSSA Status
    :target: https://app.fossa.com/projects/custom%2B162%2Fgit%40github.com%3Acilium%2Fcilium.git?ref=badge_shield

.. |gateway-api| image:: https://img.shields.io/badge/Gateway%20API%20Conformance%20v1.4.0-Cilium-green
    :alt: Gateway API Status
    :target: https://github.com/kubernetes-sigs/gateway-api/tree/main/conformance/reports/v1.4.0/cilium

.. |codespaces| image:: https://img.shields.io/badge/Open_in_GitHub_Codespaces-gray?logo=github
    :alt: Github Codespaces
    :target: https://github.com/codespaces/new?hide_repo_select=true&ref=master&repo=48109239&machine=standardLinux32gb&location=WestEurope
