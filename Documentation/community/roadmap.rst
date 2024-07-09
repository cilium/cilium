.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

Roadmap
=======

This page describes a high-level view of the main priorities for the project,
agreed as a result of collaboration between Cilium's committers_ and the
broader community. You'll also find here some pointers on how you can
:ref:`influence the roadmap<rm-influence>`. 

Major Feature Status
--------------------

+--------------------------------------------------+----------------------------------------------------------+
| eBPF Networking                                  | Stable (:ref:`Roadmap Details<rm-advanced-networking>`)  |
++-------------------------------------------------+----------------------------------------------------------+
|| :ref:`Kubernetes CNI<k8s_network_root>`         | Stable                                                   |
++-------------------------------------------------+----------------------------------------------------------+
|| `Load Balancing`_                               | Stable                                                   |
++-------------------------------------------------+----------------------------------------------------------+
|| :ref:`k8s_policy`                               | Stable                                                   |
++-------------------------------------------------+----------------------------------------------------------+
|| :ref:`Kube-proxy Replacement<kubeproxy-free>`   | Stable                                                   |
++-------------------------------------------------+----------------------------------------------------------+
|| :ref:`egress-gateway`                           | Stable                                                   |
++-------------------------------------------------+----------------------------------------------------------+
|| :ref:`gsg_encryption` (IPSec and WireGuard)     | Stable                                                   |
++-------------------------------------------------+----------------------------------------------------------+
|| :ref:`bandwidth-manager`                        | Stable                                                   |
++-------------------------------------------------+----------------------------------------------------------+
|| :ref:`local-redirect-policy`                    | Stable                                                   |
++-------------------------------------------------+----------------------------------------------------------+
| Cilium Mesh                                      | Stable (:ref:`Roadmap Details<rm-clustermesh>`)          |
++-------------------------------------------------+----------------------------------------------------------+
|| :ref:`Multi-Cluster (ClusterMesh)<clustermesh>` | Stable                                                   |
++-------------------------------------------------+----------------------------------------------------------+
|| :ref:`External Workloads<external_workloads>`   | Beta                                                     |
++-------------------------------------------------+----------------------------------------------------------+
| Hubble Observability                             | Stable (:ref:`Roadmap Details<rm-hubble-observability>`) |
++-------------------------------------------------+----------------------------------------------------------+
|| :ref:`Hubble CLI<hubble_cli>`                   | Stable                                                   |
++-------------------------------------------------+----------------------------------------------------------+
|| :ref:`hubble_ui`                                | Stable                                                   |
++-------------------------------------------------+----------------------------------------------------------+
|| :ref:`Prometheus metrics<metrics>`              | Stable                                                   |
++-------------------------------------------------+----------------------------------------------------------+
| Cilium Service Mesh                              | Stable (:ref:`Roadmap Details<rm-cilium-service-mesh>`)  |
++-------------------------------------------------+----------------------------------------------------------+
|| :ref:`gs_ingress`                               | Stable                                                   |
++-------------------------------------------------+----------------------------------------------------------+
|| :ref:`gs_gateway_api`                           | Beta                                                     |
++-------------------------------------------------+----------------------------------------------------------+
|| :ref:`gs_l7_traffic_management`                 | Beta                                                     |
++-------------------------------------------------+----------------------------------------------------------+
|| :ref:`gs_mutual_authentication`                 | Beta                                                     |
++-------------------------------------------------+----------------------------------------------------------+
|| :ref:`SPIFFE integration<identity_management>`  | Beta                                                     |
++-------------------------------------------------+----------------------------------------------------------+
| `Tetragon`_ Security                             | Stable (:ref:`Roadmap Details<rm-tetragon>`)             |
+--------------------------------------------------+----------------------------------------------------------+

"Stable" means that the feature is in use in production (though advanced
features may still be in beta or in development).

Release Cadence
~~~~~~~~~~~~~~~

We aim to make 2 to 3 `point releases`_ per year of Cilium and its core components
(Hubble, Cilium CLI, Tetragon, etc). We also make patch releases available as
necessary for security or urgent fixes. 

Focus Areas
-----------

For a finer-granularity view, and insight into detailed enhancements and fixes,
please refer to `issues on GitHub <GitHub issues_>`_. 

Welcoming New Contributors
~~~~~~~~~~~~~~~~~~~~~~~~~~

As a CNCF project we want to make it easier for new contributors to get involved
with Cilium. This includes both code and non-code contributions such as
documentation, blog posts, example configurations, presentations, training
courses, testing and more. Check the :ref:`dev_guide` documentation to understand how to get
involved with code contributions, and the `Get Involved`_ guide for guidance on
contributing blog posts, training and other resources. 

.. _rm-cilium-service-mesh:

Cilium Service Mesh 
~~~~~~~~~~~~~~~~~~~

As Cilium Service Mesh gets wider adoption, the next steps in
this area (in no particular order) include: 

* Graduating Gateway API and L7 Traffic management to stable
* Graduating next-gen mutual authentication and SPIFFE integration to stable
* Graduating Prometheus metrics and OpenTelemetry collector to stable
* Extended sample Grafana dashboards for L7 visibility
* SMI integration 
* Performance benchmarking

.. _rm-clustermesh:

Cilium Mesh 
~~~~~~~~~~~

Cilium Mesh incorporates the ability to connect any application workload to any
other, whether they are distributed within the same or different Kubernetes
clusters, or in external services or VMs in public or private clouds. This
builds on the core :ref:`ClusterMesh<clustermesh>` capability that is stable and
widely adopted. Future extensions include: 

* Cluster health checks
* :ref:`External Workloads<external_workloads>` graduating to stable

.. _rm-advanced-networking:

Advanced Networking Features
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There are several advanced networking features currently in beta, several of
these are already in production use with a set of adopters. We expect the
following features to graduate to stable:

* :ref:`BGP<bgp>`
* :ref:`CiliumEndpointSlice<gsg_ces>`
* :ref:`Multi-Pool IPAM<ipam_crd_multi_pool>`
* :ref:`Node-to-node WireGuard encryption<node-node-wg>`

.. _rm-hubble-observability:

Hubble Observability 
~~~~~~~~~~~~~~~~~~~~

Hubble provides visibility into network flows through the :ref:`Hubble CLI<hubble_cli>` (stable)
and :ref:`UI<hubble_ui>` (beta), with support for Prometheus and OpenTelemetry metrics. Areas of
focus currently include:

* Hubble UI additional features

CI Test Improvements
~~~~~~~~~~~~~~~~~~~~

We have a comprehensive set of tests running in CI, but several contributors are
currently working on `CI improvements`_ to make these more reliable and easier to
maintain. This is a good area to get involved if you are interested in learning
more about Cilium internals and development.

.. _rm-tetragon:

Tetragon Security
~~~~~~~~~~~~~~~~~

`Tetragon`_ is a sub-project within the Cilium family. It provides security observability and runtime enforcement through the JSON events and the Tetragon
CLI for things like process execution, file access, network observability, and
privileged execution.

Codebase modularization
~~~~~~~~~~~~~~~~~~~~~~~

As the project is growing in complexity it is becoming increasingly important
to be able to divide it into more manageable chunks. To achieve this, we're
working on modularizing the codebase and going from a tightly coupled design
(one large initialization and configuration) to a more loosely coupled design
of mostly self-contained modules. This will make Cilium internals easier to
comprehend, test and extend.

Contributions in this area are very welcome. To get started, take a look at the
:ref:`guide-to-the-hive` documentation and the issues referenced from
`modularization meta issue <modularization-issue_>`_. If you have any questions
or ideas please join us on the ``#sig-modularization`` channel on `Cilium
Slack`_.

.. _rm-influence:

Influencing the Roadmap
-----------------------

You are welcome to raise feature requests by creating them as `GitHub issues`_.
Please search the existing issues to avoid raising duplicates; if you find that
someone else is making the same or similar request we encourage the use of
GitHub emojis to express your support for an idea! 

The most active way to influence the capabilities in Cilium is to get involved
in development. We label issues with `good-first-issue`_ to help new potential
contributors find issues and feature requests that are relatively self-contained
and could be a good place to start. Please also read the :ref:`dev_guide` for
details of our pull request process and expectations, along with instructions
for setting up your development environment.

We encourage you to discuss your ideas for significant enhancements and feature
requests on the ``#development`` channel on `Cilium Slack`_, bring them to the
:ref:`weekly-community-meeting`, and/or create a `CFP design doc`_.

This roadmap does not give date commitments since the work is dependent on the
community. If you're looking for commitments to apply engineering resources to
work on particular features, one option is to discuss this with the companies
who offer `commercial distributions of Cilium <enterprise_>`_ and may be able to
help. 

Changes to this Roadmap Page
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This roadmap page will be updated through documentation pull requests in the
usual way, but the Cilium committers_ should be consulted beforehand about
anything other than trivial fixes. 


.. _committers: https://raw.githubusercontent.com/cilium/cilium/main/MAINTAINERS.md
.. _Load Balancing: https://cilium.io/use-cases/load-balancer/
.. _Tetragon: https://tetragon.cilium.io
.. _GitHub issues: https://github.com/cilium/cilium/issues
.. _point releases: https://cilium.io/blog/categories/release/
.. _Get Involved: https://cilium.io/get-involved
.. _CNCF Graduation: https://github.com/cncf/toc/pull/952
.. _CI improvements: https://github.com/cilium/cilium/issues?q=is%3Aopen+is%3Aissue+label%3Aarea%2FCI-improvement
.. _good-first-issue: https://github.com/cilium/cilium/labels/good-first-issue
.. _enterprise: https://cilium.io/enterprise
.. _CFP design doc: https://github.com/cilium/design-cfps/tree/main
.. _modularization-issue: https://github.com/cilium/cilium/issues/23425
