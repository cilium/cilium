.. _intro:

######################
Introduction to Cilium
######################

What is Cilium?
===============

Cilium is open source software for transparently securing the network
connectivity between application services deployed using Linux container
management platforms like Docker and Kubernetes.

At the foundation of Cilium is a new Linux kernel technology called BPF, which
enables the dynamic insertion of powerful security visibility and control logic
within Linux itself.  Because BPF runs inside the Linux kernel, Cilium
security policies can be applied and updated without any changes to the
application code or container configuration.

Why Cilium?
===========

The development of modern datacenter applications has shifted to a
service-oriented architecture often referred to as *microservices*, wherein a
large application is split into small independent services that communicate
with each other via APIs using lightweight protocols like HTTP.  Microservices
applications tend to be highly dynamic, with individual containers getting
started or destroyed as the application scales out / in to adapt to load changes
and during rolling updates that are deployed as part of continuous delivery.

This shift toward highly dynamic microservices presents both a challenge and an
opportunity in terms of securing connectivity between microservices.
Traditional Linux network security approaches (e.g., iptables) filter on IP
address and TCP/UDP ports, but IP addresses frequently churn in dynamic
microservices environments. The highly volatile life cycle of containers causes
these approaches to struggle to scale side by side with the application as load
balancing tables and access control lists carrying hundreds of thousands of
rules that need to be updated with a continuously growing frequency. Protocol
ports (e.g. TCP port 80 for HTTP traffic) can no longer be used to
differentiate between application traffic for security purposes as the port is
utilized for a wide range of messages across services.

An additional challenge is the ability to provide accurate visibility as
traditional systems are using IP addresses as primary identification vehicle
which may have a drastically reduced lifetime of just a few seconds in
microservices architectures.

By leveraging Linux BPF, Cilium retains the ability to transparently insert
security visibility + enforcement, but does so in a way that is based on
service / pod / container identity (in contrast to IP address identification in
traditional systems) and can filter on application-layer (e.g. HTTP).  As a
result, Cilium not only makes it simple to apply security policies in a highly
dynamic environment by decoupling security from addressing, but can also
provide stronger security isolation by operating at the HTTP-layer in addition
to providing traditional Layer 3 and Layer 4 segmentation.

The use of BPF enables Cilium to achieve all of this in a way that is highly
scalable even for large-scale environments.

Documentation Roadmap
=====================

The remainder of this documentation is divided into the following sections:

* :ref:`gs_guide` :   Provides a simple tutorial for running a small Cilium
  setup on your laptop.  Intended as an easy way to get your hands dirty
  applying Cilium security policies between containers.

* :ref:`arch_guide` :   Describes the components of the Cilium architecture,
  and the different models for deploying Cilium.  Provides the high-level
  understanding required to run a full Cilium deployment and understand its
  behavior.

* :ref:`install_guide` :  Details instructions for installing, configuring, and
  troubleshooting Cilium in different deployment modes.

* :ref:`policy_guide` : Detailed walkthrough of the policy language structure
  and the supported formats.

* :ref:`admin_guide` : Describes how to troubleshoot Cilium in different
  deployment modes.

* :ref:`bpf_guide` : Provides a technical deep dive of BPF and XDP technology,
  primarily focused at developers.

* :ref:`api_ref` : Details the Cilium agent API for interacting with a local
  Cilium instance.

* :ref:`dev_guide` : Gives background to those looking to develop and contribute
  modifications to the Cilium code or documentation.
