.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _intro:

###############################
Introduction to Cilium & Hubble
###############################

What is Cilium?
===============

Cilium is open source software for transparently securing the network
connectivity between application services deployed using Linux container
management platforms like Docker and Kubernetes.

At the foundation of Cilium is a new Linux kernel technology called eBPF, which
enables the dynamic insertion of powerful security visibility and control logic
within Linux itself.  Because eBPF runs inside the Linux kernel, Cilium
security policies can be applied and updated without any changes to the
application code or container configuration.

.. admonition:: Video
  :class: attention

  If you'd like a video introduction to Cilium, check out this `explanation by Thomas Graf, Co-founder of Cilium <https://www.youtube.com/watch?v=80OYrzS1dCA&t=405s>`__.

What is Hubble?
===============

Hubble is a fully distributed networking and security observability platform.
It is built on top of Cilium and eBPF to enable deep visibility into the
communication and behavior of services as well as the networking infrastructure
in a completely transparent manner.

By building on top of Cilium, Hubble can leverage eBPF for visibility. By
relying on eBPF, all visibility is programmable and allows for a dynamic
approach that minimizes overhead while providing deep and detailed visibility
as required by users. Hubble has been created and specifically designed to make
best use of these new eBPF powers.

Hubble can answer questions such as:

Service dependencies & communication map
----------------------------------------

* What services are communicating with each other? How frequently? What does
  the service dependency graph look like?
* What HTTP calls are being made? What Kafka topics does a service consume from
  or produce to?

Network monitoring & alerting
-----------------------------

* Is any network communication failing? Why is communication failing? Is it
  DNS? Is it an application or network problem? Is the communication broken on
  layer 4 (TCP) or layer 7 (HTTP)?
* Which services have experienced a DNS resolution problem in the last 5
  minutes? Which services have experienced an interrupted TCP connection
  recently or have seen connections timing out? What is the rate of unanswered
  TCP SYN requests?

Application monitoring
----------------------

* What is the rate of 5xx or 4xx HTTP response codes for a particular service
  or across all clusters?
* What is the 95th and 99th percentile latency between HTTP requests and
  responses in my cluster? Which services are performing the worst? What is the
  latency between two services?

Security observability
----------------------

* Which services had connections blocked due to network policy? What services
  have been accessed from outside the cluster? Which services have resolved a
  particular DNS name?

.. admonition:: Video
  :class: attention

  If you'd like a video introduction to Hubble, check out `eCHO episode 2: Introduction to Hubble <https://www.youtube.com/watch?v=hD2iJUyIXQw&t=187s>`__.

Why Cilium & Hubble?
====================

eBPF is enabling visibility into and control over systems and applications at a
granularity and efficiency that was not possible before. It does so in a
completely transparent way, without requiring the application to change in any
way. eBPF is equally well-equipped to handle modern containerized workloads as
well as more traditional workloads such as virtual machines and standard Linux
processes.

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

By leveraging Linux eBPF, Cilium retains the ability to transparently insert
security visibility + enforcement, but does so in a way that is based on
service / pod / container identity (in contrast to IP address identification in
traditional systems) and can filter on application-layer (e.g. HTTP).  As a
result, Cilium not only makes it simple to apply security policies in a highly
dynamic environment by decoupling security from addressing, but can also
provide stronger security isolation by operating at the HTTP-layer in addition
to providing traditional Layer 3 and Layer 4 segmentation.

The use of eBPF enables Cilium to achieve all of this in a way that is highly
scalable even for large-scale environments.

Functionality Overview
======================

.. include:: ../../README.rst
     :start-after: begin-functionality-overview
     :end-before: end-functionality-overview
