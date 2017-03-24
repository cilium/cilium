Introduction
============

What is Cilium?
--------------

Cilium is open source software for transparently securing the network connectivity between application services deployed using Linux container management platforms like Docker and Kubernetes.

At the foundation of Cilium is a new Linux kernel technology called BPF, which enables the dynamic insertion of powerful security visibility and control logic within Linux itself, meaning that security can be applied and updated without any changes to the application code or container configuration.


Why Cilium?
-----------

The development of modern datacenter applications has shifted to a service-oriented architecture often referred to as “microservices”, wherein a large application is broken down into small independent units that communicate with each other via APIs using lightweight protocols like HTTP.    Microservices applications also tend to be highly dynamic, with individual containers coming and going as the application scales out/in based on load and rolling updates are deployed as part of continuous delivery.

This shift toward highly dynamic microservices presents both a challenge and an opportunity in terms of securing connectivity between microservices.  Traditional Linux network security approaches (e.g., iptables) filter on IP address and TCP/UDP port, and as a result struggle to properly lock-down connectivity between microservices and stay up to date with the frequent churn of container instances.

By leveraging Linux BPF, Cilium retains the ability to transparently insert security visibility + enforcement, but does so in a way that is based on service-identity (not address) and can filter on application-layer API messages (e.g., HTTP).  As a result, Cilium not only makes it simple to apply security policies in a highly dynamic environment, but can also provide stronger security isolation by operating at the HTTP-layer,  rather than just IP/port.    And the power of Linux BPF means that Cilium achieves all of this in a way that is highly scalable even for large environments.

Documentation Roadmap
---------------------

The remainder of this documentation is divided into three sections:

* **Getting Started Guide:**   A simple tutorial for running a small Cilium setup on your laptop.  Intended as an easy way to get your hands dirty applying Cilium security policies between containers.

* **Architecture Guide:**   Describes the components of the Cilium architecture, and the different models for deploying Cilium.  Focuses on the higher-level understanding required to run a full Cilium deployment and understand its behavior.

* **Installation + Configuration Guide:**  Detailed instructions for installing + configuring Cilium in different configurations.

Getting Help
------------

The best way to get help if you get stuck is to contact us on the `Cilium Slack channel <https://cilium.herokuapp.com>`_ .

If you’re confident that you’ve found a bug, please go ahead and create an issue on our `Github <https://github.com/cilium/cilium/issues>`_.

If you’re interested in contributing to the code or docs, ping us on `Slack <https://cilium.herokuapp.com>`_ or just dive in on `Github <https://github.com/cilium/cilium/>`_!


