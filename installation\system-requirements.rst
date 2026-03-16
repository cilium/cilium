.. _system_requirements:

System Requirements
===================

Before installing Cilium, make sure your system meets the requirements below.

.. contents:: Table of Contents
   :local:
   :depth: 2

.. _requirements_kernel:

Linux Kernel
------------

Cilium requires a Linux kernel of version **4.19.57** or later. Some features
require a newer kernel version. See :ref:`admin_kernel_version` for details.

.. _requirements_ip_addresses:

.. warning::

   **IP Address Ranges Must Not Overlap**

   One of the most common causes of Cilium connectivity failures is overlapping
   IP address ranges. Before installing Cilium, ensure that the following three
   IP ranges are **completely non-overlapping**:

   - **Pod CIDR** – IP addresses assigned to pods
   - **Node CIDR** – IP addresses of your cluster nodes
   - **Service CIDR** – Virtual IPs for Kubernetes Services (ClusterIP)

   These ranges must also not overlap with any external networks your nodes
   need to reach (e.g., corporate VPNs, on-premises subnets, cloud VPC CIDRs).

   **Example of a valid configuration:**

   .. code-block:: text

      Node IPs:     192.168.0.0/24   (assigned by your infra/cloud provider)
      Pod CIDR:     10.244.0.0/16    (configured in Cilium)
      Service CIDR: 10.96.0.0/12    (configured in kube-apiserver)

   See :ref:`ip_address_planning` for a full guide on planning IP ranges,
   including how to detect and avoid overlaps before installing.

IP Address Planning
-------------------

Carefully plan your IP address ranges before installation. Refer to the
dedicated :ref:`ip_address_planning` guide for:

- Why non-overlapping ranges are required
- How to check for overlaps
- Example valid and invalid configurations
- IPv6 / dual-stack planning

.. _requirements_kubernetes:

Kubernetes Version
------------------

Cilium requires Kubernetes **1.21** or later. For the full compatibility
matrix, see :ref:`version_matrix`.

.. _requirements_network:

Network
-------

Ensure the following network requirements are met:

- Nodes must be able to reach each other
- Nodes must be able to reach the Kubernetes API server
- If using direct routing mode, nodes must have L3 connectivity

.. _requirements_container_runtime:

Container Runtime
-----------------

Cilium supports the following container runtimes:

- containerd
- CRI-O
- Docker (via cri-dockerd)
