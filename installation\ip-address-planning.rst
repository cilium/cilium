.. _ip_address_planning:

IP Address Planning
===================

Before installing Cilium, it is critical to plan your IP address ranges carefully.
Using overlapping IP address ranges for Pods, Nodes, and Services is a common
source of connectivity problems that can be difficult to diagnose after installation.

.. warning::

   If your Pod CIDR, Node IP range, and Service CIDR overlap with each other
   or with your underlying network, you will experience connectivity failures
   that are difficult to debug. Plan these ranges **before** installing Cilium.

   See `GitHub issue #36406 <https://github.com/cilium/cilium/issues/36406>`_
   for an example of the problems caused by overlapping ranges.

Overview of IP Ranges in a Cilium Cluster
------------------------------------------

A typical Cilium deployment uses three distinct, **non-overlapping** IP address
ranges:

.. list-table:: IP Range Summary
   :widths: 20 40 20 20
   :header-rows: 1

   * - Range Type
     - Description
     - Cilium Config Key
     - Common Default
   * - **Pod CIDR**
     - IP addresses assigned to individual pods
     - ``ipam.operator.clusterPoolIPv4PodCIDRList``
     - ``10.0.0.0/8``
   * - **Node CIDR**
     - IP addresses assigned to cluster nodes (hosts)
     - Determined by your infrastructure / cloud provider
     - Varies
   * - **Service CIDR**
     - Virtual IPs for Kubernetes Services (ClusterIP)
     - ``--service-cluster-ip-range`` (kube-apiserver flag)
     - ``10.96.0.0/12``

.. important::

   These three ranges **must not overlap** with each other or with any external
   networks your cluster nodes need to reach (e.g., on-premises subnets,
   corporate VPNs, cloud VPC CIDRs).

Why Non-Overlapping Ranges Are Required
----------------------------------------

Cilium programs eBPF maps and routing rules based on these IP ranges to
determine:

- Which traffic is destined for a pod (Pod CIDR)
- Which traffic is destined for a node (Node CIDR)
- Which traffic should be intercepted as a Kubernetes Service (Service CIDR)

When ranges overlap, the kernel's routing table and Cilium's eBPF datapath
cannot unambiguously determine how to forward packets. This results in:

- Pods unable to reach each other across nodes
- Services returning connection refused or timing out
- Nodes unable to reach pods on other nodes
- Intermittent connectivity depending on the order routes are installed

Planning Your Ranges
--------------------

Use the following checklist when planning IP ranges:

.. code-block:: text

   Checklist:
   [ ] Pod CIDR does NOT overlap with Node IP range
   [ ] Pod CIDR does NOT overlap with Service CIDR
   [ ] Service CIDR does NOT overlap with Node IP range
   [ ] Pod CIDR does NOT overlap with on-premises / VPN / VPC subnets
   [ ] Service CIDR does NOT overlap with on-premises / VPN / VPC subnets
   [ ] Node IPs do NOT overlap with on-premises / VPN / VPC subnets (if applicable)

Example: Valid Non-Overlapping Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following is an example of a valid, non-overlapping IP address plan:

.. list-table::
   :widths: 30 30 40
   :header-rows: 1

   * - Range
     - CIDR
     - Notes
   * - Node IPs
     - ``192.168.0.0/24``
     - Assigned by your cloud/infra provider
   * - Pod CIDR
     - ``10.244.0.0/16``
     - Configured in Cilium Helm values
   * - Service CIDR
     - ``10.96.0.0/12``
     - Configured in kube-apiserver

These three ranges do not overlap and do not conflict with common RFC 1918
private address space used in corporate networks.

Example: **Invalid** Overlapping Configuration (Do NOT use)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: text

   Node IPs:     10.0.0.0/16    ← PROBLEM: overlaps with Pod CIDR
   Pod CIDR:     10.0.0.0/8     ← PROBLEM: overlaps with Node IPs and Service CIDR
   Service CIDR: 10.96.0.0/12   ← PROBLEM: falls within Pod CIDR (10.0.0.0/8)

This configuration will cause unpredictable connectivity failures.

IPv6 Considerations
--------------------

If you are using IPv6 or dual-stack, the same rules apply to IPv6 ranges:

- Pod CIDR (IPv6), Node IPs (IPv6), and Service CIDR (IPv6) must all be
  non-overlapping.

.. list-table:: Example Dual-Stack Configuration
   :widths: 30 30 40
   :header-rows: 1

   * - Range
     - CIDR
     - Notes
   * - Node IPs (IPv4)
     - ``192.168.1.0/24``
     - Assigned by infra
   * - Node IPs (IPv6)
     - ``fd00::/120``
     - Assigned by infra
   * - Pod CIDR (IPv4)
     - ``10.244.0.0/16``
     - Cilium config
   * - Pod CIDR (IPv6)
     - ``fd00:10:244::/48``
     - Cilium config
   * - Service CIDR (IPv4)
     - ``10.96.0.0/12``
     - kube-apiserver
   * - Service CIDR (IPv6)
     - ``fd00:10:96::/112``
     - kube-apiserver

How to Check for Overlapping Ranges
-------------------------------------

Before installing, verify your planned ranges do not overlap using standard
network tools.

**Using Python (ipcalc-style check):**

.. code-block:: python

   import ipaddress

   ranges = {
       "Node CIDR":    "192.168.0.0/24",
       "Pod CIDR":     "10.244.0.0/16",
       "Service CIDR": "10.96.0.0/12",
   }

   networks = {name: ipaddress.ip_network(cidr) for name, cidr in ranges.items()}

   all_ok = True
   names = list(networks.keys())
   for i in range(len(names)):
       for j in range(i + 1, len(names)):
           a, b = names[i], names[j]
           if networks[a].overlaps(networks[b]):
               print(f"ERROR: {a} ({ranges[a]}) overlaps with {b} ({ranges[b]})")
               all_ok = False

   if all_ok:
       print("All ranges are non-overlapping. Safe to proceed.")

**Using the ``ipcalc`` tool:**

.. code-block:: shell-session

   # Check if two CIDRs overlap (non-zero exit = overlap detected)
   $ ipcalc --check-network 10.244.0.0/16 10.96.0.0/12

**After installation** — verify Cilium's view of ranges:

.. code-block:: shell-session

   # Check configured Pod CIDR
   $ kubectl -n kube-system get configmap cilium-config -o yaml | grep cluster-pool

   # Check Service CIDR configured in kube-apiserver
   $ kubectl -n kube-system get pod kube-apiserver-$(hostname) -o yaml \
       | grep service-cluster-ip-range

   # Check node IPs
   $ kubectl get nodes -o wide

Configuring IP Ranges in Cilium
---------------------------------

Pod CIDR
~~~~~~~~~

The Pod CIDR is configured via Helm values:

.. code-block:: yaml

   # values.yaml
   ipam:
     operator:
       clusterPoolIPv4PodCIDRList:
         - "10.244.0.0/16"
       # For dual-stack:
       clusterPoolIPv6PodCIDRList:
         - "fd00:10:244::/48"

Or via the ``--helm-set`` flag:

.. code-block:: shell-session

   $ cilium install \
       --set ipam.operator.clusterPoolIPv4PodCIDRList="{10.244.0.0/16}"

Service CIDR
~~~~~~~~~~~~~

The Service CIDR is **not** configured in Cilium directly. It is configured
when the Kubernetes API server is started, typically via:

- ``kube-apiserver --service-cluster-ip-range=10.96.0.0/12``
- In kubeadm: ``clusterConfiguration.networking.serviceSubnet``
- In managed Kubernetes (EKS, GKE, AKS): configured at cluster creation time

.. note::

   Cilium reads the Service CIDR from the cluster automatically. However,
   it is your responsibility to ensure this range does not overlap with the
   Pod CIDR or Node IP range when the cluster is created.

Node IP Range
~~~~~~~~~~~~~~

Node IPs are assigned by your infrastructure or cloud provider. When creating
a cluster, ensure the subnet/VPC CIDR used for nodes does not overlap with the
Pod or Service CIDRs you plan to use.

Troubleshooting Overlapping Ranges
------------------------------------

If you suspect overlapping ranges are causing connectivity issues:

1. Collect current ranges:

   .. code-block:: shell-session

      # Pod CIDR
      $ kubectl get nodes -o jsonpath='{.items[*].spec.podCIDR}'

      # Service CIDR (from kube-apiserver manifest)
      $ cat /etc/kubernetes/manifests/kube-apiserver.yaml \
          | grep service-cluster-ip-range

      # Node IPs
      $ kubectl get nodes -o wide

2. Check for overlaps using the Python script above.

3. If overlaps are found, the cluster typically must be **recreated** with
   correct non-overlapping ranges. In-place changes to Pod or Service CIDRs
   are not supported in most Kubernetes distributions.

4. File a support request or open a GitHub issue if you need further assistance:
   https://github.com/cilium/cilium/issues

Additional Resources
---------------------

- :ref:`concepts_networking` — Cilium networking concepts
- :ref:`k8s_install_helm` — Helm installation guide
- :ref:`k8s_install_quick` — Quick installation guide
- `RFC 1918 Private Address Space <https://datatracker.ietf.org/doc/html/rfc1918>`_
- `Kubernetes Cluster Networking <https://kubernetes.io/docs/concepts/cluster-administration/networking/>`_
