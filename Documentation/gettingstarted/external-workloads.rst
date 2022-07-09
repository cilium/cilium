.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _external_workloads:

.. _gs_external_workloads:

*************************************************
Setting up Support for External Workloads (beta)
*************************************************

This is a step-by-step guide on how to add external workloads (such as
VMs) in to your Kubernetes cluster and to enforce security policies to
restrict access.

.. include:: ../beta.rst

Prerequisites
#############

* Cilium must be configured to use Kubernetes for identity allocation
  (``identityAllocationMode`` set to ``crd``). This is the default
  for new installations.

* External workloads must run a recent enough kernel (>= 4.19.57) for k8s
  service access from the external host to work, see
  :ref:`kubeproxy-free` for details.

* External workloads must have Docker 20.10 or newer installed on the
  system (a version which supports ``--cgroupns`` CLI option).

* External workloads must have IP connectivity with the nodes in your
  cluster. This requirement is typically met by running your VMs in
  the same cloud provider virtual network (e.g., GCP VPC) as your k8s
  cluster, or establishing peering or VPN tunnels between the networks
  of the nodes of your cluster and your external workloads. Note that
  this precludes any VMs running behind NATs.

* All external workloads must have a unique IP address assigned
  them. Node IPs of such nodes and your clusters must not conflict with
  each other.

* The network between the external workloads and your cluster must
  allow the node-cluster communication. The exact ports are documented
  in the :ref:`firewall_requirements` section.

* This guide assumes your external workload manages domain name
  resolution service by a stand-alone ``/etc/resolv.conf``, or via
  systemd (e.g., Ubuntu).

* So far this functionality is only tested with the vxlan tunneling
  datapath mode (default for most installations).

Limitations
###########

* Transparent encryption of traffic to/from external workloads is currently not
  supported.

Prepare your cluster
####################

Enable support for external workloads
=====================================

Your cluster must be configured with support for external workloads
enabled. This can be done with the cilium CLI tool by issuing ``cilium
clustermesh enable`` after ``cilium install``:

.. code-block:: shell-session

    cilium install --config tunnel-protocol=vxlan
    cilium clustermesh enable

Config option ``tunnel-protocol=vxlan`` overrides any default that could
otherwise be auto-detected for your k8s cluster. This is currently a
requirement for external workload support.

.. note::

    If this fails indicating that ``--service-type`` needs to be
    given, add ``--service-type NodePort`` to the second command
    above, i.e. ``cilium clustermesh enable --service-type
    NodePort``. This will allow you to go through this guide, but be
    warned that NodePort service type makes your installation very
    fragile, it will become non-functional if the node through which
    the service is accessed is removed from the cluster or if it
    otherwise becomes unreachable.

This will add a deployment for ``clustermesh-apiserver`` into your
cluster, as well as the related cluster resources, such as TLS
secrets. ``clustermesh-apiserver`` service is exposed to the external
workloads. If your are on GKE, EKS, or AKS, this is done by default
using the internal ``LoadBalancer`` service type. Override the
auto-detection with an explicit ``--service-type LoadBalancer`` to use
an external LoadBalancer service type that uses an IP that is
accessible from outside of the cluster.

.. note::

    Use the ``--help`` option after any of the ``cilium clustermesh``
    commands to see a short synopsis of available command options.
    
Tell your cluster about external workloads
==========================================

To allow an external workload to join your cluster, the cluster must
be informed about each such workload. This is done by creating a
``CiliumExternalWorkload`` (CEW) resource for each external
workload. CEW resource specifies the name and identity labels
(including namespace) for the workload. The name must be the hostname
of the external workload, as returned by the ``hostname`` command run
in the external workload. In this example this is ``runtime``. For now
you must also allocate a small IP CIDR that must be unique to each
workload. For example, for a VM named ``runtime`` that is to join the
``default`` namespace (``vm`` is an alias for the
``external-workload`` subcommand):

.. code-block:: shell-session

    cilium clustermesh vm create runtime -n default --ipv4-alloc-cidr 10.192.1.0/30

``-n`` is an alias for ``--namespace`` and can be left out when the
value is ``default``. The namespace value will be set as an identity
label. The CEW resource itself is not namespaced.

To see the list of existing CEW resources, run:

.. code-block:: shell-session

    cilium clustermesh vm status

Note that CEW resources are not namespaced, so this command shows the
status of all CEW resources regardless of the namespace label that was
used when creating them. ``--namespace`` option for the status command
controls the namespace of Cilium deployment in your cluster and
usually needs to be left as the default ``kube-system``.

At this point the ``IP:`` in the status for ``runtime`` is ``N/A`` to
inform that the VM has not yet joined the cluster.

Install and configure Cilium on external workloads
##################################################

Run the external workload install command on your k8s cluster. This
extracts the TLS certificates and other access information from the
cluster installation and writes out an installation script to be used
in the external workloads to install Cilium and connect it to your k8s
cluster:

.. code-block:: shell-session

    cilium clustermesh vm install install-external-workload.sh

Note that the created script embeds the IP address for the
``clustermesh-apiserver`` service. If service type ``LoadBalancer``
can not be used, this IP address will be the one of the first node in
your k8s cluster (for ``NodePort`` service type). If this node is
removed from the cluster the above step for creating the installation
script must be repeated and all the external workloads
reinstalled. ``LoadBalancer`` is not affected by a node removal.

Log in to the external workload. First make sure the hostname matches
the name used in the CiliumExternalWorkload resource:

.. code-block:: shell-session

    hostname

Next, copy ``install-external-workload.sh`` created above to the
external workload. Then run the installation script:

.. code-block:: shell-session

    ./install-external-workload.sh

This command launches the Cilium agent in a docker container named
``cilium`` and copies the ``cilium`` node CLI to your host. This needs
``sudo`` permissions, so you may be asked for a password. Note that
this ``cilium`` command is not the same as the ``cilium`` CLI used to
manage Cilium installation on a k8s cluster.

This command waits until the node has been connected to the cluster
and the cluster services are available. Then it re-configures
``/etc/resolv.conf`` with the IP address of the ``kube-dns`` service.

.. note::

    If your external workload node has multiple IP addresses you may
    need to tell Cilium agent which IP to use. To this end add
    ``HOST_IP=<ip-address>`` to the beginning of the command line
    above.

Verify basic connectivity
=========================

Next you can check the status of the Cilium agent in your external workload:

.. code-block:: shell-session

    cilium status

You should see something like:

.. code-block:: shell-session

    KVStore:     Ok   etcd: 1/1 connected, lease-ID=7c02748328e75f57, lock lease-ID=7c02748328e75f59, has-quorum=true: https://clustermesh-apiserver.cilium.io:32379 - 3.4.13 (Leader)
    Kubernetes:  Disabled
    ...

Check that cluster DNS works:

.. code-block:: shell-session

    nslookup -norecurse clustermesh-apiserver.kube-system.svc.cluster.local

Inspecting status changes in the cluster
========================================

The following command in your cluster should show the external workload IPs and their Cilium security IDs:

.. code-block:: shell-session

    kubectl get cew

External workloads should also be visible as Cilium Endpoints:

.. code-block:: shell-session

    kubectl get cep

Apply Cilium Network Policy to enforce traffic from external workloads
######################################################################

From the external workload, ping the backend IP of ``clustermesh-apiserver`` service to verify connectivity:

.. code-block:: shell-session

    ping $(cilium service list get -o jsonpath='{[?(@.spec.flags.name=="clustermesh-apiserver")].spec.backend-addresses[0].ip}')

The ping should keep running also when the following CCNP is applied in your cluster:

.. code-block:: yaml

    apiVersion: cilium.io/v2
    kind: CiliumClusterwideNetworkPolicy
    metadata:
      name: test-ccnp
      namespace: kube-system
    spec:
      endpointSelector:
        matchLabels:
          k8s-app: clustermesh-apiserver
      ingress:
      - fromEndpoints:
        - matchLabels:
            io.kubernetes.pod.name: runtime
      - toPorts:
        - ports:
          - port: "2379"
            protocol: TCP

The ping should stop if you delete these lines from the policy (e.g., ``kubectl edit ccnp test-ccnp``):

.. code-block:: yaml

      - fromEndpoints:
        - matchLabels:
            io.kubernetes.pod.name: runtime

The ping should continue if you delete the policy:

.. code-block:: shell-session

     kubectl delete ccnp test-ccnp

Clean-up
########

You can remove the Cilium installation from your external workload by
running the installation script with the ``uninstall`` argument:

.. code-block:: shell-session

    ./install-external-workload.sh uninstall


Conclusion
##########

With the above we have enabled policy-based communication between
external workloads and pods in your Kubernetes cluster. We have also
established service load-balancing from external workloads to your
cluster backends, and configured domain name lookup in the external
workload to be served by kube-dns of your cluster.
