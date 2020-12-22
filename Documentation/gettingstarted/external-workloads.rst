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

* External workloads must run a recent enough kernel for k8s service
  access from the external host to work, see :ref:`host-services` for
  details.

* External workloads must have IP connectivity with the nodes in your
  cluster. This requirement is typically met by establishing peering
  or VPN tunnels between the networks of the nodes of your cluster and
  your external workloads.

* All external workloads must have a unique IP address assigned
  them. Node IPs of such nodes and your clusters must not conflict with
  each other.

* The network between the external workloads and your cluster must
  allow the node-cluster communication. The exact ports are documented
  in the :ref:`firewall_requirements` section.

* This guide assumes your external workload manages domain name
  resolution service via systemd.

Prepare your cluster
####################

Enable support for external workloads
=====================================

.. include:: k8s-install-download-release.rst

Your cluster must be configured with support for external workloads
enabled. This can also be done by passing ``--set
externalWorkloads.enabled=true`` to ``helm install`` when installing
or updating Cilium:

.. parsed-literal::

    helm install cilium |CHART_RELEASE|         \\
      --namespace kube-system                   \\
      --set externalWorkloads.enabled=true

This will add a deployment for ``clustermesh-apiserver`` into your
cluster, as well as the related cluster resources, such as TLS
secrets.

.. _gs_external_workloads_tls_configuration:

TLS configuration
=================

By default TLS secrets are created by helm. This has the downside that
each time you run ``helm`` the TLS secrets will be re-created, forcing
each external workload to be reconfigured to be able to connect to
your cluster. There are two ways to get around this. You can
enable a cluster job to create TLS secrets instead. This way the CA
cert secrets are reused as long as they are not removed from your
cluster:

.. parsed-literal::

    helm install cilium |CHART_RELEASE|                     \\
      --namespace kube-system                               \\
      --set externalWorkloads.enabled=true                  \\
      --set clustermesh.apiserver.tls.auto.method=cronJob

Alternatively, you can use your own CA certs. You can either create the
``clustermesh-apiserver-ca-cert`` secret in your Cilium install
namespace (e.g., ``kube-system``) yourself, or pass the CA cert and
key to helm:

.. parsed-literal::

    helm install cilium |CHART_RELEASE|                     \\
      --namespace kube-system                               \\
      --set externalWorkloads.enabled=true                  \\
      --set clustermesh.apiserver.tls.auto.method=cronJob   \\
      --set clustermesh.apiserver.tls.ca.cert="<< base64 encoded CA certificate >>"   \\
      --set clustermesh.apiserver.tls.ca.key="<< base64 encoded CA key >>"

You can also allow the cronJob create the secrets using the first approach above and then save the
generated CA certs to be used with the second approach above:

.. code:: bash

    kubectl -n kube-system get secret clustermesh-apiserver-ca-cert -o yaml > clustermesh-apiserver-ca-cert.yaml
   
.. _gs_external_workloads_expose_clustermesh_apiserver:

Expose cluster to external workloads
====================================

``clustermesh-apiserver`` must be exposed to the external
workloads. By default this is done using a NodePort service on
port 32379. It is also possible to use the ``LoadBalancer`` service
type that, depending on your cloud provider, allows use of a static
IP, making configuring the external workloads easier.

.. tabs::
  .. group-tab:: NodePort

    NodePort is the default service type. Get the Node IP to use with:

    .. code:: bash

      kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type == "InternalIP")].address}{"\n"}'

  .. group-tab:: GCP

    Add the following values to the ``helm install cilium`` command:

    .. parsed-literal::

      --set clustermesh.apiserver.service.type=LoadBalancer
      --set clustermesh.apiserver.service.annotations."cloud\.google\.com/load-balancer-type"=Internal

    It is also possible to use an IP address from a pre-defined subnet. In this
    example, ``gke-vip-subnet`` is the name of the subnet that must
    have been created before ``helm install cilium`` (see `Google
    documentation for details
    <https://cloud.google.com/kubernetes-engine/docs/how-to/internal-load-balancing#lb_subnet>`_):
    
    .. parsed-literal::

      --set clustermesh.apiserver.service.annotations."networking\.gke\.io/internal-load-balancer-subnet"="gke-vip-subnet"
      --set clustermesh.apiserver.service.loadBalancerIP="xxx.xxx.xxx.xxx"

    ``xxx.xxx.xxx.xxx`` must be an IP from ``gke-vip-subnet``.

    If not using a pre-set IP, get the service IP with:

    .. code:: bash

      kubectl -n kube-system get svc clustermesh-apiserver -o jsonpath='{.status.loadBalancer.ingress[0].ip}{"\n"}'

  .. group-tab:: AWS

    .. parsed-literal::

      --set clustermesh.apiserver.service.type=LoadBalancer
      --set clustermesh.apiserver.service.annotations."service\.beta\.kubernetes\.io/aws-load-balancer-internal"="true"

    If not using a pre-set IP, get the service IP with:

    .. code:: bash

      kubectl -n kube-system get svc clustermesh-apiserver -o jsonpath='{.status.loadBalancer.ingress[0].ip}{"\n"}'

.. note::

   Make sure that you use the namespace in which cilium is
   running. Depending on which installation method you chose, this
   could be ``kube-system`` or ``cilium``.

Tell your cluster about external workloads
==========================================

To allow an external workload to join your cluster, the cluster must
be informed about each such workload. This is done by adding a
``CiliumExternalWorkload`` (CEW) resource for each external workload. CEW
resource specifies the name, namespace, and labels for the workload. For
now you must also allocate a small IP CIDR that must be unique to the
workload. For example, for a VM named ``runtime`` that is to join the
``default`` namespace, you could create a file ``runtime.yaml`` with
the following contents:

.. parsed-literal::

    apiVersion: cilium.io/v2
    kind: CiliumExternalWorkload
    metadata:
      name: runtime
      namespace: default
      labels:
        app: runtime
    spec:
      ipv4-alloc-cidr: 10.192.1.0/30

Apply this with:

.. code:: bash

    kubectl apply -f runtime.yaml

Extract the TLS keys for external workloads
===========================================

Cilium control plane performs TLS based authentication and encryption.
For this purpose, the TLS keys and certificates of
``clustermesh-apiserver`` need to be made available to external
workload that wish to join the cluster.

Extract the TLS certs from your k8s cluster using ``extract-external-workload-certs.sh``:

.. parsed-literal::

    curl -LO \ |SCM_WEB|\/contrib/k8s/extract-external-workload-certs.sh
    chmod +x extract-external-workload-certs.sh
    ./extract-external-workload-certs.sh

This saves the certs (``ca.crt``, ``tls.crt``, ``tls.key``) to the
current directory. These files need to be copied to your external
workload.

Install and configure Cilium on external workloads
##################################################

Log in to the external workload. First make sure the hostname matches
the name used in the CiliumExternalWorkload resource:

.. code:: bash

    hostname

By now you should be able to find the corresponding resource in your k8s
cluster (``<name>`` is the output from ``hostname`` above):

.. code:: bash

    kubectl get cew <name>

Next, copy the saved TLS certs from your kubectl command line to the
external workload. Then download the ``install-external-workload.sh`` script:

.. parsed-literal::

    curl -LO \ |SCM_WEB|\/contrib/k8s/install-external-workload.sh
    chmod +x install-external-workload.sh

Before you continue you need to stop the system service updating ``/etc/resolv.conf``:

.. code:: bash

    sudo cp /etc/resolv.conf /etc/resolv.conf.orig
    sudo systemctl disable systemd-resolved.service
    sudo service systemd-resolved stop

Then, assuming they are in the same directory:

.. tabs::
  .. group-tab:: NodePort

    .. parsed-literal::

      CLUSTER_ADDR=<node-ip> CILIUM_IMAGE=cilium/cilium:|IMAGE_TAG| ./install-external-workload.sh

    ``<node-ip>`` is the node IP you extracted from the k8s cluster above.

  .. group-tab:: LoadBalancer

    .. parsed-literal::

      CLUSTER_ADDR=<load-balancer-ip> CILIUM_IMAGE=cilium/cilium:|IMAGE_TAG| ./install-external-workload.sh

    ``<load-balancer-ip>`` is the load balancer IP you extracted from the k8s cluster above.

This command launches the Cilium agent in a docker container named
``cilium`` and copies the ``cilium`` CLI to your host. This needs
``sudo`` permissions, so you may be asked for a password.

This command waits until the node has been connected to the cluster
and the cluster services are available. Then it re-configures
``/etc/resolv.conf`` with the IP address of the ``kube-dns`` service.

.. note::

    If your node has multiple IP addresses you may need to tell Cilium
    agent which IP to use. To this end add ``HOST_IP=<ip-address>`` to
    the beginning of the command line above.

Verify basic connectivity
=========================

Next you can check the status of the Cilium agent in your external workload:

.. code:: bash

    cilium status

You should see something like:

.. parsed-literal::

    etcd: 1/1 connected, lease-ID=7c02748328e75f57, lock lease-ID=7c02748328e75f59, has-quorum=true: 192.168.36.11:32379 - 3.4.13 (Leader)
    ...

Check that cluster DNS works:

.. code:: bash

    nslookup clustermesh-apiserver.kube-system.svc.cluster.local

Inspecting status changes in the cluster
========================================

The following command in your cluster should show the external workload IPs and their Cilium security IDs:

.. code:: bash

    kubectl get cew

External workloads should also be visible as Cilium Endpoints:

.. code:: bash

    kubectl get cep

Apply Cilium Network Policy to enforce traffic from external workloads
######################################################################

From the external workload, ping the backend IP of ``clustermesh-apiserver`` service to verify connectivity:

.. code:: bash

    ping $(cilium service list get -o jsonpath='{[?(@.spec.flags.name=="clustermesh-apiserver")].spec.backend-addresses[0].ip}')

The ping should keep running also when the following CCNP is applied in your cluster:

.. parsed-literal::

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

.. parsed-literal::

      - fromEndpoints:
        - matchLabels:
            io.kubernetes.pod.name: runtime

Clean-up
########

You can remove the Cilium installation from your external workload by
first removing the Cilium docker image and Cilium CLI tool:

.. code:: bash

    docker rm -f cilium
    sudo rm /usr/bin/cilium

Then restore the domain name resolver configuration:

.. code:: bash

    sudo cp /etc/resolv.conf.orig /etc/resolv.conf
    sudo systemctl enable systemd-resolved.service
    sudo service systemd-resolved start


Conclusion
##########

With the above we have enabled policy-based communication between
external workloads and pods in your Kubernetes cluster. We have also
established service load-balancing from external workloads to your
cluster backends, and configured domain name lookup in the external
workload to be served by kube-dns of your cluster.

