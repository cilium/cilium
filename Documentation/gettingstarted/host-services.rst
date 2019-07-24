.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _host-services:

******************************
Host-Reachable Services (beta)
******************************

This guide explains how to configure Cilium to enable services to be
reached from the host namespace.

.. note::

    This is a beta feature. Please provide feedback and file a GitHub issue if
    you experience any problems.

.. note::

   Host-reachable services for TCP and UDP requires a v4.19.57, v5.1.16, v5.2.0
   or more recent Linux kernel. For only enabling TCP-based host-reachable
   services a v4.17.0 or newer kernel is required.

First step is to download the Cilium Kubernetes descriptor:

.. tabs::

  .. group-tab:: K8s 1.15

    .. parsed-literal::

      curl -LO \ |SCM_WEB|\/examples/kubernetes/1.15/cilium.yaml

  .. group-tab:: K8s 1.14

    .. parsed-literal::

      curl -LO \ |SCM_WEB|\/examples/kubernetes/1.14/cilium.yaml

  .. group-tab:: K8s 1.13

    .. parsed-literal::

      curl -LO \ |SCM_WEB|\/examples/kubernetes/1.13/cilium.yaml

  .. group-tab:: K8s 1.12

    .. parsed-literal::

      curl -LO \ |SCM_WEB|\/examples/kubernetes/1.12/cilium.yaml

  .. group-tab:: K8s 1.11

    .. parsed-literal::

      curl -LO \ |SCM_WEB|\/examples/kubernetes/1.11/cilium.yaml

  .. group-tab:: K8s 1.10

    .. parsed-literal::

      curl -LO \ |SCM_WEB|\/examples/kubernetes/1.10/cilium.yaml

Edit the ``cilium-config`` ConfigMap in that file with the etcd server
that is running in your cluster and set the option ``enable-host-reachable-services``
to ``"true"``. This is all which is required to expose services to the
host namespace. A Linux kernel of v4.19.57, v5.1.16, v5.2.0 or more
recent is needed for exposing both TCP and UDP-based services.

The basic minimum required for host-reachable services is a Linux kernel
v4.17.0. This allows to only enable TCP-based services to the host, but
not UDP-based ones due to lack of kernel features. This can be enabled
through additionally specifying ``host-reachable-services-protos`` to
``"tcp"``. This setting otherwise defaults to ``"tcp,udp"``.

Host-reachable services act transparent to Cilium's lower layer datapath
in that upon connect system call (TCP, connected UDP) or sendmsg as well
as recvmsg (UDP) the destination IP is checked for an existing service IP
and one of the service backends is selected as a target, meaning, while
the application is assuming its connection to the service address, the
corresponding kernel's socket is actually connected to the backend address
and therefore no additional lower layer NAT is required.

Example ConfigMap extract for TCP and UDP host reachable services:

::

  enable-host-reachable-services: "true"

Example ConfigMap extract for TCP-only host reachable services (only
needed for old Linux kernels):

::

  enable-host-reachable-services: "true"
  host-reachable-services-protos: "tcp"

After that, apply the DaemonSet file to deploy Cilium and verify that it
has come up correctly:

.. parsed-literal::

    kubectl create -f ./cilium.yaml
    kubectl -n kube-system get pods -l k8s-app=cilium
    NAME                READY     STATUS    RESTARTS   AGE
    cilium-crf7f        1/1       Running   0          10m

For further information on Cilium's host reachable services setting,
see :ref:`arch_guide`.
