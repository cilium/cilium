.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _kubeproxy-free:

*****************************
Kubernetes without kube-proxy
*****************************

This guide explains how to provision a Kubernetes cluster without ``kube-proxy``,
and to use Cilium to replace it. For simplicity, we will use ``kubeadm`` to
bootstrap the cluster.

For installing ``kubeadm`` and for more provisioning options please refer to
`the official kubeadm documentation <https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm>`__.

.. note::

   Cilium's kube-proxy replacement depends on the :ref:`host-services` feature,
   therefore a v4.19.57, v5.1.16, v5.2.0 or more recent Linux kernel is required.

   Note that v5.0.y kernels do not have the fix required to run the kube-proxy
   replacement since at this point in time the v5.0.y stable kernel is end-of-life
   (EOL) and not maintained anymore on kernel.org.

   For individual distribution maintained kernels, the situation could differ.
   Therefore, please check with your distribution.

Quick-start
###########

Initialize the control-plane node via ``kubeadm init``, set a pod network
CIDR and skip the ``kube-proxy`` add-on:

.. tabs::

  .. group-tab:: K8s 1.16 and newer

    .. code:: bash

      kubeadm init --pod-network-cidr=10.217.0.0/16 --skip-phases=addon/kube-proxy

  .. group-tab:: K8s 1.15 and older

    In K8s 1.15 and older it is not yet possible to disable kube-proxy via ``--skip-phases=addon/kube-proxy``
    in kubeadm, therefore the below workaround for manually removing the ``kube-proxy`` DaemonSet and
    cleaning the corresponding iptables rules after kubeadm initialization is still necessary (`kubeadm#1733 <https://github.com/kubernetes/kubeadm/issues/1733>`__).

    Initialize control-plane as first step with a given pod network CIDR:

    .. code:: bash

      kubeadm init --pod-network-cidr=10.217.0.0/16

    Then delete the ``kube-proxy`` DaemonSet and remove its iptables rules as following:

    .. code:: bash

      kubectl -n kube-system delete ds kube-proxy
      iptables-restore <(iptables-save | grep -v KUBE)

Afterwards, join worker nodes by specifying the control-plane node IP address and
the token returned by ``kubeadm init``:

.. code:: bash

   kubeadm join <..>

.. include:: k8s-install-download-release.rst

Next, generate the required YAML files and deploy them. **Important:** Replace
``API_SERVER_IP`` and ``API_SERVER_PORT`` below with the concrete control-plane
node IP address and the kube-apiserver port number reported by ``kubeadm init``
(usually, it is port ``6443``).

Specifying this is necessary as ``kubeadm init`` is run explicitly without setting
up ``kube-proxy`` and as a consequence it neither exports ``KUBERNETES_SERVICE_HOST``
nor ``KUBERNETES_SERVICE_PORT`` to the environment. The Cilium agent therefore needs
to be made aware of this information through below configuration.

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set global.kubeProxyReplacement=strict \\
        --set global.k8sServiceHost=API_SERVER_IP \\
        --set global.k8sServicePort=API_SERVER_PORT

This will install Cilium as a CNI plugin with the BPF kube-proxy replacement to
implement handling of Kubernetes services of type ClusterIP, NodePort, ExternalIPs
and LoadBalancer.

Finally, as a last step, verify that Cilium has come up correctly on all nodes and
is ready to operate:

.. parsed-literal::

    kubectl -n kube-system get pods -l k8s-app=cilium
    NAME                READY     STATUS    RESTARTS   AGE
    cilium-crf7f        1/1       Running   0          10m
    cilium-mkcmb        1/1       Running   0          10m

Note, in above helm configuration the ``kubeProxyReplacement`` has been set to
``strict`` mode. This means that the Cilium agent will bail out in case the
underlying Linux kernel support is missing. Without explicitly specifying a
``kubeProxyReplacement`` option, helm uses ``kubeProxyReplacement`` with ``probe``
by default which would automatically disable a subset of the features to implement
the kube-proxy replacement instead of bailing out if the kernel support is
missing. This makes the assumption that Cilium's BPF kube-proxy replacement would
co-exist with kube-proxy on the system to optimize Kubernetes services. Given
we've used kubeadm to deploy a kube-proxy-free setup, the ``strict`` mode
has been used instead.

When running Cilium's BPF kube-proxy replacement, by default, a NodePort or
ExternalIPs service will be accessible through the IP address of a native device
which has the default route on the host. To change the device, set its name in
the ``global.nodePort.device`` helm option.

In addition, thanks to the :ref:`host-services` feature, the NodePort service can
be accessed from a host or a Pod within a cluster via it's public, cilium_host
device or loopback address, e.g. ``127.0.0.1:NODE_PORT``.

Cilium's BPF kube-proxy replacement is supported in direct routing as well as in
tunneling mode.

If ``kube-apiserver`` was configured to use a non-default NodePort port range,
then the same range must be passed to Cilium via the ``global.nodePort.range``
option.

Limitations
###########

    * NodePort and ExternalIPs services are currently exposed through the native device
      which has the default route on the host or a user specified device. In tunneling
      mode, they are additionally exposed through the tunnel interface (``cilium_vxlan``
      or ``cilium_geneve``). Exposing services through multiple native devices will be
      supported in upcoming Cilium versions. See `GH issue 9620
      <https://github.com/cilium/cilium/issues/9620>`_ for additional details.
    * Cilium's BPF kube-proxy replacement currently cannot be used with :ref:`encryption`.
    * Cilium's BPF kube-proxy replacement relies upon the :ref:`host-services` feature
      which uses BPF cgroup hooks to implement the service translation. The getpeername(2)
      hook is currently missing which will be addressed for newer kernels. It is known
      to currently not work with libceph deployments.
