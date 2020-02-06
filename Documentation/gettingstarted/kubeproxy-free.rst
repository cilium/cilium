.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _kubeproxy-free:

*****************************
Kubernetes without kube-proxy
*****************************

This guide explains how to provision a Kubernetes cluster without ``kube-proxy``,
and to use Cilium to fully replace it. For simplicity, we will use ``kubeadm`` to
bootstrap the cluster.

For installing ``kubeadm`` and for more provisioning options please refer to
`the official kubeadm documentation <https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm>`__.

.. note::

   Cilium's kube-proxy replacement depends on the :ref:`host-services` feature,
   therefore a v4.19.57, v5.1.16, v5.2.0 or more recent Linux kernel is required!
   We recommend a v5.3 or more recent Linux kernel as Cilium can perform additional
   optimizations in its kube-proxy replacement implementation.

   Note that v5.0.y kernels do not have the fix required to run the kube-proxy
   replacement since at this point in time the v5.0.y stable kernel is end-of-life
   (EOL) and not maintained anymore on kernel.org. For individual distribution
   maintained kernels, the situation could differ. Therefore, please check with
   your distribution.

Quick-Start
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
up kube-proxy and as a consequence while it exports ``KUBERNETES_SERVICE_HOST``
and ``KUBERNETES_SERVICE_PORT`` with a ClusterIP of the kube-apiserver service
to the environment, there is no kube-proxy in our setup provisioning that service.
The Cilium agent therefore needs to be made aware of this information through below
configuration.

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
underlying Linux kernel support is missing.

Without explicitly specifying a ``kubeProxyReplacement`` option, helm uses
``kubeProxyReplacement`` with ``probe`` by default which would automatically
disable a subset of the features to implement the kube-proxy replacement instead
of bailing out if the kernel support is missing. This makes the assumption that
Cilium's BPF kube-proxy replacement would co-exist with kube-proxy on the system
to optimize Kubernetes services. Given we've used kubeadm to explicitly deploy
a kube-proxy-free setup, the ``strict`` mode has been used instead to ensure
that we do not rely on a (non-existing) fallback.

Cilium's BPF kube-proxy replacement is supported in direct routing as well as in
tunneling mode.

Direct Server Return (DSR) and other NodePort Settings
######################################################

When running Cilium's BPF kube-proxy replacement, by default, a NodePort or
ExternalIPs service will be accessible through the IP address of a native device
which has the default route on the host. To change the device, set its name in
the ``global.nodePort.device`` helm option.

In addition, thanks to the :ref:`host-services` feature, the NodePort service can
be accessed by default from a host or a Pod within a cluster via it's public,
cilium_host device or loopback address, e.g. ``127.0.0.1:NODE_PORT``.

By default, Cilium's BPF NodePort implementation operates in SNAT mode. That is,
when node-external traffic arrives and the node determines that the backend for
the NodePort or ExternalIPs service is at a remote node, then the node is redirecting
the request to the remote backend on its behalf by performing SNAT. This does not
require any additional MTU changes at the cost that replies from the backend need
to make the extra hop back that node in order to perform the reverse SNAT translation
there before returning the packet directly to the external client.

This setting can be changed through the ``global.nodePort.mode`` helm option to
``dsr`` in order to let Cilium's BPF NodePort implementation operate in DSR mode.
In this mode, the backends reply directly to the external client without taking
the extra hop, meaning, backends reply by using the service IP/port as a source.
Another advantage is that while in the SNAT mode a client's source IP address is not
preserved, in the DSR mode it is. Given a specific backend can be used by multiple
services, the backends need to be made aware of the service IP/port which they need
to reply with. Therefore, Cilium encodes this information as an IPv4 option or IPv6
extension header at the cost of advertising a lower MTU. For TCP services, Cilium
only encodes the service IP/port for the SYN packet.

Above helm example configuration in a kube-proxy-free environment with DSR enabled
would look as follows:

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set global.kubeProxyReplacement=strict \\
        --set global.nodePort.mode=dsr \\
        --set global.k8sServiceHost=API_SERVER_IP \\
        --set global.k8sServicePort=API_SERVER_PORT

If ``kube-apiserver`` was configured to use a non-default NodePort port range,
then the same range must be passed to Cilium via the ``global.nodePort.range``
option.

kube-proxy Replacement Modes
############################

Cilium's BPF kube-proxy replacement can be configured in several modes, i.e. it can
replace kube-proxy entirely or it can co-exist with kube-proxy on the system if the
underlying Linux kernel requirements do not support a full kube-proxy replacement.

This section therefore elaborates on the various ``global.kubeProxyReplacement`` options:

- ``global.kubeProxyReplacement=strict``: This option expects a kube-proxy-free
  Kubernetes setup where Cilium is expected to fully replace all kube-proxy
  functionality. Once the Cilium agent is up and running, it takes care of handling
  Kubernetes services of type ClusterIP, NodePort, ExternalIPs and LoadBalancer.
  If the underlying kernel version requirements are not met (see :ref:`kubeproxy-free`
  note), then the Cilium agent will bail out on start-up with an error message.

- ``global.kubeProxyReplacement=probe``: This option is intended for a hybrid setup,
  that is, kube-proxy is running in the Kubernetes cluster where Cilium partially
  replaces and optimizes kube-proxy functionality. Once the Cilium agent is up and
  running, it probes the underlying kernel for the availability of needed BPF kernel
  features and, if not present, disables a subset of the functionality in BPF by
  relying on kube-proxy to complement the remaining Kubernetes service handling. The
  Cilium agent will emit an info message into its log in such case. For example, if
  the kernel does not support :ref:`host-services`, then the ClusterIP translation
  for the node's host-namespace is done through kube-proxy's iptables rules.

- ``global.kubeProxyReplacement=partial``: Similarly to ``probe``, this option is
  intended for a hybrid setup, that is, kube-proxy is running in the Kubernetes cluster
  where Cilium partially replaces and optimizes kube-proxy functionality. As opposed to
  ``probe`` which checks the underlying kernel for available BPF features and automatically
  disables components responsible for the BPF kube-proxy replacement when kernel support
  is missing, the ``partial`` option requires the user to manually specify which components
  for the BPF kube-proxy replacement should be used. Similarly to ``strict`` mode, the
  Cilium agent will bail out on start-up with an error message if the underlying kernel
  requirements are not met. For fine-grained configuration, ``global.hostServices.enabled``,
  ``global.nodePort.enabled`` and ``global.externalIPs.enabled`` can be set to ``true``.
  By default all three options are set to ``false``. A few example configurations for the
  ``partial`` option are provided below.

  The following helm setup below would be equivalent to ``global.kubeProxyReplacement=strict``
  in a kube-proxy-free environment:

  .. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set global.kubeProxyReplacement=partial \\
        --set global.hostServices.enabled=true \\
        --set global.nodePort.enabled=true \\
        --set global.externalIPs.enabled=true \\
        --set global.k8sServiceHost=API_SERVER_IP \\
        --set global.k8sServicePort=API_SERVER_PORT

  The following helm setup below would be equivalent to Cilium service handling in v1.5 in a
  kube-proxy environment, that is, serving ClusterIP for pods:

  .. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set global.kubeProxyReplacement=partial

  The following helm setup below would optimize Cilium's ClusterIP handling for TCP in a
  kube-proxy environment (``global.hostServices.protocols`` default is ``tcp,udp``):

  .. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set global.kubeProxyReplacement=partial \\
        --set global.hostServices.enabled=true \\
        --set global.hostServices.protocols=tcp

  The following helm setup below would optimize Cilium's NodePort and ExternalIPs handling
  for external traffic ingressing into the Cilium managed node in a kube-proxy environment:

  .. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --set global.kubeProxyReplacement=partial \\
        --set global.nodePort.enabled=true \\
        --set global.externalIPs.enabled=true

- ``global.kubeProxyReplacement=disabled``: This option disables any Kubernetes service
  handling by fully relying on kube-proxy instead.

In Cilium's helm chart, the default mode is ``global.kubeProxyReplacement=probe`` for
new deployments.

For existing Cilium deployments in version v1.6 or prior, please consult the :ref:`1.7_upgrade_notes`.

The current Cilium kube-proxy replacement mode can also be introspected through the
``cilium status`` CLI command. See the ``KubeProxyReplacement`` section below:

.. parsed-literal::

    kubectl exec -it -n kube-system cilium-xxxx -- cilium status
    KVStore:                Ok   Disabled
    Kubernetes:             Ok   1.17 (v1.17.2) [linux/amd64]
    Kubernetes APIs:        ["CustomResourceDefinition", "cilium/v2::CiliumClusterwideNetworkPolicy", "cilium/v2::CiliumEndpoint", "cilium/v2::CiliumNetworkPolicy", "cilium/v2::CiliumNode", "core/v1::Endpoint", "core/v1::Namespace", "core/v1::Pods", "core/v1::Service", "networking.k8s.io/v1::NetworkPolicy"]
    KubeProxyReplacement:   Strict   [NodePort, ExternalIPs, HostReachableServicesTCP, HostReachableServicesUDP]
    Cilium:                 Ok   OK
    NodeMonitor:            Disabled
    Cilium health daemon:   Ok
    IPAM:                   IPv4: 4/65535 allocated from 10.1.0.0/16,
    Controller Status:      17/17 healthy
    Proxy Status:           OK, ip 10.1.28.236, port-range 10000-20000
    Cluster health:       0/1 reachable   (2020-02-05T14:02:54+01:00)
      Name                IP              Reachable   Endpoints reachable
        ceuse (localhost)   10.5.57.1       true        false

Limitations
###########

    * NodePort and ExternalIPs services are currently exposed through the native device
      which has the default route on the host or a user specified device. In tunneling
      mode, they are additionally exposed through the tunnel interface (``cilium_vxlan``
      or ``cilium_geneve``). Exposing services through multiple native devices will be
      supported in upcoming Cilium versions. See `GH issue 9620
      <https://github.com/cilium/cilium/issues/9620>`__ for additional details.
    * Cilium's BPF kube-proxy replacement currently cannot be used with :ref:`encryption`.
    * Cilium's BPF kube-proxy replacement relies upon the :ref:`host-services` feature
      which uses BPF cgroup hooks to implement the service translation. The getpeername(2)
      hook is currently missing which will be addressed for newer kernels. It is known
      to currently not work with libceph deployments.
    * Cilium in general currently does not support IP de-/fragmentation. This also includes
      the BPF kube-proxy replacement. Meaning, while the first packet with L4 header will
      reach the backend, all subsequent packets will not due to service lookup failing.
      This will be addressed via `GH issue 10076 <https://github.com/cilium/cilium/issues/10076>`__.
    * Kubernetes Service sessionAffinity is currently not implemented.
      This will be addressed via `GH issue 9076 <https://github.com/cilium/cilium/issues/9076>`__.
