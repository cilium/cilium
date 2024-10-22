.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _talos_linux_install:

**Prerequisites / Limitations**

  - Cilium's Talos Linux support is only tested with Talos versions ``>=1.5.0``.
  - As Talos `does not allow loading Kernel modules`_ by Kubernetes workloads, ``SYS_MODULE`` needs to be dropped from the Cilium default capability list.

.. _`does not allow loading Kernel modules`: https://www.talos.dev/latest/learn-more/process-capabilities/

.. note::

    The official Talos Linux documentation already covers many different Cilium deployment
    options inside their `Deploying Cilium CNI guide`_. Thus, this guide will only focus on
    the most recommended deployment option, from a Cilium perspective:

    - Deployment via official `Cilium Helm chart`_
    - Cilium `Kube-Proxy replacement<kubeproxy-free>` enabled
    - Reuse the ``cgroupv2`` mount that Talos already provides
    - `Kubernetes Host Scope<k8s_hostscope>` IPAM mode as Talos, by default, assigns ``PodCIDRs`` to ``v1.Node`` resources

.. _`Cilium Helm chart`: https://github.com/cilium/charts
.. _`Deploying Cilium CNI guide`: https://www.talos.dev/v1.6/kubernetes-guides/network/deploying-cilium/

**Configure Talos Linux**

Before installing Cilium, there are two `Talos Linux Kubernetes configurations`_ that
need to be adjusted:

#. Ensuring no other CNI is deployed via ``cluster.network.cni.name: none``
#. Disabling Kube-Proxy deployment via ``cluster.proxy.disabled: true``

Prepare a ``patch.yaml`` file:

.. code-block:: yaml

    cluster:
      network:
        cni:
          name: none
      proxy:
        disabled: true

Next, generate the configuration files for the Talos cluster by using the
``talosctl gen config`` command:

.. code-block:: shell-session

    talosctl gen config \
      my-cluster https://mycluster.local:6443 \
      --config-patch @patch.yaml

.. _`Talos Linux Kubernetes configurations`: https://www.talos.dev/latest/reference/configuration/v1alpha1/config/#Config.cluster

**Install Cilium**

To run Cilium with `Kube-Proxy replacement<kubeproxy-free>` enabled, it's required
to configure ``k8sServiceHost`` and ``k8sServicePort``, and point them to the
Kubernetes API. Luckily, Talos Linux provides KubePrism_ which allows it to access
the Kubernetes API in a convenient way, which solely relies on host networking without
using an external loadbalancer. This KubePrism_ endpoint can be accessed from every
Talos Linux node on ``localhost:7445``.

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
      --namespace $CILIUM_NAMESPACE \\
      --set ipam.mode=kubernetes \\
      --set=kubeProxyReplacement=true \\
      --set=securityContext.capabilities.ciliumAgent="{CHOWN,KILL,NET_ADMIN,NET_RAW,IPC_LOCK,SYS_ADMIN,SYS_RESOURCE,DAC_OVERRIDE,FOWNER,SETGID,SETUID}" \\
      --set=securityContext.capabilities.cleanCiliumState="{NET_ADMIN,SYS_ADMIN,SYS_RESOURCE}" \\
      --set=cgroup.autoMount.enabled=false \\
      --set=cgroup.hostRoot=/sys/fs/cgroup \\
      --set=k8sServiceHost=localhost \\
      --set=k8sServicePort=7445

.. _KubePrism: https://www.talos.dev/v1.6/kubernetes-guides/configuration/kubeprism/