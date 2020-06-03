Install Cilium
==============

Install Cilium as `DaemonSet
<https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/>`_ into
your new Kubernetes cluster. The DaemonSet will automatically install itself as
Kubernetes CNI plugin.

.. tabs::

   .. group-tab:: With ``quick-install.yaml``

      .. note::

        ``quick-install.yaml`` is a pre-rendered Cilium chart template. The
        template is generated using `helm template <https://helm.sh/docs/helm/helm_template/>`_
        command with default configuration parameters without any customization.

        In case of installing Cilium with CRIO, please see :ref:`crio-instructions` instructions.

      .. parsed-literal::

         kubectl create -f |SCM_WEB|/install/kubernetes/quick-install.yaml

   .. group-tab:: With ``experimental-install.yaml``

      .. warning::

        ``experimental-install.yaml`` is a pre-rendered Cilium chart template with
        experimental features enabled. These features may include unreleased or beta
        features that are not considered production-ready. While it provides a convenient
        way to try out experimental features, It should only be used in testing environments.

      .. parsed-literal::

         kubectl create -f |SCM_WEB|/install/kubernetes/experimental-install.yaml
