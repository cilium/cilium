1. Install ``kubectl`` version >= v1.10.0 as described in the
   `Kubernetes Docs <https://kubernetes.io/docs/tasks/tools/install-kubectl/>`_

2. Install ``minikube`` >= v1.3.1 as per minikube documentation:
   `Install Minikube <https://kubernetes.io/docs/tasks/tools/install-minikube/>`_.

.. note::

   It is important to validate that you have minikube v1.3.1 installed. Older
   versions of minikube are shipping a kernel configuration that is *not*
   compatible with the TPROXY requirements of Cilium >= 1.6.0.

::

     minikube version
     minikube version: v1.3.1
     commit: ca60a424ce69a4d79f502650199ca2b52f29e631

3. Create a minikube cluster:

::

     minikube start --network-plugin=cni --memory=4096


::

     # Only available for minikube >= v1.12.1
     minikube start --cni=cilium --memory=4096

.. note::

   From minikube v1.12.1+, cilium networking plugin can be enabled directly with
   ``--network-plugin=cilium`` parameter in ``minikube start`` command. With this
   flag enabled, ``minikube`` will not only mount eBPF file system but also
   deploy ``quick-install.yaml`` automatically.

4. Mount the eBPF filesystem

::

     minikube ssh -- sudo mount bpffs -t bpf /sys/fs/bpf

.. note::

   In case of installing Cilium for a specific Kubernetes version, the
   ``--kubernetes-version vx.y.z`` parameter can be appended to the ``minikube
   start`` command for bootstrapping the local cluster. By default, minikube
   will install the most recent version of Kubernetes.
