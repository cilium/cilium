If you haven't read the :ref:`intro` yet, we'd encourage you to do that first.

The best way to get help if you get stuck is to ask a question on the `Cilium
Slack channel <https://cilium.herokuapp.com>`_.  With Cilium contributors
across the globe, there is almost always someone available to help.

Setup Cilium
============

If you have not set up Cilium yet, pick any installation method as described in
section :ref:`gs_install` to set up Cilium for your Kubernetes environment. If
in doubt, pick :ref:`gs_minikube` as the simplest way to set up a Kubernetes
cluster with Cilium:

.. parsed-literal::

    minikube start --network-plugin=cni --memory=4096
    minikube ssh -- sudo mount bpffs -t bpf /sys/fs/bpf
    kubectl create -f \ |SCM_WEB|\/install/kubernetes/quick-install.yaml

