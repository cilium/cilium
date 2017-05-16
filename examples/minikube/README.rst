Getting Started with Cilium on minikube
=======================================

Deploying Cilium on a minikube cluster is simple. The provided
``cilium-ds.yaml`` file contains a DaemonSet spec which can be used to take
care of all deployments steps.

Deploy a minikube cluster using the ISO as described below and instruct
Kubernetes to use the CNI plugin infrastructure:

::

	$ minikube start --network-plugin=cni --iso-url https://raw.githubusercontent.com/cilium/minikube-iso/master/minikube.iso


.. note:: All the required changes have already been merged into the minikube
          repository and the next release of the minikube ISO image will no
          longer require to provide the ``--iso-url``` parameter.

Deploy Cilium:

::

	$ kubectl create -f cilium-ds.yaml
