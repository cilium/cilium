Getting Started with Cilium on minikube
=======================================

Deploying Cilium on a minikube cluster is simple. The provided
``cilium-ds.yaml`` file contains a DaemonSet spec which can be used to take
care of all deployments steps.

Deploy a minikube cluster using the ISO as described below and instruct
Kubernetes to use the CNI plugin infrastructure:

::

	$ minikube start --network-plugin=cni --iso-url https://raw.githubusercontent.com/cilium/minikube-iso/master/minikube.iso
        [...]
	$ kubectl create -f cilium-ds.yaml

Please see full `Getting Started on Kubernetes`_  guide for additional details
on how to get started on Kubernetes including details on how to import
Kubernetes NetworkPolicies.

.. _Getting Started on Kubernetes: http://cilium.readthedocs.io/en/stable/gettingstarted/#getting-started-using-kubernetes
