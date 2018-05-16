Getting Started with Cilium on minikube
=======================================

Deploying Cilium on a minikube cluster is simple. The provided
``cilium-ds.yaml`` file contains a DaemonSet spec which can be used to take
care of all deployments steps.

Boot a minikube cluster with the Container Network Interface (CNI) network
plugin, the ``localkube`` bootstrapper, and CustomResourceValidation.

The ``localkube`` bootstrapper provides ``etcd`` >= ``3.1.0``, a cilium
dependency. ``CustomResourceValidation`` will allow Cilium to install the Cilium
Network Policy validator into kubernetes
(`more info <https://kubernetes.io/docs/tasks/access-kubernetes-api/extend-api-custom-resource-definitions/#validation>`_)

::

	$ minikube start --network-plugin=cni --bootstrapper=localkube --feature-gates=CustomResourceValidation=true
        [...]
	$ kubectl create -f cilium-ds.yaml

Please see full `Getting Started on Kubernetes`_  guide for additional details
on how to get started on Kubernetes including details on how to import
Kubernetes NetworkPolicies.

.. _Getting Started on Kubernetes: http://cilium.readthedocs.io/en/doc-1.0/kubernetes/
