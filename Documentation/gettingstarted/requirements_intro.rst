Requirements
============

Make sure your Kubernetes environment is meeting the requirements:

* Kubernetes >= 1.9
* Linux kernel >= 4.9
* Kubernetes in CNI mode
* Running kube-dns/coredns (When using the etcd-operator installation method)
* Mounted BPF filesystem mounted on all worker nodes
* Enable PodCIDR allocation (``--allocate-node-cidrs``) in the ``kube-controller-manager`` (recommended)

Refer to the section :ref:`k8s_requirements` for detailed instruction on how to
prepare your Kubernetes environment.
