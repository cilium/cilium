Requirements
============

Make sure your Kubernetes environment is meeting the requirements:

* Kubernetes >= 1.16
* Linux kernel >= 4.19.57 or equivalent
* Kubernetes in CNI mode
* Mounted eBPF filesystem mounted on all worker nodes
* Recommended: Enable PodCIDR allocation (``--allocate-node-cidrs``) in the ``kube-controller-manager`` (recommended)

Refer to the section :ref:`k8s_requirements` for detailed instruction on how to
prepare your Kubernetes environment.
