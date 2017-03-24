Cilium Loadbalancer and Kubernetes
==================================

Cilium provides a loadbalancer by its own which can be used as a
replacement to kube-proxy.

This feature is still under development but this readme file will be
kept updated as possible.

Kubernetes loadbalancer (kube-proxy)
------------------------------------

Kubernetes has developed the Services abstration which provides the user
the ability to load balance network traffic to different pods. This
abstraction allows the pods reaching out to other pods by a single IP
address, a virtual IP address, without knowing all the pods that are
running that particular service.

Kube-proxy, installed on every node, watches for endpoints and services
addition and removal on the kube-master which allows it to to apply the
necessary enforcement on iptables. Thus, the received and sent traffic
from and to the pods are properly routed to the node and port serving
for that service. For more information you can check out the kubernetes
user guide for services
`here <http://kubernetes.io/docs/user-guide/services>`__

Cilium loadbalancer
-------------------

Cilium loadbalancer acts on the same principles as kube-proxy, it
watches for services addition or removal, but instead of doing the
enforcement on the iptables, it only updates some bpf maps entries on
each node. More info
`here <https://github.com/cilium/cilium/pull/109>`__

What do I need to change in kubernetes?
---------------------------------------

If you are using the kubernetes ``hack/local-up-cluster.sh`` script you
only need to apply the cilium kubernetes
`patch <../examples/kubernetes/kubernetes-v1.4.0.patch>`__ and use the
same environment variables that we use
`here <../examples/kubernetes/env-kube.sh>`__

Otherwise you need to disable the local kube-proxy and start the
kubernetes apiserver with the
``--service-cluster-ip-range="f00d:1::/112"``. You can choose your own
IPv6 prefix, but keep the mask to ``/112`` or bigger (>=112).

**Important note**: The `service-cluster-ip-range` is currently limited to a single address
family. This means that unless you are running Cilium with `--disable-ipv4`, the
`service-cluster-ip-range` must be set to an IPv4 range. This should get resolved once
Kubernetes starts supporting multiple IP addresses for a single pod.

Also, since kubernetes ``v1.3.5`` the user needs to install the
``loopback`` cni plugin from the `containernetworking
repo <https://github.com/containernetworking/cni/releases/tag/v0.3.0>`__.
If you are using the vagrant box with the Vagrantfile that we provide in
our repo you don't need to worry about it since we already did that for
you.
