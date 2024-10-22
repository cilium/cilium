.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _pod_mac_address:

************************************
Use a Specific MAC Address for a Pod
************************************

Some applications bind software licenses to network interface MAC addresses.
Cilium provides the ability to specific MAC addresses for pods
at deploy time instead of letting the operating system allocate them.


Configuring the address
#######################

Cilium will configure the MAC address for the primary interface inside a
Pod if you specify the MAC address in the ``cni.cilium.io/mac-address``
annotation before deploying the Pod.
This MAC address is isolated to the container so it will
not collide with any other MAC addresses assigned to other Pods on the same
node. The MAC address must be specified **before** deploying the Pod.

Annotate the pod with ``cni.cilium.io/mac-address`` set to the desired MAC address.
For example:

.. code-block:: yaml

    apiVersion: v1
    kind: Pod
    metadata:
      annotations:
        cni.cilium.io/mac-address: e2:9c:30:38:52:61
      labels:
        app: busybox
      name: busybox
      namespace: default

Deploy the Pod. Cilium will configure the mac address to the first interface in the Pod automatically.
Check whether its mac address is the specified mac address.

.. code-block:: shell-session

    $ kubectl exec -it busybox -- ip addr
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue qlen 1000
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
           valid_lft forever preferred_lft forever
        inet6 ::1/128 scope host
           valid_lft forever preferred_lft forever
    7: eth0@if8: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue qlen 1000
        link/ether e2:9c:30:38:52:61 brd ff:ff:ff:ff:ff:ff
        inet 10.244.2.195/32 scope global eth0
           valid_lft forever preferred_lft forever
        inet6 fe80::e46d:f4ff:fe4d:ebca/64 scope link
           valid_lft forever preferred_lft forever
