How to test VXLAN Tunnel Endpoint (VTEP) integration 
====================================================

Requirements

1. One Virtual Machine with Linux distribution (Ubuntu 20.04 tested)
2. Please reference https://docs.cilium.io/en/stable/installation/kind/
   for Cilium deployment in kind dependencies
3. Install python3-scapy package

::

    KIND (K8S in Docker)

    +------------------------------------------------------------------------+
    |                                              Host(initns)              |
    |      +------------------------------+    +--------------------+        |
    |      |                              |    |                    |        |
    |      |  K8S control node            |    | K8S worker node    |        |
    |      |                              |    |                    |        |
    |      |  +--------+ vtepCIDR:        |    |                    |        |
    |      |  |busybox |    10.1.5.0/24   |    |                    |        |
    |      |  |        | vtepEndpoint:    |    |                    |        |
    |      |  +-eth0---+    172.18.0.1    |    |                    |        |
    |      |     |       vtepMAC:         |    |                    |        |
    |      |     |         x:x:x:x:x:x:x  |    |                    |        |
    |      |    lxcxxx@if                 |    |                    |        |
    |      |     |                        |    |                    |        |
    |      |     |                        |    |                    |        |
    |      |     +---cilium_vxlan--+      |    |                    |        |
    |      |                       |      |    |                    |        |
    |      |                       |      |    |  172.18.0.3        |        |
    |      +----------------------veth0---+    +------veth0---------+        |
    |         172.18.0.2            |                  |                     |
    |                             veth1               veth2                  |
    |                               |                  |                     |
    |  kubectl exec -it \           |                  |                     |
    |    <busybox> -- \             +-----------br0----+                     |
    |    ping 10.1.5.1                       172.18.0.1                      |
    |                                       ./vxlan-responder.py sniff       |
    |                                        on host bridge interface        |
    +------------------------------------------------------------------------+


VTEP integration test steps, You can also run install.sh for following steps

.. code-block:: bash 

   # Deploy kind cluster with one control plane node kind-cluster.yaml
   kind create cluster --config=kind-cluster.yaml
   # Deploy Cilium in KIND k8s control plane node VTEP support enabled
   helm install cilium cilium/cilium --version <cilium version> \
         --namespace kube-system \
         --set vtep.enabled="true" \
         --set vtep.endpoint="172.18.0.1" \
         --set vtep.cidr="10.1.5.0/24" \
         --set vtep.mask="255.255.255.0" \
         --set vtep.mac="00:50:56:A0:7D:D8"
   # docker pull the image and load in kind
   docker pull cilium/cilium:<version>
   kind load docker-image cilium/cilium:<version>
   # deploy busybox on kind control plaine node
   kubectl label node kind-control-plane  dedicated=master
   kubectl taint nodes --all node-role.kubernetes.io/master-
   kubectl taint nodes --all node-role.kubernetes.io/control-plane-
   kubectl apply -f busybox-master.yaml
   # Deploy vxlan-responder.py in systemd service
   cp vxlan-responder.service /etc/systemd/system/
   cp vxlan-responder.py /usr/local/bin/
   systemctl enable vxlan-responder.service
   systemctl start vxlan-responder.service
   # Ping from busybox to IP 10.1.5.1 within external VXLAN CIDR 10.1.5.0/24
   kubectl exec -it busybox-master  -- ping -c 10 10.1.5.1

.. note::

   When kind cluster is up, check VM host bridge interface name
   and change ``vxlan-responder.py`` argument ``--bridge`` in  ``vxlan-responder.service``
   to sniff on the bridge interface for example ``--bridge br-22b28ede79c2``
