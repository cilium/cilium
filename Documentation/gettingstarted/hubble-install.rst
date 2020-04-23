Install Hubble
==============

Hubble is a fully distributed networking and security observability platform
for cloud native workloads. It is built on top of Cilium and eBPF to enable
deep visibility into the communication and behavior of services as well as the
networking infrastructure in a completely transparent manner. `Visit Hubble Github page <https://github.com/cilium/hubble>`_.

Deploy Hubble using Helm:

.. code:: bash

    git clone https://github.com/cilium/hubble.git --branch v0.5
    cd hubble/install/kubernetes

    helm install hubble ./hubble \
        --namespace kube-system \
        --set metrics.enabled="{dns,drop,tcp,flow,port-distribution,icmp,http}" \
        --set ui.enabled=true
