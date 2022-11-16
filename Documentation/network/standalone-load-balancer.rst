.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _standalone-load-balancer:

************************
Standalone Load-Balancer
************************

Cilium's eBPF-based load-balancer supports advanced features such as Maglev
consistent hashing, or forwarding plane acceleration at the XDP layer,
improving the robustness and the efficiency of load-balancing. Even though
these features were developed for Kubernetes environments in order to replace
kube-proxy, they led to the creation of a standalone, generically programmable,
high-performance layer 4 load-balancer framework (L4LB, also abbreviated as LB
in the rest of this document), which can be deployed as a standalone component.

Quick-Start
===========

Prepare the Setup
-----------------

In this tutorial, we use Kind to create a cluster with two nodes, a
load-balancer frontend and a backend. We set up Cilium's standalone
load-balancer on the frontend and configure a service to make sure that the
requests are properly routed to the backend. We test the traffic in three
cases: regular setup, XDP redirection, and backend in maintenance mode.

Before we start, some preparation is necessary.

``bpf_xdp_veth_host`` is a dummy XDP program which is going to be attached to
LB node's veth pair end in the host netns. When ``bpf_xdp``, which is attached
in the container netns, forwards a LB request with ``XDP_TX``, the request
needs to be picked in the host netns by a NAPI handler. To register the
handler, we attach the dummy program. First, we compile it:

.. code-block:: shell-session

    $ clang -O2 -Wall -target bpf -c test/l4lb/bpf_xdp_veth_host.c -o bpf_xdp_veth_host.o

The worker (backend node) will receive IPIP packets from the LB node. To
decapsulate the packets, instead of creating an ``ipip`` dev which would
complicate network setup, we will attach the following program which terminates
the tunnel. We compile it:

.. code-block:: shell-session

    $ clang -O2 -Wall -target bpf -c test/l4lb/test_tc_tunnel.c -o test_tc_tunnel.o

With Kind, we create a cluster with two nodes:

- ``kind-control-plane`` runs Cilium in LB-only mode.
- ``kind-worker`` runs the Nginx server.

.. code-block:: shell-session

    $ kind create cluster --config test/l4lb/kind-config.yaml --image=kindest/node:v1.24.3

The Cilium LB node does not connect to the kube-apiserver. We just use Kind to
create Docker-in-Docker containers.

Setup the Nginx Worker Node
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: shell-session

    $ docker exec kind-worker /bin/sh -c 'apt-get update && apt-get install -y nginx && systemctl start nginx'
    $ WORKER_IP=$(docker exec kind-worker ip -o -4 a s eth0 | awk '{print $4}' | cut -d/ -f1)
    # nsenter -t $(docker inspect kind-worker -f '{{ .State.Pid }}') -n /bin/sh -c \
        'tc qdisc add dev eth0 clsact && tc filter add dev eth0 ingress bpf direct-action object-file ./test_tc_tunnel.o section decap'

Set up the Load-Balancer Node
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We create an additional veth pair between the host and the Cilium LB node. We
will use it later to test ``XDP_REDIRECT``:

.. code-block:: shell-session

    # ip l a l4lb-veth0 type veth peer l4lb-veth1
    $ SECOND_LB_NODE_IP=3.3.3.2
    # ip a a "3.3.3.1/24" dev l4lb-veth0
    $ CONTROL_PLANE_PID=$(docker inspect kind-control-plane -f '{{ .State.Pid }}')
    # ip l s dev l4lb-veth1 netns $CONTROL_PLANE_PID
    # ip l s dev l4lb-veth0 up
    # nsenter -t $CONTROL_PLANE_PID -n /bin/sh -c "\
        ip a a "${SECOND_LB_NODE_IP}/24" dev l4lb-veth1 && \
        ip l s dev l4lb-veth1 up"

Install Cilium as standalone L4 LB:

.. code-block:: shell-session

    $ helm install cilium install/kubernetes/cilium \
        --wait \
        --namespace kube-system \
        --set debug.enabled=true \
        --set image.repository="quay.io/cilium/cilium-ci" \
        --set image.tag="latest" \
        --set image.useDigest=false \
        --set image.pullPolicy=IfNotPresent \
        --set operator.enabled=false \
        --set loadBalancer.standalone=true \
        --set loadBalancer.algorithm=maglev \
        --set loadBalancer.mode=dsr \
        --set loadBalancer.acceleration=native \
        --set loadBalancer.dsrDispatch=ipip \
        --set devices='{eth0,l4lb-veth1}' \
        --set nodePort.directRoutingDevice=eth0 \
        --set affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].key="kubernetes.io/hostname" \
        --set affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].operator=In \
        --set affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].values[0]=kind-control-plane

We attach our dummy XDP program to veth pair ends:

.. code-block:: shell-session

    $ IFIDX=$(docker exec -i kind-control-plane \
        /bin/sh -c 'echo $(( $(ip -o l show eth0 | awk "{print $1}" | cut -d: -f1) ))')
    $ LB_VETH_HOST=$(ip -o l | grep "if$IFIDX" | awk '{print $2}' | cut -d@ -f1)
    # ip l set dev $LB_VETH_HOST xdp obj bpf_xdp_veth_host.o
    # ip l set dev l4lb-veth0 xdp obj bpf_xdp_veth_host.o

Disable TX and RX checksum offload, as veth does not support it. Otherwise, the
packets forwarded by the LB to the worker node will have invalid checksums:

.. code-block:: shell-session

    # ethtool -K $LB_VETH_HOST rx off tx off
    # ethtool -K l4lb-veth0 rx off tx off

Wait for the node to get ready:

.. code-block:: shell-session

    $ CILIUM_POD_NAME=$(kubectl -n kube-system get pod -l k8s-app=cilium -o=jsonpath='{.items[0].metadata.name}')
    $ kubectl -n kube-system wait --for=condition=Ready pod "$CILIUM_POD_NAME" --timeout=5m

Deploy the Load-Balancer
------------------------

.. code-block:: shell-session

    $ ./daemon/cilium-agent \
        --enable-ipv4=true \
        --enable-ipv6=true \
        --datapath-mode=lb-only \
        --bpf-lb-algorithm=maglev \
        --bpf-lb-maglev-table-size=2039 \
        --bpf-lb-mode=dsr \
        --bpf-lb-acceleration=native \
        --devices=enp2s0np0 \
        --bpf-lb-dsr-dispatch=ipip \
        --disable-envoy-version-check=true

Validate the Setup
------------------

We retrieve the LB node's IP address, and set the relevant routes for the
traffic:

.. code-block:: shell-session

    $ LB_VIP="10.0.0.2"
    # nsenter -t $(docker inspect kind-worker -f '{{ .State.Pid }}') -n /bin/sh -c \
        "ip a a dev eth0 ${LB_VIP}/32"
    $ LB_NODE_IP=$(docker exec kind-control-plane ip -o -4 a s eth0 | awk '{print $4}' | cut -d/ -f1)
    # ip r a "${LB_VIP}/32" via "$LB_NODE_IP"

Then we declare the LB service (NodePort), using the LB node as a frontend, and
the Nginx worker nodes as a backend, listening on port 80:

    $ kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- \
        cilium service update --id 1 --frontend "${LB_VIP}:80" --backends "${WORKER_IP}:80" --k8s-node-port

We can issue a few requests to the LB, and observe they all go through:

.. code-block:: bash

    for i in $(seq 1 10); do
        curl -o /dev/null "${LB_VIP}:80" || (echo "Failed $i"; exit -1)
    done

Now we steer the traffic to ``LB_VIP`` via the secondary device so that
``XDP_REDIRECT`` can be tested on the LB node:

.. code-block:: shell-session

    # ip r replace "${LB_VIP}/32" via "$SECOND_LB_NODE_IP"

Again, we send some requests to the LB and should see them answered:

.. code-block:: bash

    for i in $(seq 1 10); do
        curl -o /dev/null "${LB_VIP}:80" || (echo "Failed $i"; exit -1)
    done

Now we set ``kind-worker`` to maintenance, by assigning a weight of ``0`` to
the backend:

.. code-block:: shell-session

    $ kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- \
        cilium service update --id 1 --frontend "${LB_VIP}:80" --backends "${WORKER_IP}:80" --backend-weights "0" --k8s-node-port

We issue requests to the LB (here with a 500 milliseconds timeout). Given that
``kind-worker`` no longer receives the packets, the requests are expected to
timeout:

.. code-block:: bash

    for i in $(seq 1 10); do
        # curl should fail with code 28 - Operation timeout
        curl -o /dev/null -m 0.5 "${LB_VIP}:80"
    done

Clean up the Cluster
--------------------

.. code-block:: shell-session

    $ kind delete cluster

Configuration Options
=====================

The ``cilium`` CLI recognizes the following options for configuring the load-balancer:

``id``
    Load-Balancer identifier

``k8s-external``
    Set service as a Kubernetes ExternalIPs

``k8s-node-port``
    Set service as a Kubernetes NodePort

``k8s-load-balancer``
    Set service as a Kubernetes LoadBalancer

``k8s-host-port``
    Set service as a Kubernetes HostPort

``local-redirect``
    Set service as a Local Redirect

``k8s-traffic-policy``
    Set service with Kubernetes ``externalTrafficPolicy`` as ``{Local,Cluster}``

``k8s-cluster-internal``
    Set service as cluster-internal for ``externalTrafficPolicy=Local``

``frontend``
    Frontend address

``backends``
    Backend address or addresses (``<IP:Port>``)

``states``
    Backend state(s) as ``{active(default),terminating,quarantined,maintenance}``

``backend-weights``
    Backend weights (100 default, 0 means maintenance state, only for Maglev mode)

Further Readings
================

The following resources contain further details on the Standalone
Load-Balancer.

- `Cilium Standalone Layer 4 Load Balancer XDP
  <https://cilium.io/blog/2022/04/12/cilium-standalone-L4LB-XDP/>`_
- `Cilium Standalone XDP L4 Load Balancer
  <https://www.youtube.com/watch?v=0YqF45Kaapo&t=7259s>`_
  (eBPF Summit 2022)
- `eCHO Episode 9: XDP and Load Balancing
  <https://www.youtube.com/watch?v=OIyPm6K4ooY>`_
- `XDP-based Standalone Load Balancer
  <https://cilium.io/blog/2021/05/20/cilium-110/#standalonelb>`_
  (Cilium 1.10 release announcement)
