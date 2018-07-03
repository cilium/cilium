****************************
Using kube-router to run BGP
****************************

This guide explains how to configure Cilium and kube-router to co-operate to
use kube-router for BGP peering and route propagation and Cilium for policy
enforcement and load-balancing.

.. note::

    This is a beta feature. Please provide feedback and file a GitHub issue if
    you experience any problems.

Deploy kube-router
##################

Download the kube-router DaemonSet template:

.. code:: bash

    curl -LO https://raw.githubusercontent.com/cloudnativelabs/kube-router/v0.2.0-beta.7/daemonset/generic-kuberouter-only-advertise-routes.yaml

Open the file ``generic-kuberouter-only-advertise-routes.yaml`` and edit the
``args:`` section. The following arguments are **requried** to be set to
exactly these values:

.. code:: bash

    - --run-router=true
    - --run-firewall=false
    - --run-service-proxy=false
    - --enable-cni=false
    - --enable-pod-egress=false

The following arguments are **optional** and may be set according to your
needs.  For the purpose of keeping this guide simple, the following values are
being used which require the least preparations in your cluster. Please see the
`kube-router user guide
<https://github.com/cloudnativelabs/kube-router/blob/master/docs/user-guide.md>`_
for more information.

.. code:: bash

    - --enable-ibgp=true
    - --enable-overlay=true
    - --advertise-cluster-ip=true
    - --advertise-external-ip=true
    - --advertise-loadbalancer-ip=true

Apply the DaemonSet file to deploy kube-router and verify it has come up
correctly:

.. code:: bash

    $ kubectl apply -f generic-kuberouter-only-advertise-routes.yaml
    $ kubectl -n kube-system get pods -l k8s-app=kube-router
    NAME                READY     STATUS    RESTARTS   AGE
    kube-router-n6fv8   1/1       Running   0          10m
    kube-router-nj4vs   1/1       Running   0          10m
    kube-router-xqqwc   1/1       Running   0          10m
    kube-router-xsmd4   1/1       Running   0          10m

Deploy Cilium
#############

In order for routing to be delegated to kube-router, tunneling/encapsulation
must be disabled. This is done by setting the ``tunnel=disabled`` in the
ConfigMap ``cilium-config`` or by adjusting the DaemonSet to run the
``cilium-agent`` with the argument ``--tunnel=disabled``:

.. code:: bash

    # Encapsulation mode for communication between nodes
    # Possible values:
    #   - disabled
    #   - vxlan (default)
    #   - geneve
    tunnel: "disabled"

You can then install Cilium according to the instructions in section
:ref:`ds_deploy`.

Ensure that Cilium is up and running:

.. code:: bash

    $ kubectl -n kube-system get pods -l k8s-app=cilium
    NAME           READY     STATUS    RESTARTS   AGE
    cilium-fhpk2   1/1       Running   0          45m
    cilium-jh6kc   1/1       Running   0          44m
    cilium-rlx6n   1/1       Running   0          44m
    cilium-x5x9z   1/1       Running   0          45m

Verify Installation
###################

Verify that kube-router has installed routes:

.. code:: bash

    $ kubectl -n kube-system exec -ti cilium-fhpk2 -- ip route list scope global
    default via 172.0.32.1 dev eth0 proto dhcp src 172.0.50.227 metric 1024
    10.2.0.0/24 via 10.2.0.172 dev cilium_host src 10.2.0.172
    10.2.1.0/24 via 172.0.51.175 dev eth0 proto 17
    10.2.2.0/24 dev tun-172011760 proto 17 src 172.0.50.227
    10.2.3.0/24 dev tun-1720186231 proto 17 src 172.0.50.227

In the above example, we see three categories of routes that have been
installed:

* *Local PodCIDR:* This route points to all pods running on the host and makes
  these pods available to 
  * `10.2.0.0/24 via 10.2.0.172 dev cilium_host src 10.2.0.172`
* *BGP route:* This type of route is installed if kube-router determines that
  the remote PodCIDR can be reached via a router known to the local host. It
  will instruct pod to pod traffic to be forwarded directly to that router
  without requiring any encapsulation.
  * `10.2.1.0/24 via 172.0.51.175 dev eth0 proto 17`
* *IPIP tunnel route:*  If no direct routing path exists, kube-router will fall
  back to using an overlay and establish an IPIP tunnel between the nodes.
  * `10.2.2.0/24 dev tun-172011760 proto 17 src 172.0.50.227`
  * `10.2.3.0/24 dev tun-1720186231 proto 17 src 172.0.50.227`

You can test connectivity by deploying the following connectivity checker pods:

.. code:: bash

    $ kubectl create -f \ |SCM_WEB|\/examples/kubernetes/connectivity-check/connectivity-check.yaml
    $ kubectl get pods
    NAME                    READY     STATUS    RESTARTS   AGE
    echo-7d9f9564df-2vbpw   1/1       Running   0          26m
    echo-7d9f9564df-ff8xh   1/1       Running   0          26m
    echo-7d9f9564df-pnbgc   1/1       Running   0          26m
    echo-7d9f9564df-sbrxh   1/1       Running   0          26m
    echo-7d9f9564df-wzfrc   1/1       Running   0          26m
    probe-8689f6579-7l7w7   1/1       Running   0          27m
    probe-8689f6579-fvqp8   1/1       Running   0          27m
    probe-8689f6579-lvjlh   1/1       Running   0          27m
    probe-8689f6579-m26g8   1/1       Running   0          27m
    probe-8689f6579-tzbjk   1/1       Running   0          27m
