.. _kops_guide:

****************************
Using kube-router to run BGP
****************************

This guide explains how to configure Cilium and kube-router to co-operate to
use kube-router for BGP peering and route propagation and Cilium for policy
enforcement and load-balancing.

.. note::

    This feature is regarded as ``tech-preview``. Please provide feedback and
    file a GitHub issue if you experience any problems.

Deploy kube-router
##################

Download the kube-router DaemonSet template:

.. code:: bash

    curl -LO https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/daemonset/generic-kuberouter-only-advertise-routes.yaml

Open the file ``generic-kuberouter-only-advertise-routes.yaml`` and edit the
``args:`` section. The following arguments are **requried** to be set to
exactly these values:

.. code:: bash

    - "--run-router=true"
    - "--run-firewall=false"
    - "--run-service-proxy=false"
    - "--enable-cni=false"
    - "--enable-pod-egress=false"

The following arguments are **optional** and may be set according to your
needs. Please see the `kube-router user guide
<https://github.com/cloudnativelabs/kube-router/blob/master/docs/user-guide.md>`_
for more information:

.. code:: bash

    - "--enable-ibgp=false"
    - "--enable-overlay=false"
    - "--peer-router-ips=<CHANGE ME>"
    - "--peer-router-asns=<CHANGE ME>"
    - "--cluster-asn=<CHANGE ME>"

Apply the DaemonSet file to deploy kube-router and verify it has come up
correctly:

.. code:: bash

    $ kubectl apply -f generic-kuberouter-only-advertise-routes.yaml
    $ kubectl -n kube-system get pods -l k8s-app=kube-router
    kube-router-2dgkt   1/1       Running   0          52s
    kube-router-pl9j6   1/1       Running   0          52s
    kube-router-shgk8   1/1       Running   0          52s
    kube-router-wvpm5   1/1       Running   0          52s

Deploy Cilium
#############

In order for route installation to be delegated to kube-router,
tunneling/encapsulation must be disabled. This is done by changing the
``tunnel`` key in the ConfigMap ``cilium-config`` or by adjusting the
DaemonSet to set ``--tunnel=disabled``:

.. code:: bash

    # Encapsulation mode for communication between nodes
    # Possible values:
    #   - disabled
    #   - vxlan (default)
    #   - geneve
    tunnel: "disabled"

.. note::

    If you are running kube-route with overlay enabled, adjust for the
    encapsulation overhead by setting the environment variable ``MTU`` to the
    value 1450.

You can then install Cilium according to the instructions in section
:ref:`ds_deploy`.

Ensure that Cilium is up and running:

.. code:: bash

    $ kubectl -n kube-system get pods -l k8s-app=cilium
    NAME           READY     STATUS    RESTARTS   AGE
    cilium-556b9   1/1       Running   0          1h
    cilium-5zx4b   1/1       Running   0          1h
    cilium-pcghg   1/1       Running   0          1h
    cilium-x5dtp   1/1       Running   0          1h

Verify Installation
###################

Verify that kube-router has installed routes:

.. code:: bash

    $ kubectl -n kube-system exec -ti cilium-556b9 -- ip route list scope global
    default via 172.0.96.1 dev eth0 proto dhcp src 172.0.117.198 metric 1024
    10.2.0.0/24 dev tun-172052116 proto 17 src 172.0.117.198
    10.2.1.0/24 via 10.2.1.18 dev cilium_host src 10.2.1.18
    10.2.2.0/24 dev tun-17204217 proto 17 src 172.0.117.198
    10.2.3.0/24 dev tun-1720179114 proto 17 src 172.0.117.198

In the above example, the routes in the form of ``10.2.0.0/24 dev
tun-172052116`` are installed by kube-router whereas the route ``10.2.1.0/24
via 10.2.1.18 dev cilium_host`` is installed by Cilium to handle the PodCIDR of
the local node.
