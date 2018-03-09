.. _admin_upgrade:

*************
Upgrade Guide
*************

Kubernetes Cilium Upgrade
=========================

Cilium should be upgraded using Kubernetes rolling upgrade functionality in order to minimize network disruptions for running workloads.

Make sure you are using the latest RBAC role and service account definitions
before performing the rolling upgrade:

.. parsed-literal::

    kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/rbac.yaml

Substitute the desired Cilium version number of vX.Y.Z in the command below

::

    kubectl set image daemonset/cilium -n kube-system cilium-agent=cilium/cilium:vX.Y.Z

To monitor the rollout and confirm it is complete, run: 

::

    kubectl rollout status daemonset/cilium -n kube-system

To undo the rollout via rollback, run:
    
::

    kubectl rollout undo daemonset/cilium -n kube-system

Cilium will continue to forward traffic at L3/L4 during the roll-out, and all endpoints and their configuration will be preserved across
the upgrade rollout.   However, because the L7 proxies implementing HTTP, gRPC, and Kafka-aware filtering currently reside in the 
same Pod as Cilium, they are removed and re-installed as part of the rollout.   As a result, any proxied connections will be lost and 
clients must reconnect.   

