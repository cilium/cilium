Validate the Installation
=========================

You can monitor as Cilium and all required components are being installed:

.. parsed-literal::

    kubectl -n cilium get pods --watch
    NAME                                    READY   STATUS              RESTARTS   AGE
    cilium-operator-cb4578bc5-q52qk         0/1     Pending             0          8s
    cilium-s8w5m                            0/1     PodInitializing     0          7s

It may take a couple of minutes for all components to come up:

.. parsed-literal::

    cilium-operator-cb4578bc5-q52qk         1/1     Running   0          4m13s
    cilium-s8w5m                            1/1     Running   0          4m12s

Deploy the connectivity test
----------------------------

You can deploy the "connectivity-check" to test connectivity between pods.

.. parsed-literal::

    kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/connectivity-check/connectivity-check.yaml

It will deploy a simple probe and echo server running with multiple replicas.
The probe will only report readiness while it can successfully reach the echo
server:

.. code:: bash

    kubectl get pods
    NAME                     READY   STATUS    RESTARTS   AGE
    echo-585798dd9d-ck5xc    1/1     Running   0          75s
    echo-585798dd9d-jkdjx    1/1     Running   0          75s
    echo-585798dd9d-mk5q8    1/1     Running   0          75s
    echo-585798dd9d-tn9t4    1/1     Running   0          75s
    echo-585798dd9d-xmr4p    1/1     Running   0          75s
    probe-866bb6f696-9lhfw   1/1     Running   0          75s
    probe-866bb6f696-br4dr   1/1     Running   0          75s
    probe-866bb6f696-gv5kf   1/1     Running   0          75s
    probe-866bb6f696-qg2b7   1/1     Running   0          75s
    probe-866bb6f696-tb926   1/1     Running   0          75s
