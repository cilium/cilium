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

.. include:: k8s-install-connectivity-test.rst
