Validate the Installation
=========================

You can monitor as Cilium and all required components are being installed:

.. parsed-literal::

    kubectl -n cilium get pods --watch
    NAME                               READY   STATUS            RESTARTS   AGE
    cilium-bbpwg                       0/1     PodInitializing   0          27s
    cilium-node-init-jwtw6             1/1     Running           0          27s
    cilium-node-init-t5cm9             1/1     Running           0          27s
    cilium-operator-7967c75f94-ckd5g   0/1     Pending           0          27s
    cilium-rnrxr                       0/1     Running           0          27s

It may take a couple of minutes for all components to come up:

.. parsed-literal::

    kubectl -n cilium get pods
    NAME                               READY   STATUS    RESTARTS   AGE
    cilium-bbpwg                       1/1     Running   0          70s
    cilium-node-init-jwtw6             1/1     Running   0          70s
    cilium-node-init-t5cm9             1/1     Running   0          70s
    cilium-operator-7967c75f94-ckd5g   1/1     Running   0          70s
    cilium-rnrxr                       1/1     Running   0          70s

.. include:: k8s-install-connectivity-test.rst
