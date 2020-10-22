Validate the Installation
=========================

You can monitor as Cilium and all required components are being installed:

.. code-block:: shell-session

   $ kubectl -n cilium get pods --watch
   cilium-2twr9                      0/1     Init:0/2            0          17s
   cilium-fkhjv                      0/1     Init:0/2            0          17s
   cilium-node-init-bhr5l            1/1     Running             0          17s
   cilium-node-init-l77v9            1/1     Running             0          17s
   cilium-operator-f8bd5cd96-qdspd   0/1     ContainerCreating   0          17s
   cilium-operator-f8bd5cd96-tvdn6   0/1     ContainerCreating   0          17s

It may take a couple of minutes for all components to come up:

.. code-block:: shell-session

   cilium-operator-f8bd5cd96-tvdn6   1/1     Running             0          25s
   cilium-operator-f8bd5cd96-qdspd   1/1     Running             0          26s
   cilium-fkhjv                      1/1     Running             0          60s
   cilium-2twr9                      1/1     Running             0          61s

.. include:: k8s-install-connectivity-test.rst
