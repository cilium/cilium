You can monitor as Cilium and all required components are being installed:

.. code-block:: shell-session

   $ kubectl -n kube-system get pods --watch
   NAME                                    READY   STATUS              RESTARTS   AGE
   cilium-operator-cb4578bc5-q52qk         0/1     Pending             0          8s
   cilium-s8w5m                            0/1     PodInitializing     0          7s
   coredns-86c58d9df4-4g7dd                0/1     ContainerCreating   0          8m57s
   coredns-86c58d9df4-4l6b2                0/1     ContainerCreating   0          8m57s

It may take a couple of minutes for all components to come up:

.. code-block:: shell-session

   cilium-operator-cb4578bc5-q52qk         1/1     Running   0          4m13s
   cilium-s8w5m                            1/1     Running   0          4m12s
   coredns-86c58d9df4-4g7dd                1/1     Running   0          13m
   coredns-86c58d9df4-4l6b2                1/1     Running   0          13m
