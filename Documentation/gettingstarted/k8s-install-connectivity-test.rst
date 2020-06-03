Deploy the connectivity test
----------------------------

You can deploy the "connectivity-check" to test connectivity between pods.

.. parsed-literal::

    kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/connectivity-check/connectivity-check.yaml

It will deploy a series of deployments which will use various connectivity
paths to connect to each other. Connectivity paths include with and without
service load-balancing and various network policy combinations. The pod name
indicates the connectivity variant and the readiness and liveness gate
indicates success or failure of the test:

.. code:: bash

    NAME                                                    READY   STATUS    RESTARTS   AGE
    echo-a-5995597649-f5d5g                                 1/1     Running   0          4m51s
    echo-b-54c9bb5f5c-p6lxf                                 1/1     Running   0          4m50s
    echo-b-host-67446447f7-chvsp                            1/1     Running   0          4m50s
    host-to-b-multi-node-clusterip-78f9869d75-l8cf8         1/1     Running   0          4m50s
    host-to-b-multi-node-headless-798949bd5f-vvfff          1/1     Running   0          4m50s
    pod-to-a-59b5fcb7f6-gq4hd                               1/1     Running   0          4m50s
    pod-to-a-allowed-cnp-55f885bf8b-5lxzz                   1/1     Running   0          4m50s
    pod-to-a-external-1111-7ff666fd8-v5kqb                  1/1     Running   0          4m48s
    pod-to-a-l3-denied-cnp-64c6c75c5d-xmqhw                 1/1     Running   0          4m50s
    pod-to-b-intra-node-845f955cdc-5nfrt                    1/1     Running   0          4m49s
    pod-to-b-multi-node-clusterip-666594b445-bsn4j          1/1     Running   0          4m49s
    pod-to-b-multi-node-headless-746f84dff5-prk4w           1/1     Running   0          4m49s
    pod-to-b-multi-node-nodeport-7cb9c6cb8b-ksm4h           1/1     Running   0          4m49s
    pod-to-external-fqdn-allow-google-cnp-b7b6bcdcb-tg9dh   1/1     Running   0          4m48s

.. note::

    If you deploy the connectivity check to a single node cluster, pods that check multi-node
    functionalities will remain in the ``Pending`` state. This is expected since these pods
    need at least 2 nodes to be scheduled successfully.
