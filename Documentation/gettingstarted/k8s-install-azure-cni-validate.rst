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

It will deploy a series of deployments which will use various connectivity
paths to connect to each other. Connectivity paths include with and without
service load-balancing and various network policy combinations. The pod name
indicates the connectivity variant and the readiness and liveness gate
indicates success or failure of the test:

.. code:: bash

    kubectl get pods
    NAME                                                     READY   STATUS             RESTARTS   AGE
    echo-a-9b85dd869-292s2                                   1/1     Running            0          8m37s
    echo-b-c7d9f4686-gdwcs                                   1/1     Running            0          8m37s
    host-to-b-multi-node-clusterip-6d496f7cf9-956jb          1/1     Running            0          8m37s
    host-to-b-multi-node-headless-bd589bbcf-jwbh2            1/1     Running            0          8m37s
    pod-to-a-7cc4b6c5b8-9jfjb                                1/1     Running            0          8m36s
    pod-to-a-allowed-cnp-6cc776bb4d-2cszk                    1/1     Running            0          8m36s
    pod-to-a-external-1111-5c75bd66db-sxfck                  1/1     Running            0          8m35s
    pod-to-a-l3-denied-cnp-7fdd9975dd-2pp96                  1/1     Running            0          8m36s
    pod-to-b-intra-node-9d9d4d6f9-qccfs                      1/1     Running            0          8m35s
    pod-to-b-multi-node-clusterip-5956c84b7c-hwzfg           1/1     Running            0          8m35s
    pod-to-b-multi-node-headless-6698899447-xlhfw            1/1     Running            0          8m35s
    pod-to-external-fqdn-allow-google-cnp-667649bbf6-v6rf8   0/1     Running            0          8m35s
