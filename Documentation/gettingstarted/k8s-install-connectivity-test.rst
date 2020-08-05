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

.. code:: shell-session

   $ kubectl get pods -n cilium-test
   NAME                                                    READY   STATUS    RESTARTS   AGE
   echo-a-6788c799fd-42qxx                                 1/1     Running   0          69s
   echo-b-59757679d4-pjtdl                                 1/1     Running   0          69s
   echo-b-host-f86bd784d-wnh4v                             1/1     Running   0          68s
   host-to-b-multi-node-clusterip-585db65b4d-x74nz         1/1     Running   0          68s
   host-to-b-multi-node-headless-77c64bc7d8-kgf8p          1/1     Running   0          67s
   pod-to-a-allowed-cnp-87b5895c8-bfw4x                    1/1     Running   0          68s
   pod-to-a-b76ddb6b4-2v4kb                                1/1     Running   0          68s
   pod-to-a-denied-cnp-677d9f567b-kkjp4                    1/1     Running   0          68s
   pod-to-b-intra-node-nodeport-8484fb6d89-bwj8q           1/1     Running   0          68s
   pod-to-b-multi-node-clusterip-f7655dbc8-h5bwk           1/1     Running   0          68s
   pod-to-b-multi-node-headless-5fd98b9648-5bjj8           1/1     Running   0          68s
   pod-to-b-multi-node-nodeport-74bd8d7bd5-kmfmm           1/1     Running   0          68s
   pod-to-external-1111-7489c7c46d-jhtkr                   1/1     Running   0          68s
   pod-to-external-fqdn-allow-google-cnp-b7b6bcdcb-97p75   1/1     Running   0          68s

.. note::

    If you deploy the connectivity check to a single node cluster, pods that check multi-node
    functionalities will remain in the ``Pending`` state. This is expected since these pods
    need at least 2 nodes to be scheduled successfully.
