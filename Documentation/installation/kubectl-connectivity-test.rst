You can deploy the "connectivity-check" to test connectivity between pods. It is
recommended to create a separate namespace for this.

.. code-block:: shell-session

   kubectl create ns cilium-test

Deploy the check with:

.. parsed-literal::

   kubectl apply -n cilium-test -f \ |SCM_WEB|\/examples/kubernetes/connectivity-check/connectivity-check.yaml

It will deploy a series of deployments which will use various connectivity
paths to connect to each other. Connectivity paths include with and without
service load-balancing and various network policy combinations. The pod name
indicates the connectivity variant and the readiness and liveness gate
indicates success or failure of the test:

.. code-block:: shell-session

   $ kubectl get pods -n cilium-test
   NAME                                                     READY   STATUS    RESTARTS   AGE
   echo-a-76c5d9bd76-q8d99                                  1/1     Running   0          66s
   echo-b-795c4b4f76-9wrrx                                  1/1     Running   0          66s
   echo-b-host-6b7fc94b7c-xtsff                             1/1     Running   0          66s
   host-to-b-multi-node-clusterip-85476cd779-bpg4b          1/1     Running   0          66s
   host-to-b-multi-node-headless-dc6c44cb5-8jdz8            1/1     Running   0          65s
   pod-to-a-79546bc469-rl2qq                                1/1     Running   0          66s
   pod-to-a-allowed-cnp-58b7f7fb8f-lkq7p                    1/1     Running   0          66s
   pod-to-a-denied-cnp-6967cb6f7f-7h9fn                     1/1     Running   0          66s
   pod-to-b-intra-node-nodeport-9b487cf89-6ptrt             1/1     Running   0          65s
   pod-to-b-multi-node-clusterip-7db5dfdcf7-jkjpw           1/1     Running   0          66s
   pod-to-b-multi-node-headless-7d44b85d69-mtscc            1/1     Running   0          66s
   pod-to-b-multi-node-nodeport-7ffc76db7c-rrw82            1/1     Running   0          65s
   pod-to-external-1111-d56f47579-d79dz                     1/1     Running   0          66s
   pod-to-external-fqdn-allow-google-cnp-78986f4bcf-btjn7   1/1     Running   0          66s

.. note::

    If you deploy the connectivity check to a single node cluster, pods that check multi-node
    functionalities will remain in the ``Pending`` state. This is expected since these pods
    need at least 2 nodes to be scheduled successfully.

Once done with the test, remove the ``cilium-test`` namespace:

.. code-block:: shell-session

   kubectl delete ns cilium-test
