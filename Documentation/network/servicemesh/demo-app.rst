Deploy the Demo App
===================

.. code-block:: shell-session

    $ kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.11/samples/bookinfo/platform/kube/bookinfo.yaml

This is just deploying the demo app, it's not adding any Istio components. You
can confirm that with Cilium Service Mesh there is no Envoy sidecar created
alongside each of the demo app microservices.

.. code-block:: shell-session

    $ kubectl get pods
    NAME                              READY   STATUS    RESTARTS   AGE
    details-v1-5498c86cf5-kjzkj       1/1     Running   0          2m39s
    productpage-v1-65b75f6885-ff59g   1/1     Running   0          2m39s
    ratings-v1-b477cf6cf-kv7bh        1/1     Running   0          2m39s
    reviews-v1-79d546878f-r5bjz       1/1     Running   0          2m39s
    reviews-v2-548c57f459-pld2f       1/1     Running   0          2m39s
    reviews-v3-6dd79655b9-nhrnh       1/1     Running   0          2m39s

.. Note::

    With the sidecar implementation the output would show 2/2 READY. One for
    the microservice and one for the Envoy sidecar.
