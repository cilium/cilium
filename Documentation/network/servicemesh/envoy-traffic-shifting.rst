.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_envoy_traffic_shifting:

*******************
L7 Traffic Shifting
*******************

Cilium Service Mesh defines a ``CiliumEnvoyConfig`` CRD which allows users
to set the configuration of the Envoy component built into Cilium agents.

This example sets up an Envoy listener which load balances requests
to the helloworld Service by sending 90% of incoming requests to the
backend ``helloworld-v1`` and 10% of incoming requests to the backend
``helloworld-v2``.

Deploy Test Applications
========================

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/envoy/client-helloworld.yaml

The test workloads consist of:

- One client Deployment, ``client``
- Two server Deployments, ``helloworld-v1`` and ``helloworld-v2``

View information about these Pods and the helloworld Service:

.. code-block:: shell-session

    $ kubectl get pods --show-labels -o wide
    NAME                             READY   STATUS    RESTARTS   AGE     IP           NODE                   NOMINATED NODE   READINESS GATES   LABELS
    client-64848f85dd-sjfmb          1/1     Running   0          2m23s   10.0.0.206   cilium-control-plane   <none>           <none>            kind=client,name=client,pod-template-hash=64848f85dd
    helloworld-v1-5845f97d6b-gkdtk   1/1     Running   0          2m23s   10.0.0.241   cilium-control-plane   <none>           <none>            app=helloworld,pod-template-hash=5845f97d6b,version=v1
    helloworld-v2-7d55d87964-ns9kh   1/1     Running   0          2m23s   10.0.0.251   cilium-control-plane   <none>           <none>            app=helloworld,pod-template-hash=7d55d87964,version=v2

    $ kubectl get svc --show-labels
    NAME         TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)    AGE   LABELS
    helloworld   ClusterIP   10.96.194.77   <none>        5000/TCP   8m27s app=helloworld,service=helloworld

Apply weight-based routing
==========================

Make an environment variable with the Pod name for client:

.. code-block:: shell-session

    $ export CLIENT=$(kubectl get pods -l name=client -o jsonpath='{.items[0].metadata.name}')

Try making several requests to the helloworld Service.

.. code-block:: shell-session

    $ for i in {1..10}; do  kubectl exec -it $CLIENT -- curl  helloworld:5000/hello; done

The test results are as follows::

    Hello version: v2, instance: helloworld-v2-7d55d87964-ns9kh
    Hello version: v2, instance: helloworld-v2-7d55d87964-ns9kh
    Hello version: v2, instance: helloworld-v2-7d55d87964-ns9kh
    Hello version: v1, instance: helloworld-v1-5845f97d6b-gkdtk
    Hello version: v1, instance: helloworld-v1-5845f97d6b-gkdtk
    Hello version: v1, instance: helloworld-v1-5845f97d6b-gkdtk
    Hello version: v2, instance: helloworld-v2-7d55d87964-ns9kh
    Hello version: v1, instance: helloworld-v1-5845f97d6b-gkdtk
    Hello version: v2, instance: helloworld-v2-7d55d87964-ns9kh
    Hello version: v1, instance: helloworld-v1-5845f97d6b-gkdtk

The test results were as expected. Of the requests sent to the helloworld service,
50% of them were sent to the backend ``helloworld-v1`` and 50% of them were sent to
the backend ``helloworld-v2``.

``CiliumEnvoyConfig`` can be used to load balance traffic destined to one Service to a
group of backend Services. To load balance traffic to the helloworld Service, first create
individual Services for each backend Deployment.

.. parsed-literal::
    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/envoy/helloworld-service-v1-v2.yaml

Apply the ``envoy-helloworld-v1-90-v2-10.yaml`` file, which defines a ``CiliumEnvoyConfig``
to send 90% of traffic to the helloworld-v1 Service backend and 10% of traffic to the helloworld-v2 Service backend:

.. parsed-literal::
    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/envoy/envoy-helloworld-v1-90-v2-10.yaml

View information about these Pods and Services:

.. code-block:: shell-session

    $ kubectl get pods --show-labels -o wide
    NAME                             READY   STATUS    RESTARTS   AGE     IP           NODE                   NOMINATED NODE   READINESS GATES   LABELS
    client-64848f85dd-sjfmb          1/1     Running   0          2m23s   10.0.0.206   cilium-control-plane   <none>           <none>            kind=client,name=client,pod-template-hash=64848f85dd
    helloworld-v1-5845f97d6b-gkdtk   1/1     Running   0          2m23s   10.0.0.241   cilium-control-plane   <none>           <none>            app=helloworld,pod-template-hash=5845f97d6b,version=v1
    helloworld-v2-7d55d87964-ns9kh   1/1     Running   0          2m23s   10.0.0.251   cilium-control-plane   <none>           <none>            app=helloworld,pod-template-hash=7d55d87964,version=v2

    $ kubectl get svc --show-labels
    NAME            TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)    AGE   LABELS
    helloworld      ClusterIP   10.96.194.77   <none>        5000/TCP   16m   app=helloworld,service=helloworld
    helloworld-v1   ClusterIP   10.96.0.240    <none>        5000/TCP   4s    app=helloworld,service=helloworld,version=v1
    helloworld-v2   ClusterIP   10.96.41.142   <none>        5000/TCP   4s    app=helloworld,service=helloworld,version=v2

.. include:: warning.rst

Try making several requests to the helloworld Service again.

.. code-block:: shell-session

    $ for i in {1..10}; do  kubectl exec -it $CLIENT -- curl  helloworld:5000/hello; done

The test results are as follows::

    Hello version: v1, instance: helloworld-v1-5845f97d6b-gkdtk
    Hello version: v1, instance: helloworld-v1-5845f97d6b-gkdtk
    Hello version: v1, instance: helloworld-v1-5845f97d6b-gkdtk
    Hello version: v2, instance: helloworld-v2-7d55d87964-ns9kh
    Hello version: v1, instance: helloworld-v1-5845f97d6b-gkdtk
    Hello version: v1, instance: helloworld-v1-5845f97d6b-gkdtk
    Hello version: v1, instance: helloworld-v1-5845f97d6b-gkdtk
    Hello version: v1, instance: helloworld-v1-5845f97d6b-gkdtk
    Hello version: v1, instance: helloworld-v1-5845f97d6b-gkdtk
    Hello version: v1, instance: helloworld-v1-5845f97d6b-gkdtk

The test results were as expected. Of the requests sent to the helloworld service,
90% of them were sent to the backend ``helloworld-v1`` and 10% of them were sent to
the backend ``helloworld-v2``.

Cleaning up
===========

Remove the rules.

.. parsed-literal::

    $ kubectl delete -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/envoy/envoy-helloworld-v1-90-v2-10.yaml

Remove the test application.

.. parsed-literal::

    $ kubectl delete -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/envoy/client-helloworld.yaml
    $ kubectl delete -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/envoy/helloworld-service-v1-v2.yaml
