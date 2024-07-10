.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

Deploy the First Ingress
========================

You'll find the example Ingress definition in ``basic-ingress.yaml``.

.. literalinclude:: ../../../examples/kubernetes/servicemesh/basic-ingress.yaml

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/basic-ingress.yaml


This example routes requests for the path ``/details`` to the ``details`` service,
and ``/`` to the ``productpage`` service.

Getting the list of services, you'll see a LoadBalancer service is automatically
created for this ingress. Your cloud provider will automatically provision an
external IP address, but it may take around 30 seconds.

.. code-block:: shell-session

    # For dedicated load balancer mode
    $ kubectl get svc
    NAME                           TYPE           CLUSTER-IP       EXTERNAL-IP     PORT(S)        AGE
    cilium-ingress-basic-ingress   LoadBalancer   10.98.169.125    10.98.169.125   80:32478/TCP   2m11s
    details                        ClusterIP      10.102.131.226   <none>          9080/TCP       2m15s
    kubernetes                     ClusterIP      10.96.0.1        <none>          443/TCP        10m
    productpage                    ClusterIP      10.97.231.139    <none>          9080/TCP       2m15s
    ratings                        ClusterIP      10.108.152.42    <none>          9080/TCP       2m15s
    reviews                        ClusterIP      10.111.145.160   <none>          9080/TCP       2m15s

    # For shared load balancer mode
    $ kubectl get services -n kube-system cilium-ingress
    NAME             TYPE           CLUSTER-IP      EXTERNAL-IP     PORT(S)                      AGE
    cilium-ingress   LoadBalancer   10.98.169.125   10.98.169.125   80:32690/TCP,443:31566/TCP   18m

The external IP address should also be populated into the Ingress:

.. code-block:: shell-session

    $ kubectl get ingress
    NAME            CLASS    HOSTS   ADDRESS         PORTS   AGE
    basic-ingress   cilium   *       10.98.169.125   80      97s

.. Note::

    Some providers e.g. EKS use a fully-qualified domain name rather than an IP address.