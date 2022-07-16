.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _CiliumEndpoint:

************
Endpoint CRD
************

When managing pods in Kubernetes, Cilium will create a Custom Resource
Definition (CRD) of Kind ``CiliumEndpoint``. One ``CiliumEndpoint`` is created
for each pod managed by Cilium, with the same name and in the same namespace.
The ``CiliumEndpoint`` objects contain the same information as the json output
of ``cilium endpoint get`` under the ``.status`` field, but can be fetched for
all pods in the cluster.  Adding the ``-o json`` will export more information
about each endpoint. This includes the endpoint's labels, security identity and
the policy in effect on it.

For example:

.. code-block:: shell-session

    $ kubectl get ciliumendpoints --all-namespaces
    NAMESPACE     NAME                     AGE
    default       app1-55d7944bdd-l7c8j    1h
    default       app1-55d7944bdd-sn9xj    1h
    default       app2                     1h
    default       app3                     1h
    kube-system   cilium-health-minikube   1h
    kube-system   microscope               1h

.. note:: Each cilium-agent pod will create a CiliumEndpoint to represent its
          own inter-agent health-check endpoint. These are not pods in
          Kubernetes and are in the ``kube-system`` namespace. They are named as
          ``cilium-health-<node-name>``
