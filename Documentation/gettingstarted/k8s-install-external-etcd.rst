.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _admin_install_daemonset:
.. _k8s_install_standard:

*******************************
Installation with external etcd
*******************************

This guide walks you through the steps required to set up Cilium on Kubernetes
using an external etcd. Use of an external etcd provides better performance and
is suitable for larger environments. If you are looking for a simple
installation method to get started, refer to the section
:ref:`k8s_install_etcd_operator`.

Should you encounter any issues during the installation, please refer to the
:ref:`troubleshooting_k8s` section and / or seek help on :ref:`slack`.

.. _ds_deploy:

.. include:: requirements_intro.rst

Configure the External Etcd
===========================

When using an external kvstore, the address of the external kvstore needs to be
configured in the ConfigMap. Download the base YAML for the version of
Kubernetes you are using:

.. tabs::
  .. group-tab:: K8s 1.13

    .. parsed-literal::

      wget \ |SCM_WEB|\/examples/kubernetes/1.13/cilium-external-etcd.yaml

  .. group-tab:: K8s 1.12

    .. parsed-literal::

      wget \ |SCM_WEB|\/examples/kubernetes/1.12/cilium-external-etcd.yaml

  .. group-tab:: K8s 1.11

    .. parsed-literal::

      wget \ |SCM_WEB|\/examples/kubernetes/1.11/cilium-external-etcd.yaml

  .. group-tab:: K8s 1.10

    .. parsed-literal::

      wget \ |SCM_WEB|\/examples/kubernetes/1.10/cilium-external-etcd.yaml

  .. group-tab:: K8s 1.9

    .. parsed-literal::

      wget \ |SCM_WEB|\/examples/kubernetes/1.9/cilium-external-etcd.yaml

1. Open ``cilium-external-etcd.yaml`` and find the ``cilium-config`` ConfigMap
   and edit the ``endpoints:`` to include the list of all your etcd endpoints
   or a service IP that will load-balance to all etcd endpoints.

.. code:: bash

   etcd-config: |-
     ---
     endpoints:
     - https://etcd1.deathstar.empire:2379
     - https://etcd2.deathstar.empire:2379
     - https://etcd3.deathstar.empire:2379

2. Create a Kubernetes secret with the root certificate authority, and
   client-side key and certificate of etcd:

.. code:: bash

   kubectl create secret generic -n kube-system cilium-etcd-secrets \
        --from-file=etcd-ca=ca.crt \
        --from-file=etcd-client-key=client.key \
        --from-file=etcd-client-crt=client.crt

3. In case you are not using a TLS-enabled etcd, comment out the configuration
   options in the ConfigMap referring to the key locations like this:

.. code:: bash

    # In case you want to use TLS in etcd, uncomment the 'ca-file' line
    # and create a kubernetes secret by following the tutorial in
    # https://cilium.link/etcd-config
    #ca-file: '/var/lib/etcd-secrets/etcd-client-ca.crt'
    #
    # In case you want client to server authentication, uncomment the following
    # lines and create a kubernetes secret by following the tutorial in
    # https://cilium.link/etcd-config
    #key-file: '/var/lib/etcd-secrets/etcd-client.key'
    #cert-file: '/var/lib/etcd-secrets/etcd-client.crt'

Deploy Cilium
=============

.. code:: bash

    kubectl create -f cilium-external-etcd.yaml

Validate the Installation
=========================

Verify that a cilium pod was started on each of your worker nodes

.. code:: bash

    kubectl --namespace kube-system get ds cilium
    NAME            DESIRED   CURRENT   READY     NODE-SELECTOR   AGE
    cilium          4         4         4         <none>          2m

