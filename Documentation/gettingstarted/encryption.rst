.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _encryption:

*****************************
Transparent Encryption (beta)
*****************************

This guide explains how to configure Cilium to use IPSec based transparent
encryption using Kubernetes secrets to distribute the IPSec keys. After this
configuration is complete all traffic between Cilium
managed endpoints, as well as Cilium managed host traffic, will be encrypted
using IPSec. This guide uses Kubernetes secrets to distribute keys. Alternatively,
keys may be manually distributed but that is not shown here.

.. note::

    This is a beta feature. Please provide feedback and file a GitHub issue
    if you experience any problems.

.. note::

    Transparent encryption is currently subject to the following limitations:

    * Only works in tunnel mode
    * Not compatible with the etcd-operator
    
    Both limitations will be resolved in 1.4.1.

Generate & import the PSK
=========================

First create a yaml file for the IPSec keys to be stored as a Kubernetes
secret.  The ``cilium-ipsec-keys.yaml`` listed below gives an example.

.. parsed-literal::
  apiVersion: v1
  kind: Secret
  metadata:
    name: cilium-ipsec-keys
  type: Opaque
  stringData:

Next we will generate the necessary IPSec keys which will be distributed as a
Kubernetes secret using the ``cilium-ipsec-keys.yaml`` file. In this example we use
AES-CBC with HMAC-256 (hash based authentication code), but any of the supported
Linux algorithms may be used. To generate use the following

.. parsed-literal::
  KEY1=0x`dd if=/dev/urandom count=32 bs=1 2> /dev/null| xxd -p -c 64`
  KEY2=0x`dd if=/dev/urandom count=32 bs=1 2> /dev/null| xxd -p -c 64`
  echo "  keys: \\"hmac(sha256) $KEY1 cbc(aes) $KEY2\\"" >> cilium-ipsec-keys.yaml

.. parsed-literal::
  kubectl -n kube-system create -f cilium-ipsec-keys.yaml

The secret can be displayed with 'kubectl -n kube-system get secret' and will be
listed as 'cilium-ipsec-keys'.

.. parsed-literal::
 $ kubectl -n kube-system get secrets cilium-ipsec-keys
 NAME                                             TYPE                                  DATA   AGE
 cilium-ipsec-keys                                Opaque                                1      105m

Enable Encryption in Cilium
===========================

First step is to download the Cilium Kubernetes descriptor:

.. tabs::
  .. group-tab:: K8s 1.13

    .. parsed-literal::

      curl -LO \ |SCM_WEB|\/examples/kubernetes/1.13/cilium-ds.yaml

  .. group-tab:: K8s 1.12

    .. parsed-literal::

      curl -LO \ |SCM_WEB|\/examples/kubernetes/1.12/cilium-ds.yaml

  .. group-tab:: K8s 1.11

    .. parsed-literal::

      curl -LO \ |SCM_WEB|\/examples/kubernetes/1.11/cilium-ds.yaml

  .. group-tab:: K8s 1.10

    .. parsed-literal::

      curl -LO \ |SCM_WEB|\/examples/kubernetes/1.10/cilium-ds.yaml

  .. group-tab:: K8s 1.9

    .. parsed-literal::

      curl -LO \ |SCM_WEB|\/examples/kubernetes/1.9/cilium-ds.yaml

  .. group-tab:: K8s 1.8

    .. parsed-literal::

      curl -LO \ |SCM_WEB|\/examples/kubernetes/1.8/cilium-ds.yaml

You can also use your existing definition DaemonSet running in your cluster:

.. code:: bash

    kubectl -n kube-system get ds cilium -o yaml > cilium-ds.yaml

To enable encryption in Cilium, we use a patch file to update the configuration
with the required cilium-agent options and included IPSec keys.

.. parsed-literal::
  metadata:
    namespace: kube-system
  spec:
    template:
      spec:
        containers:
        - name: cilium-agent
          args:
          - "--debug=$(CILIUM_DEBUG)"
          - "--kvstore=etcd"
          - "--kvstore-opt=etcd.config=/var/lib/etcd-config/etcd.config"
          - "--enable-ipsec"
          - "--ipsec-key-file=/etc/ipsec/keys"
          volumeMounts:
            - name: cilium-ipsec-secrets
              mountPath: /etc/ipsec
        volumes:
        - name: cilium-ipsec-secrets
          secret:
            secretName: cilium-ipsec-keys

The above shows the ``cilium-ipsec.yaml`` used with the following ``kubectl
patch`` command:

.. parsed-literal::
  kubectl patch --filename='cilium-ds.yaml' --patch "$(cat cilium-ipsec.yaml)" --local -o yaml > cilium-ipsec-ds.yaml

Finally, apply the file,

.. parsed-literal::
  kubectl apply -f cilium-ipsec-ds.yaml

At this point the Cilium managed nodes will be using IPSec for all traffic. For further
information on Cilium's transparent encryption, see :ref:`arch_guide`.

Disabling Encryption
====================

To disable the encryption, edit the DaemonSet and remove the ``--enable-ipsec``
argument.
