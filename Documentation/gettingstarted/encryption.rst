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

Validate the Setup
==================

Run a ``bash`` shell in one of the Cilium pods with ``kubectl -n kube-system
exec -ti cilium-7cpsm -- bash`` and execute the following commands:

1. Install tcpdump

.. code:: bash

    apt-get update
    apt-get -y install tcpdump

2. Check that traffic is encrypted:

.. code:: bash

    tcpdump -n -i cilium_vxlan
    tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
    listening on cilium_vxlan, link-type EN10MB (Ethernet), capture size 262144 bytes
    15:16:21.626416 IP 10.60.1.1 > 10.60.0.1: ESP(spi=0x00000001,seq=0x57e2), length 180
    15:16:21.626473 IP 10.60.1.1 > 10.60.0.1: ESP(spi=0x00000001,seq=0x57e3), length 180
    15:16:21.627167 IP 10.60.0.1 > 10.60.1.1: ESP(spi=0x00000001,seq=0x579d), length 100
    15:16:21.627296 IP 10.60.0.1 > 10.60.1.1: ESP(spi=0x00000001,seq=0x579e), length 100
    15:16:21.627523 IP 10.60.0.1 > 10.60.1.1: ESP(spi=0x00000001,seq=0x579f), length 180
    15:16:21.627699 IP 10.60.1.1 > 10.60.0.1: ESP(spi=0x00000001,seq=0x57e4), length 100
    15:16:21.628408 IP 10.60.1.1 > 10.60.0.1: ESP(spi=0x00000001,seq=0x57e5), length 100


Troubleshooting
===============

 * Make sure that the Cilium pods have kvstore connectivity:
   
   .. code:: bash

      cilium status
      KVStore:                Ok   etcd: 1/1 connected: http://127.0.0.1:31079 - 3.3.2 (Leader)
      [...]

 * Check for ``level=warning`` and ``level=error`` messages in the Cilium log files
 * Run a ``bash`` in a Cilium and validate the following:
 
   * Routing rules matching on fwmark:

     .. code:: bash
        
        ip rule list
        1:	from all fwmark 0xd00/0xf00 lookup 200
        1:	from all fwmark 0xe00/0xf00 lookup 200
        [...]

   * Content of routing table 200
   
     .. code:: bash

        ip route list table 200
        local 10.60.0.0/24 dev cilium_vxlan proto 50 scope host
        10.60.1.0/24 via 10.60.0.1 dev cilium_host

   * XFRM policy:

     .. code:: bash

        ip xfrm p
        src 10.60.1.1/24 dst 10.60.0.1/24
                dir fwd priority 0
                mark 0xd00/0xf00
                tmpl src 10.60.1.1 dst 10.60.0.1
                        proto esp spi 0x00000001 reqid 1 mode tunnel
        src 10.60.1.1/24 dst 10.60.0.1/24
                dir in priority 0
                mark 0xd00/0xf00
                tmpl src 10.60.1.1 dst 10.60.0.1
                        proto esp spi 0x00000001 reqid 1 mode tunnel
        src 10.60.0.1/24 dst 10.60.1.1/24
                dir out priority 0
                mark 0xe00/0xf00
                tmpl src 10.60.0.1 dst 10.60.1.1
                        proto esp spi 0x00000001 reqid 1 mode tunnel

   * XFRM state:

     .. code:: bash

        ip xfrm s
        src 10.60.0.1 dst 10.60.1.1
                proto esp spi 0x00000001 reqid 1 mode tunnel
                replay-window 0
                auth-trunc hmac(sha256) 0x6162636465666768696a6b6c6d6e6f70717273747576777a797a414243444546 96
                enc cbc(aes) 0x6162636465666768696a6b6c6d6e6f70717273747576777a797a414243444546
                anti-replay context: seq 0x0, oseq 0xe0c0, bitmap 0x00000000
                sel src 0.0.0.0/0 dst 0.0.0.0/0
        src 10.60.1.1 dst 10.60.0.1
                proto esp spi 0x00000001 reqid 1 mode tunnel
                replay-window 0
                auth-trunc hmac(sha256) 0x6162636465666768696a6b6c6d6e6f70717273747576777a797a414243444546 96
                enc cbc(aes) 0x6162636465666768696a6b6c6d6e6f70717273747576777a797a414243444546
                anti-replay context: seq 0x0, oseq 0x0, bitmap 0x00000000
                sel src 0.0.0.0/0 dst 0.0.0.0/0

Disabling Encryption
====================

To disable the encryption, edit the DaemonSet and remove the ``--enable-ipsec``
argument.
