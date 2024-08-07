.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _encryption_ipsec:

****************************
IPsec Transparent Encryption
****************************

This guide explains how to configure Cilium to use IPsec based transparent
encryption using Kubernetes secrets to distribute the IPsec keys. After this
configuration is complete all traffic between Cilium-managed endpoints, as well
as Cilium-managed host traffic, will be encrypted using IPsec. This guide uses
Kubernetes secrets to distribute keys. Alternatively, keys may be manually
distributed, but that is not shown here.

Packets are not encrypted when they are destined to the same node from which
they were sent. This behavior is intended. Encryption would provide no benefits
in that case, given that the raw traffic can be observed on the node anyway.

Generate & Import the PSK
=========================

First, create a Kubernetes secret for the IPsec configuration to be stored. The
example below demonstrates generation of the necessary IPsec configuration
which will be distributed as a Kubernetes secret called ``cilium-ipsec-keys``.
A Kubernetes secret should consist of one key-value pair where the key is the
name of the file to be mounted as a volume in cilium-agent pods, and the
value is an IPsec configuration in the following format::

    key-id encryption-algorithms PSK-in-hex-format key-size

.. note::

    ``Secret`` resources need to be deployed in the same namespace as Cilium!
    In our example, we use ``kube-system``.

In the example below, GCM-128-AES is used. However, any of the algorithms
supported by Linux may be used. To generate the secret, you may use the
following command:

.. code-block:: shell-session

    $ kubectl create -n kube-system secret generic cilium-ipsec-keys \
        --from-literal=keys="3+ rfc4106(gcm(aes)) $(echo $(dd if=/dev/urandom count=20 bs=1 2> /dev/null | xxd -p -c 64)) 128"

.. attention::

    The ``+`` sign in the secret is mandatory since v1.16. It will force the
    use of per-tunnel IPsec keys. The former global IPsec keys are considered
    insecure (cf. `GHSA-pwqm-x5x6-5586`_).

.. _GHSA-pwqm-x5x6-5586: https://github.com/cilium/cilium/security/advisories/GHSA-pwqm-x5x6-5586

The secret can be seen with ``kubectl -n kube-system get secrets`` and will be
listed as ``cilium-ipsec-keys``.

.. code-block:: shell-session

    $ kubectl -n kube-system get secrets cilium-ipsec-keys
    NAME                TYPE     DATA   AGE
    cilium-ipsec-keys   Opaque   1      176m

Enable Encryption in Cilium
===========================

.. tabs::

    .. group-tab:: Cilium CLI

       If you are deploying Cilium with the Cilium CLI, pass the following
       options:

       .. parsed-literal::

          cilium install |CHART_VERSION| \
             --set encryption.enabled=true \
             --set encryption.type=ipsec

    .. group-tab:: Helm

       If you are deploying Cilium with Helm by following
       :ref:`k8s_install_helm`, pass the following options:

       .. parsed-literal::

           helm install cilium |CHART_RELEASE| \\
             --namespace kube-system \\
             --set encryption.enabled=true \\
             --set encryption.type=ipsec

       ``encryption.enabled`` enables encryption of the traffic between
       Cilium-managed pods. ``encryption.type`` specifies the encryption method
       and can be omitted as it defaults to ``ipsec``.

.. attention::

   When using Cilium in any direct routing configuration, ensure that the
   native routing CIDR is set properly. This is done using
   ``--ipv4-native-routing-cidr=CIDR`` with the CLI or ``--set
   ipv4NativeRoutingCIDR=CIDR`` with Helm.

At this point the Cilium managed nodes will be using IPsec for all traffic. For further
information on Cilium's transparent encryption, see :ref:`ebpf_datapath`.

Dependencies
============

When L7 proxy support is enabled (``--enable-l7-proxy=true``), IPsec requires that the
DNS proxy operates in transparent mode (``--dnsproxy-enable-transparent-mode=true``).

Encryption interface
--------------------

An additional argument can be used to identify the network-facing interface.
If direct routing is used and no interface is specified, the default route
link is chosen by inspecting the routing tables. This will work in many cases,
but depending on routing rules, users may need to specify the encryption
interface as follows:

.. tabs::

    .. group-tab:: Cilium CLI

       .. parsed-literal::

          cilium install |CHART_VERSION| \
             --set encryption.enabled=true \
             --set encryption.type=ipsec \
             --set encryption.ipsec.interface=ethX

    .. group-tab:: Helm

       .. code-block:: shell-session

           --set encryption.ipsec.interface=ethX

Validate the Setup
==================

Run a ``bash`` shell in one of the Cilium pods with
``kubectl -n kube-system exec -ti ds/cilium -- bash`` and execute the following
commands:

1. Install tcpdump

   .. code-block:: shell-session

       $ apt-get update
       $ apt-get -y install tcpdump

2. Check that traffic is encrypted. In the example below, this can be verified
   by the fact that packets carry the IP Encapsulating Security Payload (ESP).
   In the example below, ``eth0`` is the interface used for pod-to-pod
   communication. Replace this interface with e.g. ``cilium_vxlan`` if
   tunneling is enabled.

   .. code-block:: shell-session

       tcpdump -l -n -i eth0 esp
       tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
       listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
       15:16:21.626416 IP 10.60.1.1 > 10.60.0.1: ESP(spi=0x00000001,seq=0x57e2), length 180
       15:16:21.626473 IP 10.60.1.1 > 10.60.0.1: ESP(spi=0x00000001,seq=0x57e3), length 180
       15:16:21.627167 IP 10.60.0.1 > 10.60.1.1: ESP(spi=0x00000001,seq=0x579d), length 100
       15:16:21.627296 IP 10.60.0.1 > 10.60.1.1: ESP(spi=0x00000001,seq=0x579e), length 100
       15:16:21.627523 IP 10.60.0.1 > 10.60.1.1: ESP(spi=0x00000001,seq=0x579f), length 180
       15:16:21.627699 IP 10.60.1.1 > 10.60.0.1: ESP(spi=0x00000001,seq=0x57e4), length 100
       15:16:21.628408 IP 10.60.1.1 > 10.60.0.1: ESP(spi=0x00000001,seq=0x57e5), length 100

.. _ipsec_key_rotation:

Key Rotation
============

.. attention::

   Key rotations should not be performed during upgrades and downgrades. That
   is, all nodes in the cluster (or clustermesh) should be on the same Cilium
   version before rotating keys.

To replace cilium-ipsec-keys secret with a new key:

.. code-block:: shell-session

    KEYID=$(kubectl get secret -n kube-system cilium-ipsec-keys -o go-template --template={{.data.keys}} | base64 -d | grep -oP "^\d+")
    if [[ $KEYID -ge 15 ]]; then KEYID=0; fi
    data=$(echo "{\"stringData\":{\"keys\":\"$((($KEYID+1)))+ "rfc4106\(gcm\(aes\)\)" $(echo $(dd if=/dev/urandom count=20 bs=1 2> /dev/null| xxd -p -c 64)) 128\"}}")
    kubectl patch secret -n kube-system cilium-ipsec-keys -p="${data}" -v=1

During transition the new and old keys will be in use. The Cilium agent keeps
per endpoint data on which key is used by each endpoint and will use the correct
key if either side has not yet been updated. In this way encryption will work as
new keys are rolled out.

The ``KEYID`` environment variable in the above example stores the current key
ID used by Cilium. The key variable is a uint8 with value between 1 and 15
included and should be monotonically increasing every re-key with a rollover
from 15 to 1. The Cilium agent will default to ``KEYID`` of zero if its not
specified in the secret.

If you are using Cluster Mesh, you must apply the key rotation procedure
to all clusters in the mesh. You might need to increase the transition time to
allow for the new keys to be deployed and applied across all clusters,
which you can do with the agent flag ``ipsec-key-rotation-duration``.

Monitoring
==========

When monitoring network traffic on a node with IPSec enabled, it is normal to observe
in the same interface both the outer packet (node-to-node) carrying the ESP-encrypted
payload and then the decrypted inner packet (pod-to-pod). This occurs as, once a packet
is decrypted, it is recirculated back to the same interface for further processing.
Therefore, depending on the ``tcpdump`` filter applied, the capture might differ, but this
**does not** indicate that encryption is not functioning correctly. In particular, to observe:
    
1. Only the encrypted packet: use the filter ``esp``.
2. Only the decrypted packet: use a specific filter for the protocol used by the pods (such as ``icmp`` for ping).
3. Both encrypted and decrypted packets: use no filter or combine the filters for both (such as ``esp or icmp``).

The following capture was taken on a Kind cluster with no filter applied (replace ``eth0``
with ``cilium_vxlan`` if tunneling is enabled). The nodes have IP addresses ``10.244.2.92``
and ``10.244.1.148``, while the pods have IP addresses ``10.244.2.189`` and ``10.244.1.7``,
using ping (ICMP) for communication.

.. code-block:: shell-session

  tcpdump -l -n -i eth0
  tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
  listening on cilium_vxlan, link-type EN10MB (Ethernet), snapshot length 262144 bytes
  09:22:16.379908 IP 10.244.2.92 > 10.244.1.148: ESP(spi=0x00000003,seq=0x8), length 120
  09:22:16.379908 IP 10.244.2.189 > 10.244.1.7: ICMP echo request, id 33, seq 1, length 64


Troubleshooting
===============

 * If the ``cilium`` Pods fail to start after enabling encryption, double-check if
   the IPsec ``Secret`` and Cilium are deployed in the same namespace together.

 * Check for ``level=warning`` and ``level=error`` messages in the Cilium log files

   * If there is a warning message similar to ``Device eth0 does not exist``,
     use ``--set encryption.ipsec.interface=ethX`` to set the encryption
     interface.

 * Run ``cilium-dbg encrypt status`` in the Cilium Pod:

   .. code-block:: shell-session

       $ cilium-dbg encrypt status
       Encryption: IPsec
       Decryption interface(s): eth0, eth1, eth2
       Keys in use: 4
       Max Seq. Number: 0x1e3/0xffffffff
       Errors: 0

   If the error counter is non-zero, additional information will be displayed
   with the specific errors the kernel encountered. If the sequence number
   reaches its maximum value, it will also result in errors.

   The number of keys in use should be 2 per remote node per enabled IP family.
   During a key rotation, it can double to 4 per remote node per IP family. For
   example, in a 3-nodes cluster, if both IPv4 and IPv6 are enabled and no key
   rotation is ongoing, there should be 8 keys in use on each node.

   The list of decryption interfaces should have all native devices that may
   receive pod traffic (for example, ENI interfaces).

All XFRM errors correspond to a packet drop in the kernel. The following
details operational mistakes and expected behaviors that can cause those
errors.

 * When a node reboots, the key used to communicate with it is expected to
   change on other nodes. You may notice the ``XfrmInNoStates`` and
   ``XfrmOutNoStates`` counters increase while the new node key is being
   deployed.

 * If the sequence number reaches its maximum value for any XFRM OUT state, it
   will result in packet drops and XFRM errors of type
   ``XfrmOutStateSeqError``. A key rotation resets all sequence numbers.
   Rotate keys frequently to avoid this issue.

 * After a key rotation, if the old key is cleaned up before the
   configuration of the new key is installed on all nodes, it results in
   ``XfrmInNoStates`` errors. The old key is removed from nodes after a default
   interval of 5 minutes by default. By default, all agents watch for key
   updates and update their configuration within 1 minute after the key is
   changed, leaving plenty of time before the old key is removed. If you expect
   the key rotation to take longer for some reason (for example, in the case of
   Cluster Mesh where several clusters need to be updated), you can increase the
   delay before cleanup with agent flag ``ipsec-key-rotation-duration``.

 * ``XfrmInStateProtoError`` errors can happen for the following reasons:
   1. If the key is updated without incrementing the SPI (also called ``KEYID``
   in :ref:`ipsec_key_rotation` instructions above). It can be fixed by
   performing a new key rotation, properly.
   2. If the source node encrypts the packets using a different anti-replay seq
   from the anti-reply oseq on the destination node. This can be fixed by
   properly performing a new key rotation.

 * ``XfrmFwdHdrError`` and ``XfrmInError`` happen when the kernel fails to
   lookup the route for a packet it decrypted. This can legitimately happen
   when a pod was deleted but some packets are still in transit. Note these
   errors can also happen under memory pressure when the kernel fails to
   allocate memory.

 * ``XfrmInStateInvalid`` can happen on rare occasions if packets are received
   while an XFRM state is being deleted. XFRM states get deleted as part of
   node scale-downs and for some upgrades and downgrades.

 * The following table documents the known explanations for several XFRM errors
   that were observed in the past. Many other error types exist, but they are
   usually for Linux subfeatures that Cilium doesn't use (e.g., XFRM
   expiration).

   =======================  ==================================================
   Error                    Known explanation
   =======================  ==================================================
   XfrmInError              The kernel (1) decrypted and tried to route a
                            packet for a pod that was deleted or (2) failed to
                            allocate memory.
   XfrmInNoStates           Bug in the XFRM configuration for decryption.
   XfrmInStateProtoError    There is a key or anti-replay seq mismatch between
                            nodes.
   XfrmInStateInvalid       A received packet matched an XFRM state that is
                            being deleted.
   XfrmInTmplMismatch       Bug in the XFRM configuration for decryption.
   XfrmInNoPols             Bug in the XFRM configuration for decryption.
   XfrmInPolBlock           Explicit drop, not used by Cilium.
   XfrmOutNoStates          Bug in the XFRM configuration for encryption.
   XfrmOutStateSeqError     The sequence number of an encryption XFRM
                            configuration reached its maximum value.
   XfrmOutPolBlock          Cilium dropped packets that would have otherwise
                            left the node in plain-text.
   XfrmFwdHdrError          The kernel (1) decrypted and tried to route a
                            packet for a pod that was deleted or (2) failed to
                            allocate memory.
   =======================  ==================================================

 * In addition to the above XFRM errors, packet drops of type ``No node ID
   found`` (code 197) may also occur under normal operations. These drops can
   happen if a pod attempts to send traffic to a pod on a new node for which
   the Cilium agent didn't yet receive the CiliumNode object or to a pod on a
   node that was recently deleted. It can also happen if the IP address of the
   destination node changed and the agent didn't receive the updated CiliumNode
   object yet. In both cases, the IPsec configuration in the kernel isn't ready
   yet, so Cilium drops the packets at the source. These drops will stop once
   the CiliumNode information is propagated across the cluster.

Disabling Encryption
====================

To disable the encryption, regenerate the YAML with the option
``encryption.enabled=false``

Limitations
===========

    * Transparent encryption is not currently supported when chaining Cilium on
      top of other CNI plugins. For more information, see :gh-issue:`15596`.
    * :ref:`HostPolicies` are not currently supported with IPsec encryption.
    * IPsec encryption does not work when using :ref:`kube-proxy replacement
      <kubeproxy-free>`. Be aware that other features may require a kube-proxy
      free environment in which case they are mutual exclusive.
    * IPsec encryption is not currently supported in combination with IPv6-only clusters.
    * IPsec encryption is not supported on clusters or clustermeshes with more
      than 65535 nodes.
    * Decryption with Cilium IPsec is limited to a single CPU core per IPsec
      tunnel. This may affect performance in case of high throughput between
      two nodes.
