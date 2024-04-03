.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_mutual_authentication:

****************************
Mutual Authentication (Beta)
****************************

.. note::

    This is a beta feature. Please provide feedback and file a GitHub issue if
    you experience any problems.

    This feature is still incomplete, see :ref:`mutual_auth_roadmap` below for more details.

Mutual Authentication and mTLS Background
#########################################

Mutual Transport Layer Security (mTLS) is a mechanism that ensures the authenticity, integrity, 
and confidentiality of data exchanged between two entities over a network.

Unlike traditional TLS, which involves a one-way authentication process where the client verifies the 
server's identity, mutual TLS adds an additional layer of security by requiring both the client and the server to authenticate each other.

Mutual TLS aims at providing authentication, confidentiality and integrity to service-to-service communications. 

Mutual Authentication in Cilium
###############################

Cilium's mTLS-based Mutual Authentication support brings the mutual authentication handshake out-of-band for regular connections.

For Cilium to meet most of the common requirements for service-to-service authentication and encryption, users must enable encryption.

.. Note::

    Cilium's encryption features,  :ref:`encryption_wg` and :ref:`encryption_ipsec`, can be enabled 
    to automatically create and maintain encrypted connections between Pods.

To address the challenge of identity verification in dynamic and heterogeneous environments, 
mutual authentication requires a framework secure identity verification for distributed systems.

.. Note::

    To learn more about the the Mutual Authentication architecture for the Cilium Service Mesh, read the `CFP <https://github.com/cilium/design-cfps/blob/main/cilium/CFP-22215-mutual-auth-for-service-mesh.md>`_.

.. _identity_management:

Identity Management
###################

In Cilium's current mutual authentication support, identity management is provided through the use of 
SPIFFE (Secure Production Identity Framework for Everyone).

SPIFFE benefits
---------------
Here are some of the benefits provided by `SPIFFE <https://spiffe.io/>`_ :

- Trustworthy identity issuance: SPIFFE provides a standardized mechanism for issuing and managing identities. 
  It ensures that each service in a distributed system receives a unique and verifiable identity, even in dynamic environments where services may scale up or down frequently.
- Identity attestation: SPIFFE allows services to prove their identities through attestation. 
  It ensures that services can demonstrate their authenticity and integrity by providing verifiable evidence about their identity, like digital signatures or cryptographic proofs.
- Dynamic and scalable environments: SPIFFE addresses the challenges of identity management in dynamic environments. 
  It supports automatic identity issuance, rotation, and revocation, which are critical in cloud-native architectures where services may be constantly deployed, updated, or retired.

Cilium and SPIFFE
-----------------

SPIFFE provides an API model that allows workloads to request an identity from a central server. In our case, a workload means the same thing that a Cilium Security Identity does - a set of pods described by a label set. 
A SPIFFE identity is a subclass of URI, and looks something like this: ``spiffe://trust.domain/path/with/encoded/info``.

There are two main parts of a SPIFFE setup:

- A central SPIRE server, which forms the root of trust for the trust domain.
- A per-node SPIRE agent, which first gets its own identity from the SPIRE server, then validates the identity requests of workloads running on its node.

When a workload wants to get its identity, usually at startup, it connects to the local SPIRE agent using the SPIFFE workload API, and describes itself to the agent.

The SPIRE agent then checks that the workload is really who it says it is, and then connects to the SPIRE server and attests that the workload is requesting an identity, and that the request is valid. 

The SPIRE agent checks a number of things about the workload, that the pod is actually running on the node it's coming from, that the labels match, and so on. 

Once the SPIRE agent has requested an identity from the SPIRE server, it passes it back to the workload in the SVID (SPIFFE Verified Identity Document) format.
This document includes a TLS keypair in the X.509 version. 

In the usual flow for SPIRE, the workload requests its own information from the SPIRE server. 
In Cilium's support for SPIFFE, the Cilium agents get a common SPIFFE identity and can themselves ask for identities on behalf of other workloads.

This is demonstrated in the following example.

.. include:: installation.rst

Examples
########

Please refer to the following example on how to use and leverage
the mutual authentication feature:

.. toctree::
   :maxdepth: 1
   :glob:

   mutual-authentication-example

Limitations
###########
* Cilium Mutual Authentication is still in development and considered beta. Several planned security features have not been implemented yet, see below for details.
* Cilium's Mutual authentication has only been validated with SPIRE, the production-ready implementation of SPIFFE.
  As Cilium uses SPIFFE APIs, it's possible that other SPIFFE implementations may work.
  However, Cilium is currently only tested with the supplied SPIRE install, and using any other SPIFFE implementation is currently not supported.
* There is no current option to build a single trust domain across multiple clusters for combining Cluster Mesh and Service Mesh.
  Therefore clusters connected in a Cluster Mesh are not currently compatible with Mutual Authentication.
* The current support of mutual authentication only works within a Cilium-managed cluster and is not compatible with an external mTLS solution.


.. _mutual_auth_roadmap:

Detailed Roadmap Status
#######################

The following table shows the roadmap status of the mutual authentication feature.
There are several work items outstanding before the feature is complete from a security model perspective.
For details, see the [roadmap issue](https://github.com/cilium/cilium/issues/28986).


+--------------------------------------------------+----------------------------------------------------------+
| SPIFFE/SPIRE Integration                         | Beta                                                     |
+--------------------------------------------------+----------------------------------------------------------+
| Authentication API for agent                     | Beta                                                     |
+--------------------------------------------------+----------------------------------------------------------+
| mTLS handshake between agents                    | Beta                                                     |
+--------------------------------------------------+----------------------------------------------------------+
| Auth cache to enable per-identity handshake      | Beta                                                     |
+--------------------------------------------------+----------------------------------------------------------+
| CiliumNetworkPolicy support                      | Beta                                                     |
+--------------------------------------------------+----------------------------------------------------------+
| Integrate with Wireguard                         | TODO                                                     |
+--------------------------------------------------+----------------------------------------------------------+
| Per-connection handshake                         | TODO                                                     |
+--------------------------------------------------+----------------------------------------------------------+
| Sync ipcache with auth data                      | TODO                                                     |
+--------------------------------------------------+----------------------------------------------------------+
| Detailed documentation of security model         | TODO                                                     |
+--------------------------------------------------+----------------------------------------------------------+
| Conduct penetration test of model                | TODO                                                     |
+--------------------------------------------------+----------------------------------------------------------+
| Minimize packet drops                            | TODO                                                     |
+--------------------------------------------------+----------------------------------------------------------+
| Use auth secret for network encryption           | TODO                                                     |
+--------------------------------------------------+----------------------------------------------------------+
| Review maturity and consider for stable          | TODO                                                     |
+--------------------------------------------------+----------------------------------------------------------+
