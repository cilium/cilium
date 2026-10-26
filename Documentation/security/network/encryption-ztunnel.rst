.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _encryption_ztunnel:

*************************************
Ztunnel Transparent Encryption (Beta)
*************************************

.. include:: /beta.rst

This guide explains how to configure Cilium to use ztunnel for transparent
encryption and mutual TLS (mTLS) authentication between Cilium-managed endpoints.
ztunnel is a purpose-built per-node proxy that provides transparent Layer 4 mTLS
encryption and authentication for pod-to-pod communication.

When ztunnel is enabled in Cilium, the agent running on each cluster node
establishes a control plane connection with the local ztunnel proxy. Cilium
enrolls pods into the mesh on a per-namespace basis, allowing fine-grained
control over which workloads participate in mTLS encryption. Enrolled pods have
their traffic transparently redirected to the ztunnel proxy using iptables rules
configured in their network namespace, where the traffic is encrypted and
authenticated using mutual TLS before being sent to the destination.


Generating secrets for authentication
=====================================

Cilium's ztunnel integration requires a set of private keys and accompanying
to certificates be present via Kubernetes secrets. This follows the same pattern
as IPsec key injections.

These keys can be generated with the following bash script prior to deploying
Cilium.

.. literalinclude:: ../../../examples/kubernetes-ztunnel/generate-secrets.sh
   :language: bash

The 'bootstrap' keys are used to secure the connection between ztunnel and
Cilium's xDS and certificate server implementation.

The 'ca' keys are used as the root certificate for creating in-memory and
ephemeral client certificates on ztunnel's request.

Enable ztunnel in Cilium
========================

Before you install Cilium with ztunnel enabled, ensure that:

* The necessary Kubernetes secrets are available.
* Cluster Mesh is not enabled (ztunnel is currently not compatible with Cluster Mesh).

.. tabs::

    .. group-tab:: Cilium CLI

       If you are deploying Cilium with the Cilium CLI, pass the following
       options:

       .. parsed-literal::

          cilium install --version |CHART_VERSION| \\
             --set encryption.enabled=true \\
             --set encryption.type=ztunnel

    .. group-tab:: Helm

       If you are deploying Cilium with Helm by following
       :ref:`k8s_install_helm`, pass the following options:

       .. parsed-literal::

           helm install cilium |CHART_RELEASE| \\
             --namespace kube-system \\
             --set encryption.enabled=true \\
             --set encryption.type=ztunnel


Enrolling Namespaces
====================

After enabling ztunnel in Cilium, you need to explicitly enroll namespaces to
enable mTLS encryption for their workloads. This is done by applying a label
to the namespace:

.. code-block:: shell-session

    kubectl label namespace <namespace-name> io.cilium/mtls-enabled=true

To verify that a namespace is enrolled:

.. code-block:: shell-session

    kubectl get namespace <namespace-name> --show-labels

When a namespace is enrolled:

* All existing pods in the namespace (except ztunnel pods themselves) are enrolled
* Iptables rules are configured in each pod's network namespace for traffic redirection
* Pod metadata is sent to the ztunnel proxy via the ZDS protocol
* Future pods created in the namespace are automatically enrolled

To disenroll a namespace:

.. code-block:: shell-session

    kubectl label namespace <namespace-name> io.cilium/mtls-enabled-

This will:

#. Disenroll all pods in the namespace from ztunnel
#. Remove the iptables rules from each pod's network namespace
#. Notify ztunnel to stop processing traffic for those workloads

Validate the Setup
==================

#. Check that ztunnel has been enabled:

   .. code-block:: shell-session

      kubectl -n kube-system describe cm cilium-config | grep enable-ztunnel -A2

   You should see output indicating that ztunnel encryption is enabled.

#. Check which namespaces are enrolled:

   .. code-block:: shell-session

      kubectl get namespaces -l io.cilium/mtls-enabled=true

   This shows all namespaces labeled for ztunnel enrollment.

   To verify that these namespaces are actually enrolled in the StateDB table:

   .. code-block:: shell-session

      kubectl exec -n kube-system ds/cilium -- cilium-dbg statedb dump | jq '.["mtls-enrolled-namespaces"]'

   The results of this query should show which namespaces have been successfully
   processed by the enrollment reconciler.

#. Run a ``bash`` shell in one of the Cilium pods hosting a mtls-enrolled pod with
   ``kubectl -n kube-system exec -ti pod/<cilium-pod-hosting-mtls-pod> -- bash``
   and execute the following commands:

   Install tcpdump

   .. code-block:: shell-session

       $ apt-get update
       $ apt-get -y install tcpdump

   Check that traffic is encrypted. In the example below, this can be verified
   by the fact that packets will have a destination port of 15008 (HBONE).
   In the example below, ``eth0`` is the interface used for pod-to-pod
   communication. Replace this interface with e.g. ``cilium_vxlan`` if
   tunneling is enabled.

   .. code-block:: shell-session

       tcpdump -i eth0 port 15008
       tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
       listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
       13:00:06.982499 IP 10.244.1.95.15008 > 10.244.2.3.33446: ...
       13:00:06.982536 IP 10.244.2.3.33446 > 10.244.1.95.15008: ...
       13:00:06.982675 IP 10.244.2.3.33446 > 10.244.1.95.15008: ...

.. _encryption_ztunnel_spire_crds:

Registering SPIRE entries with Kubernetes resources
===================================================

When ztunnel obtains workload certificates from the SPIRE installation of the
chart (``encryption.ztunnel.ca.type=spire``,
``authentication.mutual.spire.enabled=true`` and
``authentication.mutual.spire.install.enabled=true``), the Cilium operator
registers a SPIRE entry for each service account of the enrolled namespaces
through the SPIRE Entry API, and the ``cilium-init`` container of the SPIRE
server registers the SPIRE agents, the Cilium agent and the Cilium operator.

With ``encryption.ztunnel.spire.useCRD=true``, a spire-controller-manager
sidecar of the SPIRE server registers these identities from Kubernetes
resources instead:

* A ClusterSPIFFEID gives each pod of the enrolled namespaces the SPIFFE ID
  ``spiffe://<trust domain>/ns/<namespace>/sa/<service account>``. The
  operator stops registering entries.
* ClusterStaticEntries register the SPIRE agents and the ``cilium-agent``,
  ``cilium-operator`` and ``ztunnel`` identities. They replace the
  ``cilium-init`` container.
* The SPIRE agents authorize ztunnel to request workload certificates through
  the SPIRE Delegated Identity API. Because the SPIRE agents only read their
  configuration at startup, the chart restarts them whenever it changes.

The sidecar only manages entries whose IDs start with ``cilium.``: it creates,
updates and deletes them to match the ClusterSPIFFEIDs and ClusterStaticEntries
of the class ``encryption.ztunnel.spire.className``, and leaves all other
entries alone.

The sidecar reports its progress in the status of the resources.
``status.stats`` of a ClusterSPIFFEID counts the selected pods, the entries to
set and the entries that failed. ``status.rendered`` and ``status.masked`` of a
ClusterStaticEntry show whether its entry rendered and whether another resource
declares the same entry. ``status.set`` is only ``true`` after the
reconciliation that created the entry and returns to ``false`` at the next one,
and it never becomes ``true`` for an entry that the sidecar adopted, so it does
not show whether the entry exists: check the entries in the SPIRE server
instead.

Prerequisites
-------------

The chart does not install the ClusterSPIFFEID and ClusterStaticEntry custom
resource definitions (CRDs). Before you install Cilium with ``useCRD`` or
enable it on an existing installation, install the CRDs of the
spire-controller-manager version that the chart deploys, v0.6.2 by default:

.. code-block:: shell-session

   kubectl apply --server-side \
     -f https://raw.githubusercontent.com/spiffe/spire-controller-manager/v0.6.2/config/crd/bases/spire.spiffe.io_clusterspiffeids.yaml \
     -f https://raw.githubusercontent.com/spiffe/spire-controller-manager/v0.6.2/config/crd/bases/spire.spiffe.io_clusterstaticentries.yaml

If the cluster does not serve both resources, the installation or upgrade fails
and prints the command that installs the missing CRDs.
``encryption.ztunnel.spire.trustCRDsExist=true`` skips this check, for example
when you render the chart without access to the cluster. It does not install
the CRDs, and Helm cannot apply the release until both exist.

Enabling useCRD on an existing installation
-------------------------------------------

The SPIRE server keeps the entries that ``cilium-init`` and the operator
registered, and the sidecar ignores them because their IDs do not start with
``cilium.``. Left in place, they cause two problems:

* The SPIRE server refuses to create an entry with the same SPIFFE ID, parent
  and selectors as an existing one. While the entries of ``cilium-init`` exist,
  and a ``spiffe://<trust domain>/ztunnel`` entry if you registered one by
  hand, the sidecar fails to create the ClusterStaticEntries with
  ``AlreadyExists`` errors and never manages these identities.
* The entries that the operator registered for the service accounts of the
  enrolled namespaces, parented to ``spiffe://<trust domain>/ztunnel``, remain
  valid. Pods then receive two certificates for the same identity, and a
  namespace that you withdraw from the mesh after the upgrade keeps an identity
  that SPIRE still issues.

Replace these entries while you upgrade. The following commands use ``jq``,
``uuidgen`` and the default namespaces and service accounts of the chart:
adjust them to your Helm values.

#. Install the CRDs as described in the prerequisites.

#. Define a helper that runs the SPIRE server CLI, read the trust domain of
   your installation, and save the current entries for reference:

   .. code-block:: bash

      spire_server() {
        kubectl -n cilium-spire exec spire-server-0 -c spire-server -- \
          /opt/spire/bin/spire-server "$@"
      }
      TRUST_DOMAIN=$(kubectl -n kube-system get configmap cilium-config \
        -o jsonpath='{.data.mesh-auth-spiffe-trust-domain}')
      AGENT_ID="spiffe://${TRUST_DOMAIN}/ns/cilium-spire/sa/spire-agent"
      spire_server entry show -output json > spire-entries-before.json

#. Replace the entries of ``cilium-init``, and the ``ztunnel`` entry if you
   registered one by hand, with identical entries whose IDs start with
   ``cilium.``. The sidecar adopts them when it starts. ``cilium-init`` keeps
   running until the upgrade, but it does not recreate an entry while an
   identical one exists.

   .. code-block:: bash

      replace_entry() {
        spiffe_id=$1
        shift
        entries=$(spire_server entry show -spiffeID "${spiffe_id}" -output json)
        for id in $(jq -r '.entries[]?.id | select(startswith("cilium.") | not)' <<< "${entries}"); do
          spire_server entry delete -entryID "${id}"
        done
        if ! jq -e '.entries[]? | select(.id | startswith("cilium."))' <<< "${entries}" > /dev/null; then
          spire_server entry create -entryID "cilium.$(uuidgen)" -spiffeID "${spiffe_id}" "$@"
        fi
      }
      replace_entry "${AGENT_ID}" -node \
        -selector k8s_psat:agent_ns:cilium-spire \
        -selector k8s_psat:agent_sa:spire-agent
      replace_entry "spiffe://${TRUST_DOMAIN}/cilium-agent" -parentID "${AGENT_ID}" \
        -selector k8s:ns:kube-system -selector k8s:sa:cilium
      replace_entry "spiffe://${TRUST_DOMAIN}/cilium-operator" -parentID "${AGENT_ID}" \
        -selector k8s:ns:kube-system -selector k8s:sa:cilium-operator
      replace_entry "spiffe://${TRUST_DOMAIN}/ztunnel" -parentID "${AGENT_ID}" \
        -selector k8s:ns:kube-system -selector k8s:sa:ztunnel-cilium

   If ``entry create`` fails because a similar entry already exists,
   ``cilium-init`` recreated the old entry in the meantime: run the same
   ``replace_entry`` command again.

#. Upgrade Cilium with your Helm values and
   ``encryption.ztunnel.spire.useCRD=true``:

   .. parsed-literal::

      helm upgrade cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --values my-values.yaml \\
        --set encryption.ztunnel.spire.useCRD=true

   The SPIRE server restarts with the sidecar instead of ``cilium-init``, the
   operator stops registering entries, and the SPIRE agents restart to
   authorize ztunnel as a delegate. If you edited the ``spire-agent``
   ConfigMap by hand, for example to authorize ztunnel, and the release uses
   server-side apply, as releases installed with Helm 4 do, add
   ``--force-conflicts``. Otherwise Helm stops with a conflict on that
   ConfigMap after it applied some of the other resources.

#. Wait until the sidecar registered the pods of the enrolled namespaces:
   ``ENTRIES`` matches ``PODS`` and ``FAILURES`` is ``0``.

   .. code-block:: shell-session

      kubectl get clusterspiffeids -o custom-columns=NAME:.metadata.name,PODS:.status.stats.podsSelected,ENTRIES:.status.stats.entriesToSet,FAILURES:.status.stats.entryFailures

#. Delete the entries that the operator registered. They are parented to
   ``spiffe://<trust domain>/ztunnel`` and their IDs do not start with
   ``cilium.``:

   .. code-block:: bash

      spire_server entry show -parentID "spiffe://${TRUST_DOMAIN}/ztunnel" -output json |
        jq -r '.entries[]?.id | select(startswith("cilium.") | not)' |
        while read -r id; do
          spire_server entry delete -entryID "${id}"
        done

#. Check the result. The SPIRE agents, ``cilium-agent``, ``cilium-operator``
   and ``ztunnel`` each have one entry, whose ID starts with ``cilium.``, no
   entry is parented to ``spiffe://<trust domain>/ztunnel``, and the sidecar
   has not failed to create an entry:

   .. code-block:: bash

      spire_server entry show -output json | jq -r '.entries[] |
        [.id, "spiffe://\(.spiffe_id.trust_domain)\(.spiffe_id.path)",
         "spiffe://\(.parent_id.trust_domain)\(.parent_id.path)"] | @tsv'
      kubectl -n cilium-spire logs spire-server-0 -c spire-controller-manager |
        grep 'Failed to create entry'

Running multiple SPIRE servers
------------------------------

With ``useCRD``, ``authentication.mutual.spire.install.server.replicas`` can
run more than one SPIRE server. Each server keeps its own datastore, and its
own sidecar registers the same entries in it. Unless you set
``authentication.mutual.spire.install.server.affinity``, the servers run on
different nodes, and the SPIRE server Service sends the connections of each
SPIRE agent to the same server.

The servers must sign with a common root, so that each of them accepts the
certificates that the others issue. With more than one server, they sign with
the upstream root CA from the Secret that
``authentication.mutual.spire.install.server.ca.upstreamSecret`` names,
``spire-upstream-ca`` by default. The chart does not create the Secret. Create
it in the SPIRE namespace from the certificate and private key of a self-signed
root CA, for example:

.. code-block:: shell-session

   openssl req -new -x509 -nodes -newkey rsa:4096 -sha256 -days 3650 \
     -subj '/O=Example/CN=SPIRE upstream root' \
     -addext 'basicConstraints=critical,CA:TRUE' \
     -addext 'keyUsage=critical,keyCertSign,cRLSign' \
     -keyout tls.key -out tls.crt
   kubectl -n cilium-spire create secret tls spire-upstream-ca --cert=tls.crt --key=tls.key

To create the Secret before you install Cilium, also create the namespace and
set ``authentication.mutual.spire.install.existingNamespace=true``. Otherwise
the SPIRE servers wait for the Secret after the installation.

A SPIRE server that already runs keeps signing with the CA in its datastore
when you set ``ca.upstreamSecret``, while a new server only trusts the upstream
root. Workloads that obtained their certificates from different servers then
fail to authenticate each other. To run more than one server on an
installation that runs one server without ``ca.upstreamSecret``, move that
server to the upstream root first:

#. Create the Secret as described above, and upgrade Cilium with your Helm
   values and the Secret, still with one server:

   .. parsed-literal::

      helm upgrade cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --values my-values.yaml \\
        --set encryption.ztunnel.spire.useCRD=true \\
        --set authentication.mutual.spire.install.server.ca.upstreamSecret=spire-upstream-ca

#. Prepare a CA that the upstream root signs, using the ``spire_server`` helper
   of the previous section, and note the authority ID that it prints. The trust
   bundle of the server now contains the upstream root as well.

   .. code-block:: shell-session

      spire_server localauthority x509 prepare

#. Wait at least one hour, the default lifetime of the certificates that the
   SPIRE server issues, and activate the prepared CA. ztunnel only takes the
   new trust bundle when it renews the certificate of a workload, and rejects
   certificates from the prepared CA until then.

   .. code-block:: shell-session

      spire_server localauthority x509 activate -authorityID <authority ID>

#. Wait at least one hour again, so that the SPIRE agents and the workloads
   renew their certificates from the new CA. Then add the other servers:

   .. parsed-literal::

      helm upgrade cilium |CHART_RELEASE| \\
        --namespace kube-system \\
        --values my-values.yaml \\
        --set encryption.ztunnel.spire.useCRD=true \\
        --set authentication.mutual.spire.install.server.ca.upstreamSecret=spire-upstream-ca \\
        --set authentication.mutual.spire.install.server.replicas=2

#. Check that the trust bundle of each server contains the upstream root, with
   the subject of the certificate in the Secret. The first server also keeps
   its previous root until that root expires.

   .. code-block:: bash

      for server in spire-server-0 spire-server-1; do
        echo "${server}:"
        kubectl -n cilium-spire exec "${server}" -c spire-server -- \
          /opt/spire/bin/spire-server bundle show -format pem |
          openssl crl2pkcs7 -nocrl -certfile /dev/stdin |
          openssl pkcs7 -print_certs -noout
      done

If you add servers without these steps, the servers sign with different roots.
SPIRE agents then restart with ``x509: certificate signed by unknown
authority`` errors, and new workloads cannot connect to other workloads. To
recover, prepare and activate a CA on the first server as in steps 2 and 3
without waiting, then replace the first server, the SPIRE agents and the
ztunnel Pods. An agent that failed repeatedly waits up to five minutes before
it starts again, and the ztunnel Pod on its node gets no certificates until
then, so replace the agents before the ztunnel Pods. The traffic of the
workloads on each node fails until its ztunnel Pod is ready again:

.. code-block:: shell-session

   kubectl -n cilium-spire delete pod spire-server-0
   kubectl -n cilium-spire rollout status statefulset/spire-server
   kubectl -n cilium-spire rollout restart daemonset/spire-agent
   kubectl -n cilium-spire rollout status daemonset/spire-agent
   kubectl -n kube-system delete pod -l app=ztunnel-cilium

Each sidecar also writes the status of the ClusterSPIFFEIDs and
ClusterStaticEntries, so with more than one server the sidecars log
``Failed to update status`` errors when another sidecar updated a resource
first. These conflicts do not affect the entries, and the status shows what the
sidecar that wrote it last found in its own server. The sidecars do not use
leader election, because each of them must register the entries in its own
server.

Limitations
===========

* Traffic between workloads is only supported when both the source and
  destination endpoints are enrolled in ztunnel. Communication between an
  enrolled workload and a non-enrolled workload is not supported.

* The ztunnel integration currently only supports enrollment via namespace
  labels. Pod-level enrollment is not supported.

* Only TCP traffic is currently supported for mTLS encryption. UDP and other
  protocols are not redirected to ztunnel.

* The integration requires iptables support in the kernel and cannot be used
  with environments that do not support iptables (such as some minimal container
  runtimes).

* Ztunnel interferes with Cilium network policy as traffic is encrypted before
  it leaves the pod, meaning L4 policies won't work except for directly
  targeting the ztunnel HBONE port (15008).

Known Issues
============

* Cluster Mesh is not currently supported when ztunnel is enabled. Attempting
  to enable both will result in a validation error.

* Pods without a network namespace path (such as host-networked pods) cannot
  be enrolled in ztunnel and will be skipped during enrollment.

