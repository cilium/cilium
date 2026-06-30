.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_gateway_listenerset:

*******************
ListenerSet Support
*******************

`ListenerSet <https://gateway-api.sigs.k8s.io/guides/user-guides/listener-set/>`__
allows additional groups of listeners, defined in ListenerSet resources, to
attach to a single Gateway. This lets an infrastructure owner manage the
Gateway while application owners manage their listeners and TLS certificates
in separate namespaces. All attached listeners use the parent Gateway's
address and infrastructure.

Cilium supports the Standard ``gateway.networking.k8s.io/v1`` ListenerSet API.
This feature does not require a separate Cilium feature flag. Install the
ListenerSet CRD before starting the Cilium operator so that ListenerSet support
is detected during startup. When adding the CRD to an existing installation,
restart the Cilium operator afterward so that it can detect the new resource
and enable ListenerSet support.

.. note::

    By default, a Gateway does not accept ListenerSets. To enable attachment,
    use ``spec.allowedListeners`` to select the namespaces from which
    ListenerSets may attach.

Delegate a listener
===================

The following example creates a Gateway in the ``default`` namespace and
allows ListenerSets from namespaces with the ``gateway-access: "true"`` label.
The ListenerSet and HTTPRoute are created in the ``listenerset-demo``
namespace.

.. literalinclude:: ../../../../examples/kubernetes/gateway/listenerset.yaml
     :language: yaml

Apply the configuration and deploy the echo application in the delegated
namespace:

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/gateway/listenerset.yaml
    $ kubectl -n listenerset-demo apply -f \ |SCM_WEB|\/examples/kubernetes/gateway/echo-basic.yaml

Routes attach directly to the resource that defines their listener. The
HTTPRoute specifies ``kind: ListenerSet`` and selects the ``echo`` listener by
setting ``sectionName``. A Route that references ``shared-gateway`` does not
attach to listeners defined by ``delegated-listeners``.

Verify the ListenerSet
======================

Check both the parent Gateway and the ListenerSet:

.. code-block:: shell-session

    $ kubectl get gateway shared-gateway
    NAME             CLASS    ADDRESS          PROGRAMMED   AGE
    shared-gateway   cilium   192.0.2.100      True         1m

    $ kubectl get listenerset -n listenerset-demo delegated-listeners
    NAME                  ACCEPTED   PROGRAMMED   AGE
    delegated-listeners   True       True         1m

Send a request to the listener:

.. code-block:: shell-session

    $ GATEWAY=$(kubectl get gateway shared-gateway -o jsonpath='{.status.addresses[0].value}')
    $ curl --fail --header 'Host: echo.example.com' http://$GATEWAY/

The Gateway reports the number of attached ListenerSets that contain at least
one valid listener in ``status.attachedListenerSets``. Detailed status for
delegated listeners appears in the ListenerSet's ``status.listeners`` field
rather than the parent Gateway's listener status.
When troubleshooting, inspect the Accepted, Programmed, ResolvedRefs, and
Conflicted conditions for each listener. Also confirm that the parent Gateway
is programmed and has an address.

Operational considerations
==========================

- The Gateway controls which ListenerSet namespaces are accepted with
  ``allowedListeners``. By default, no ListenerSets are allowed.
- Each ListenerSet listener independently controls Route attachment with
  ``allowedRoutes``. When this field is omitted, Routes from the ListenerSet's
  namespace are allowed.
- A Route parent reference must explicitly set ``kind: ListenerSet``. If the
  kind is omitted, it defaults to ``Gateway``.
- HTTPRoute, GRPCRoute, TLSRoute, and the optional TCPRoute and UDPRoute APIs
  can target compatible listeners in a ListenerSet.
- Listeners defined directly on the Gateway take precedence over conflicting
  ListenerSet listeners. Among ListenerSets, older ListenerSets take
  precedence. Conflicts are reported on the lower-precedence listener.
- A ListenerSet with a mixture of valid and invalid listeners can be accepted.
  Check each listener's status instead of relying only on the ListenerSet's
  top-level conditions.
- Certificate references are evaluated from the ListenerSet's namespace. A
  cross-namespace Secret requires a ReferenceGrant for the ListenerSet;
  grants made to the parent Gateway are not inherited.
- The parent Gateway must retain at least one valid listener of its own. A
  valid ListenerSet does not make an otherwise invalid Gateway accepted.

See the upstream `ListenerSet documentation
<https://gateway-api.sigs.k8s.io/guides/user-guides/listener-set/>`__ for
complete attachment, conflict, and status semantics.
