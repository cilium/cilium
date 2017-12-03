.. _policy_guide:

Policy Enforcement Modes
========================

Whether an endpoint accepts traffic from source is dependent upon the
configuration of the agent and the policy. The agent can be put into the
following three policy enforcement modes:

default
  This is the behavior for policy enforcement when Cilium is launched without
  any specified value for policy enforcement configuration. The following rule
  applies:

  * If any rule selects an `endpoint` and the rule has an ingress
    section, the endpoint goes into default deny at ingress
  * If any rule selects an `endpoint` and the rule has an egress section, the
    endpoint goes into default deny at egress.

  This means that endpoints will start out without any restrictions, as soon as
  a rule restricts their ability to receive traffic on ingress or to transmit
  traffic on egress, then the endpoint goes into whitelisting mode and all
  traffic must be explicitly allowed.

always
  With this mode, policy enforcement is enabled on all endpoints, even if no
  rules select specific endpoints.
 
never
  With this mode, policy enforcement is disabled on all endpoints, even if
  rules do select specific endpoints. In other words, all traffic is allowed
  from any source with respect to an endpoint.

Policy enforcement is configurable at runtime by running:

.. code:: bash

    $ cilium config PolicyEnforcement={default,always,never}

If you want to have a certain policy enforcement configuration value at
launch-time, you can provide the following flag when you launch the Cilium
daemon:

.. code:: bash

    $ cilium-agent --enable-policy={default,always,never} [...]

.. _policy_rule:

Rule Basics
===========

All policy rules share a common base type which specifies what endpoints the
rule applies to and also carries common metadata to identify the rule.

Each rule is split into an ingress section which contains the rules which must
be applied at ingress and egress of all endpoints matching the endpoint
selector. Either ingress, egress, or both can be provided. If both ingress and
egress are omitted, the rule has no effect.

.. code-block:: go

        type Rule struct {
                // EndpointSelector selects all endpoints which should be subject to
                // this rule. Cannot be empty.
                EndpointSelector EndpointSelector `json:"endpointSelector"`

                // Ingress is a list of IngressRule which are enforced at ingress.
                // If omitted or empty, this rule does not apply at ingress.
                //
                // +optional
                Ingress []IngressRule `json:"ingress,omitempty"`

                // Egress is a list of EgressRule which are enforced at egress.
                // If omitted or empty, this rule does not apply at egress.
                //
                // +optional
                Egress []EgressRule `json:"egress,omitempty"`

                // Labels is a list of optional strings which can be used to
                // re-identify the rule or to store metadata. It is possible to lookup
                // or delete strings based on labels. Labels are not required to be
                // unique, multiple rules can have overlapping or identical labels.
                //
                // +optional
                Labels labels.LabelArray `json:"labels,omitempty"`

                // Description is a free form string, it can be used by the creator of
                // the rule to store human readable explanation of the purpose of this
                // rule. Rules cannot be identified by comment.
                //
                // +optional
                Description string `json:"description,omitempty"`
        }

----

endpointSelector
  Selects the endpoints to which the policy rules contained must be applied to.
  All endpoints which match the labels specified in the ``endpointSelector``
  will have the policy rules applied to. See the `LabelSelector` section for
  additional details.

ingress
  List of rules which must apply at ingress of the endpoint, i.e. to all
  network packets which are entering the endpoint.

egress
  List of rules which must apply at egress of the endpoint, i.e. to all network
  packets which are leaving the endpoint.

labels
  Labels are used to identify the rule. Rules can be listed and deleted by
  labels. Policy rules which are imported via :ref:`k8s_policy` automatically
  get the label ``io.cilium.k8s-policy-name=NAME`` assigned where ``NAME``
  corresponds to the name specified in the `NetworkPolicy` or
  `CiliumNetworkPolicy` resource.

description
  Description is a string which is not interpreted by Cilium. It can be used to
  describe the intent and scope of the rule in a human readable form.

.. _label_selector:
.. _LabelSelector:
.. _EndpointSelector:

Endpoint Selector
-----------------

The Endpoint Selector is based off on LabelSelector of Kubernetes. It is called
Endpoint Selector because it only applies to labels associated with
`endpoints`.
