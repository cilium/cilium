.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _policy_guide:

.. _policy_enforcement_modes:

Policy Enforcement Modes
========================

The configuration of the Cilium agent and the Cilium Network Policy determines whether an endpoint accepts traffic from a source or not. The agent can be put into the following three policy enforcement modes:

default
  This is the default behavior for policy enforcement when Cilium is launched without
  any specified value for the policy enforcement configuration. The following rules
  apply:

  * If any rule selects an :ref:`endpoint` and the rule has an ingress
    section, the endpoint goes into default deny at ingress.
  * If any rule selects an :ref:`endpoint` and the rule has an egress section, the
    endpoint goes into default deny at egress.

  This means that endpoints will start without any restrictions and as soon as
  a rule restricts their ability to receive traffic on ingress or to transmit
  traffic on egress, then the endpoint goes into whitelisting mode and all
  traffic must be explicitly allowed.

always
  With always mode, policy enforcement is enabled on all endpoints even if no
  rules select specific endpoints.

  If you want to configure health entity to check cluster-wide connectivity when 
  you start cilium-agent with ``enable-policy=always``, you will likely want to
  enable communications to and from the health endpoint. See :ref:`health_endpoint`.

never
  With never mode, policy enforcement is disabled on all endpoints, even if
  rules do select specific endpoints. In other words, all traffic is allowed
  from any source (on ingress) or destination (on egress).

To configure the policy enforcement mode at runtime for all endpoints managed by a Cilium agent, use:

.. code-block:: shell-session

    $ cilium config PolicyEnforcement={default,always,never}

If you want to configure the policy enforcement mode at start-time for a particular agent, provide the following flag when launching the Cilium
daemon:

.. code-block:: shell-session

    $ cilium-agent --enable-policy={default,always,never} [...]

Similarly, you can enable the policy enforcement mode across a Kubernetes cluster by including the parameter above in the Cilium DaemonSet.

.. code-block:: yaml

    - name: CILIUM_ENABLE_POLICY
      value: always


.. _policy_rule:

Rule Basics
===========

All policy rules are based upon a whitelist model, that is, each rule in the
policy allows traffic that matches the rule. If two rules exist, and one
would match a broader set of traffic, then all traffic matching the broader
rule will be allowed. If there is an intersection between two or more rules,
then traffic matching the union of those rules will be allowed. Finally, if
traffic does not match any of the rules, it will be dropped pursuant to the
`policy_enforcement_modes`.

Policy rules share a common base type which specifies which endpoints the
rule applies to and common metadata to identify the rule. Each rule is split
into an ingress section and an egress section. The ingress section contains
the rules which must be applied to traffic entering the endpoint, and the
egress section contains rules applied to traffic coming from the endpoint
matching the endpoint selector. Either ingress, egress, or both can be
provided. If both ingress and egress are omitted, the rule has no effect.

.. code-block:: go

        type Rule struct {
                // EndpointSelector selects all endpoints which should be subject to
                // this rule. EndpointSelector and NodeSelector cannot be both empty and
                // are mutually exclusive.
                //
                // +optional
                EndpointSelector EndpointSelector `json:"endpointSelector,omitempty"`

                // NodeSelector selects all nodes which should be subject to this rule.
                // EndpointSelector and NodeSelector cannot be both empty and are mutually
                // exclusive. Can only be used in CiliumClusterwideNetworkPolicies.
                //
                // +optional
                NodeSelector EndpointSelector `json:"nodeSelector,omitempty"`

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

endpointSelector / nodeSelector
  Selects the endpoints or nodes which the policy rules apply to. The policy
  rules will be applied to all endpoints which match the labels specified in
  the selector. See the `LabelSelector` and :ref:`NodeSelector` sections for
  additional details.

ingress
  List of rules which must apply at ingress of the endpoint, i.e. to all
  network packets which are entering the endpoint.

egress
  List of rules which must apply at egress of the endpoint, i.e. to all network
  packets which are leaving the endpoint.

labels
  Labels are used to identify the rule. Rules can be listed and deleted by
  labels. Policy rules which are imported via :ref:`kubernetes<k8s_policy>`
  automatically get the label ``io.cilium.k8s.policy.name=NAME`` assigned where
  ``NAME`` corresponds to the name specified in the `NetworkPolicy` or
  `CiliumNetworkPolicy` resource.

description
  Description is a string which is not interpreted by Cilium. It can be used to
  describe the intent and scope of the rule in a human readable form.

.. _label_selector:
.. _LabelSelector:
.. _EndpointSelector:

Endpoint Selector
-----------------

The Endpoint Selector is based on the `Kubernetes LabelSelector
<https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors>`_.
It is called Endpoint Selector because it only applies to labels associated
with an `endpoints`.

.. _NodeSelector:

Node Selector
-------------

The Node Selector is also based on the `LabelSelector`, although rather than
matching on labels associated with an `endpoints`, it instead applies to labels
associated with a node in the cluster.

Node Selectors can only be used in `CiliumClusterwideNetworkPolicy`. See
`HostPolicies` for details on the scope of node-level policies.
