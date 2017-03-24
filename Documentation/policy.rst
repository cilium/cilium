Policy Specification
====================

.. code:: go

    type NetworkPolicy struct {
        TypeMeta
        ObjectMeta

        Spec NetworkPolicySpec 
    }

    type NetworkPolicySpec struct {
        // Selects the pods which this NetworkPolicy object
        // applies to.
        PodSelector *unversioned.LabelSelector `json:"podSelector,omitempty"`

        // List of ingress rules to be applied to the 
        // selected pods.
        Ingress []NetworkPolicyIngressRule `json:"ingress,omitempty"`
    }

    type NetworkPolicyIngressRule struct {
        // Additional selector (optional)
        PodSelector *unversioned.LabelSelector

        // List of allowed ports. 
        Ports []NetworkPolicyPort `json:"ports,omitempty"`

        // List of allowed sources.
        From []NetworkPolicySource `json:"from,omitempty"`

        // Additional label requirements
        Requires *unversioned.LabelSelector
    }

    type NetworkPolicyPort struct {
        // If specified, the port on the given protocol.
        Port int32 `json:"port,omitempty"`

        // The protocol - TCP or UDP.
        Protocol string `json:"protocol"`
    }

    type NetworkPolicySource struct {
        // If true, a child policy element cannot negate this policy decision
        AlwaysAllow bool

        // Label selector - selects pods in this namespace.
        // If 'Namespaces' is defined, this must not be.
        Pods *unversioned.LabelSelector

        // Label selector - selects namespaces.
        // If 'Pods' is defined, this must not be.
        Namespaces map[string]string `json:"namespaces,omitempty"`
    }

.. code:: yaml

    kind: NetworkPolicy
    apiVersion: v1beta 
    metadata:
      name:
      namespace:
    spec:
      podSelector:            // Standard label selector - selects pods.  
      ingress:                // List of ingress rules (optional).
        - coverage:           // Label selector - must match for rule to be applied (optional)
          ports:              // List of allowed ports / protocols (optional).          
            - port:           // Port on the specified protocol (optional). 
              protocol:       // Protocol (TCP, UDP) 
          from:               // List of allowed sources (optional).    
            - always:         // { true | false } If true, do not allow child elements to deny (optional)
              pods:           // Label selector - selects Pods (optional). 
              namespaces:     // Label selector - selects Namespaces (optional).
          requires:           // List of additional labels required to consume selected pods (optional)
            - labels:         // Label selector

Rule matching precendence: 1. The default decision is deny (undecided)
2. If a rule matches and the from portion the source pod, the decision
is changed to allow but the evaluation continues. If multiple rules in a
policy element overlap, then the negated selector takes precendence. 3.
If a from rules has the always boolean set, the decision is final
immediately, the evaulation is not continued. 4. If a requires rule is
encounted, the additional list of labels is added to the list of
required labels of a possible source. The rule itself does not change
the decision though.
