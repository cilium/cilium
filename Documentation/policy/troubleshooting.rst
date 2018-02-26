.. _policy_tracing:
.. _policy_troubleshooting:

***************
Troubleshooting
***************

Policy Tracing
==============

If Cilium is allowing / denying connections in a way that is not aligned with the
intent of your Cilium Network policy, there is an easy way to
verify if and what policy rules apply between two
endpoints. The following example shows how to use ``cilium policy trace`` to
simulate a policy decision from an endpoint with the label ``id.curl`` to an
endpoint with the label ``id.http`` on port 80:

.. note::

    If the ``--dport`` option is not specified, then L4 policy will not be
    consulted in this policy trace command.

    Currently, there is no support for tracing L7 policies via this tool.

.. code:: bash

    $ cilium policy trace -s id.curl -d id.httpd --dport 80
    Tracing From: [container:id.curl] => To: [container:id.httpd] Ports: [80/any]
    * Rule {"matchLabels":{"any:id.httpd":""}}: selected
        Allows from labels {"matchLabels":{"any:id.curl":""}}
          Found all required labels
            Rule restricts traffic to specific L4 destinations; deferring policy decision to L4 policy stage
    1/1 rules selected
    Found no allow rule
    Label verdict: undecided

    Resolving egress port policy for [container:id.curl]
    * Rule {"matchLabels":{"any:id.curl":""}}: selected
      Allows Egress port [{80 tcp}]
        Found all required labels
    1/1 rules selected
    Found allow rule
    L4 egress verdict: allowed

    Resolving ingress port policy for [container:id.httpd]
    * Rule {"matchLabels":{"any:id.httpd":""}}: selected
      Allows Ingress port [{80 tcp}]
        Found all required labels
    1/1 rules selected
    Found allow rule
    L4 ingress verdict: allowed

    Final verdict: ALLOWED

Policy Rule to Endpoint Mapping
===============================

To determine which policy rules are currently in effect for an endpoint the
data from ``cilium endpoint list`` and ``cilium endpoint get`` can be paired
with the data from ``cilium policy get``. ``cilium endpoint get`` will list the
labels of each rule that applies to an endpoint. The list of labels can be
passed to ``cilium policy get`` to show that exact source policy.  Note that
rules that have no labels cannot be fetched alone (a no label ``cililum policy
get`` returns the complete policy on the node). Rules with the same labels will
be returned together.
For an endpoint with endpoint id 51796, We can print all policies applied to it with:

.. code:: bash

    # print out the Layer 4 ingress labels
    # clean up the data
    # fetch each policy via each set of labels
    $ cilium endpoint get 51796 -o jsonpath='{range ..policy.l4.ingress[*].derived-from-rules}{@}{"\n"}{end}' | \
      tr -d '][' | \
      xargs -I{} bash -c 'echo "Labels: {}"; cilium policy get {}'
    Labels: unspec:io.cilium.k8s.policy.name=rule1 unspec:io.cilium.k8s.policy.namespace=default
    [
      {
        "endpointSelector": {
    ...
             ],
        "labels": [
          {
            "key": "io.cilium.k8s.policy.name",
            "value": "rule1",
            "source": "unspec"
          },
          {
            "key": "io.cilium.k8s.policy.namespace",
            "value": "default",
            "source": "unspec"
          }
        ]
      }
    ]
    Revision: 6 

    # repeat for L4 egress and L3
    $ cilium endpoint get 51796 -o jsonpath='{range ..policy.l4.egress[*].derived-from-rules}{@}{"\n"}{end}' | tr -d '][' | xargs -I{} bash -c 'echo "Labels: {}"; cilium policy get {}'
    $ cilium endpoint get 51796 -o jsonpath='{range ..policy.cidr-policy.ingress[*].derived-from-rules}{@}{"\n"}{end}' | tr -d '][' | xargs -I{} bash -c 'echo "Labels: {}"; cilium policy get {}'
    $ cilium endpoint get 51796 -o jsonpath='{range ..policy.cidr-policy.egress[*].derived-from-rules}{@}{"\n"}{end}' | tr -d '][' | xargs -I{} bash -c 'echo "Labels: {}"; cilium policy get {}'
