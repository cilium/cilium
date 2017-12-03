.. _policy_tracing:
.. _policy_troubleshooting:

***************
Troubleshooting
***************

If Cilium is allowing / denying connections in a way that is not aligned with the
intent of your Cilium Network policy, there is an easy way to
verify if and what policy rules apply between two
endpoints. The following example shows how to use ``cilium policy trace`` to
simulate a policy decision from an endpoint with the label ``id.curl`` to an
endpoint with the label ``id.http`` on port 80:

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

