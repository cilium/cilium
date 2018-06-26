.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
      http://docs.cilium.io

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
endpoints. We can use the ``cilium policy trace`` to simulate a policy decision 
between the source and destination endpoints.

We will use the example from the `Minikube Getting Started Guide <http://cilium.readthedocs.io/en/latest/gettingstarted/minikube/#getting-started-using-minikube>`_ to trace the policy. In this example, there is:

* ``deathstar`` service identified by labels: ``org=empire, class=deathstar``. The service is backed by two pods.
* ``tiefighter`` spaceship client pod with labels: ``org=empire, class=tiefighter``
* ``xwing`` spaceship client pod with labels: ``org=alliance, class=xwing``

An L3/L4 policy is enforced on the ``deathstar`` service to allow access to all spaceships with labels ``org=empire``. With this policy, the ``tiefighter`` access is allowed but ``xwing`` access will be denied. Let's use the ``cilium policy trace`` to simulate the policy decision. The command provides flexibility to run using pod names, labels or Cilium security identities.

.. note::

    If the ``--dport`` option is not specified, then L4 policy will not be
    consulted in this policy trace command.

    Currently, there is no support for tracing L7 policies via this tool.

.. code:: bash

    # Policy trace using pod name and service labels

    $ kubectl exec -ti cilium-88k78 -n kube-system -- cilium policy trace --src-k8s-pod default:xwing -d any:class=deathstar,k8s:org=empire,k8s:io.kubernetes.pod.namespace=default --dport 80
    level=info msg="Waiting for k8s api-server to be ready..." subsys=k8s
    level=info msg="Connected to k8s api-server" ipAddr="https://10.96.0.1:443" subsys=k8s
    ----------------------------------------------------------------
    Tracing From: [k8s:class=xwing, k8s:io.cilium.k8s.policy.serviceaccount=default, k8s:io.kubernetes.pod.namespace=default, k8s:org=alliance] => To: [any:class=deathstar, k8s:org=empire, k8s:io.kubernetes.pod.namespace=default] Ports: [80/ANY]
    * Rule {"matchLabels":{"any:class":"deathstar","any:org":"empire","k8s:io.kubernetes.pod.namespace":"default"}}: selected
        Allows from labels {"matchLabels":{"any:org":"empire","k8s:io.kubernetes.pod.namespace":"default"}}
          Labels [k8s:class=xwing k8s:io.cilium.k8s.policy.serviceaccount=default k8s:io.kubernetes.pod.namespace=default k8s:org=alliance] not found
    1/1 rules selected
    Found no allow rule
    Label verdict: undecided

    Resolving ingress port policy for [any:class=deathstar k8s:org=empire k8s:io.kubernetes.pod.namespace=default]
    * Rule {"matchLabels":{"any:class":"deathstar","any:org":"empire","k8s:io.kubernetes.pod.namespace":"default"}}: selected
        Labels [k8s:class=xwing k8s:io.cilium.k8s.policy.serviceaccount=default k8s:io.kubernetes.pod.namespace=default k8s:org=alliance] not found
    1/1 rules selected
    Found no allow rule
    L4 ingress verdict: undecided

    Final verdict: DENIED
    
.. code:: bash
    
    # Get the Cilium security id

    $ kubectl exec -ti cilium-88k78 -n kube-system -- cilium endpoint list | egrep  'deathstar|xwing|tiefighter'
    ENDPOINT   POLICY (ingress)   POLICY (egress)   IDENTITY   LABELS (source:key[=value])                              IPv6                 IPv4            STATUS   
               ENFORCEMENT        ENFORCEMENT
    568        Enabled            Disabled          22133      k8s:class=deathstar                                      f00d::a0f:0:0:238    10.15.65.193    ready   
    900        Enabled            Disabled          22133      k8s:class=deathstar                                      f00d::a0f:0:0:384    10.15.114.17    ready   
    33633      Disabled           Disabled          53208      k8s:class=xwing                                          f00d::a0f:0:0:8361   10.15.151.230   ready   
    38654      Disabled           Disabled          22962      k8s:class=tiefighter                                     f00d::a0f:0:0:96fe   10.15.88.156    ready   

    # Policy trace using Cilium security ids

    $ kubectl exec -ti cilium-88k78 -n kube-system -- cilium policy trace --src-identity 53208 --dst-identity 22133  --dport 80
    ----------------------------------------------------------------
    Tracing From: [k8s:class=xwing, k8s:io.cilium.k8s.policy.serviceaccount=default, k8s:io.kubernetes.pod.namespace=default, k8s:org=alliance] => To: [any:class=deathstar, k8s:org=empire, k8s:io.kubernetes.pod.namespace=default] Ports: [80/ANY]
    * Rule {"matchLabels":{"any:class":"deathstar","any:org":"empire","k8s:io.kubernetes.pod.namespace":"default"}}: selected
        Allows from labels {"matchLabels":{"any:org":"empire","k8s:io.kubernetes.pod.namespace":"default"}}
          Labels [k8s:class=xwing k8s:io.cilium.k8s.policy.serviceaccount=default k8s:io.kubernetes.pod.namespace=default k8s:org=alliance] not found
    1/1 rules selected
    Found no allow rule
    Label verdict: undecided

    Resolving ingress port policy for [any:class=deathstar k8s:org=empire k8s:io.kubernetes.pod.namespace=default]
    * Rule {"matchLabels":{"any:class":"deathstar","any:org":"empire","k8s:io.kubernetes.pod.namespace":"default"}}: selected
        Labels [k8s:class=xwing k8s:io.cilium.k8s.policy.serviceaccount=default k8s:io.kubernetes.pod.namespace=default k8s:org=alliance] not found
    1/1 rules selected
    Found no allow rule
    L4 ingress verdict: undecided

    Final verdict: DENIED
    

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

In the above example, for one of the ``deathstar`` pods the endpoint id is 568. We can print all policies applied to it with:

.. code:: bash

    # Get a shell on the Cilium pod

    $ kubectl exec -ti cilium-88k78 -n kube-system /bin/bash

    # print out the Layer 4 ingress labels
    # clean up the data
    # fetch each policy via each set of labels

    $ cilium endpoint get 568 -o jsonpath='{range ..status.policy.realized.l4.ingress[*].derived-from-rules}{@}{"\n"}{end}'|tr -d '][' | xargs -I{} bash -c 'echo "Labels: {}"; cilium policy get {}'
    Labels: k8s:io.cilium.k8s.policy.name=rule1 k8s:io.cilium.k8s.policy.namespace=default
    [
      {
        "endpointSelector": {
          "matchLabels": {
            "any:class": "deathstar",
            "any:org": "empire",
            "k8s:io.kubernetes.pod.namespace": "default"
          }
        },
        "ingress": [
          {
            "fromEndpoints": [
              {
                "matchLabels": {
                  "any:org": "empire",
                  "k8s:io.kubernetes.pod.namespace": "default"
                }
              }
            ],
            "toPorts": [
              {
                "ports": [
                  {
                    "port": "80",
                    "protocol": "TCP"
                  }
                ],
                "rules": {
                  "http": [
                    {
                      "path": "/v1/request-landing",
                      "method": "POST"
                    }
                  ]
                }
              }
            ]
          }
        ],
        "labels": [
          {
            "key": "io.cilium.k8s.policy.name",
            "value": "rule1",
            "source": "k8s"
          },
          {
            "key": "io.cilium.k8s.policy.namespace",
            "value": "default",
            "source": "k8s"
          }
        ]
      }
    ]
    Revision: 217


    # repeat for L4 egress and L3
    $ cilium endpoint get 568 -o jsonpath='{range ..status.policy.realized.l4.egress[*].derived-from-rules}{@}{"\n"}{end}' | tr -d '][' | xargs -I{} bash -c 'echo "Labels: {}"; cilium policy get {}'
    $ cilium endpoint get 568 -o jsonpath='{range ..status.policy.realized.cidr-policy.ingress[*].derived-from-rules}{@}{"\n"}{end}' | tr -d '][' | xargs -I{} bash -c 'echo "Labels: {}"; cilium policy get {}'
    $ cilium endpoint get 568 -o jsonpath='{range ..status.policy.realized.cidr-policy.egress[*].derived-from-rules}{@}{"\n"}{end}' | tr -d '][' | xargs -I{} bash -c 'echo "Labels: {}"; cilium policy get {}'
