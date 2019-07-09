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

Troubleshooting ``toFQDNs`` rules
=================================

The effect of ``toFQDNs`` may change long after a policy is applied, as DNS
data changes. This can make it difficult to debug unexpectedly blocked
connections, or transient failures. Cilium amends the internal policy as it
sees DNS IP information and this can be obtained with via ``cilium policy
get``. In every rule with a ``toFQDNs`` a corresponding ``toCIDRSet`` rule is
present with the derived IPs that Cilium will allow.

.. code-block:: json

        {
          "toCIDRSet": [
            {
              "cidr": "104.198.14.52/32"
            }
          ],
          "toFQDNs": [
            {
              "matchPattern": "cilium.io"
            }
          ]
        }

The per-Endpoint status from cilium includes the labels of the
original rules that caused the ``toCIDRSet`` to be generated. This can be
obtained with ``cilium endpoint get <endpoint ID>``, or ``kubectl get cep
podname`` when running in kubernetes.


.. only:: html

   .. tabs::
      .. group-tab:: k8s YAML

         .. code-block:: yaml

            cidr-policy:
              egress:
              - derived-from-rules:
                - - k8s:io.cilium.k8s.policy.name=rebel-escape
                  - k8s:io.cilium.k8s.policy.uid=c96f66a8-135e-11e9-babd-080027d2d952
                  - k8s:io.cilium.k8s.policy.namespace=default
                  - k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy
                  - cilium-generated:ToFQDN-UUID=4cee1da1-1361-11e9-a6d4-080027d2d952
                rule: 104.198.14.52/32
              ingress: []

      .. group-tab:: JSON

         .. code-block:: json

            {
              "cidr-policy": {
                "egress": [
                  {
                    "derived-from-rules": [
                      [
                        "k8s:io.cilium.k8s.policy.name=rebel-escape",
                        "k8s:io.cilium.k8s.policy.uid=c96f66a8-135e-11e9-babd-080027d2d952",
                        "k8s:io.cilium.k8s.policy.namespace=default",
                        "k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy",
                        "cilium-generated:ToFQDN-UUID=9a1d4006-1360-11e9-a6d4-080027d2d952"
                      ]
                    ],
                    "rule": "104.198.14.52/32"
                  }
                ],
                "ingress": []
              }
            }

.. only:: epub or latex

   .. code-block:: json

      {
        "cidr-policy": {
          "egress": [
            {
              "derived-from-rules": [
                [
                  "k8s:io.cilium.k8s.policy.name=rebel-escape",
                  "k8s:io.cilium.k8s.policy.uid=c96f66a8-135e-11e9-babd-080027d2d952",
                  "k8s:io.cilium.k8s.policy.namespace=default",
                  "k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy",
                  "cilium-generated:ToFQDN-UUID=9a1d4006-1360-11e9-a6d4-080027d2d952"
                ]
              ],
              "rule": "104.198.14.52/32"
            }
          ],
          "ingress": []
        }
      }

