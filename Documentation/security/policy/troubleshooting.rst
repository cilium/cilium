.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _policy_troubleshooting:

***************
Troubleshooting
***************

Policy Rule to Endpoint Mapping
===============================

To determine which policy rules are currently in effect for an endpoint the
data from ``cilium endpoint list`` and ``cilium endpoint get`` can be paired
with the data from ``cilium policy get``. ``cilium endpoint get`` will list the
labels of each rule that applies to an endpoint. The list of labels can be
passed to ``cilium policy get`` to show that exact source policy.  Note that
rules that have no labels cannot be fetched alone (a no label ``cilium policy
get`` returns the complete policy on the node). Rules with the same labels will
be returned together.

In the above example, for one of the ``deathstar`` pods the endpoint id is 568. We can print all policies applied to it with:

.. code-block:: shell-session

    $ # Get a shell on the Cilium pod

    $ kubectl exec -ti cilium-88k78 -n kube-system -- /bin/bash

    $ # print out the ingress labels
    $ # clean up the data
    $ # fetch each policy via each set of labels
    $ # (Note that while the structure is "...l4.ingress...", it reflects all L3, L4 and L7 policy.

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


    $ # repeat for egress
    $ cilium endpoint get 568 -o jsonpath='{range ..status.policy.realized.l4.egress[*].derived-from-rules}{@}{"\n"}{end}' | tr -d '][' | xargs -I{} bash -c 'echo "Labels: {}"; cilium policy get {}'

Troubleshooting ``toFQDNs`` rules
=================================

The effect of ``toFQDNs`` may change long after a policy is applied, as DNS
data changes. This can make it difficult to debug unexpectedly blocked
connections, or transient failures. Cilium provides CLI tools to introspect
the state of applying FQDN policy in multiple layers of the daemon:

#. ``cilium policy get`` should show the FQDN policy that was imported:

   .. code-block:: json

      {
        "endpointSelector": {
          "matchLabels": {
            "any:class": "mediabot",
            "any:org": "empire",
            "k8s:io.kubernetes.pod.namespace": "default"
          }
        },
        "egress": [
          {
            "toFQDNs": [
              {
                "matchName": "api.github.com"
              }
            ]
          },
          {
            "toEndpoints": [
              {
                "matchLabels": {
                  "k8s:io.kubernetes.pod.namespace": "kube-system",
                  "k8s:k8s-app": "kube-dns"
                }
              }
            ],
            "toPorts": [
              {
                "ports": [
                  {
                    "port": "53",
                    "protocol": "ANY"
                  }
                ],
                "rules": {
                  "dns": [
                    {
                      "matchPattern": "*"
                    }
                  ]
                }
              }
            ]
          }
        ],
        "labels": [
          {
            "key": "io.cilium.k8s.policy.derived-from",
            "value": "CiliumNetworkPolicy",
            "source": "k8s"
          },
          {
            "key": "io.cilium.k8s.policy.name",
            "value": "fqdn",
            "source": "k8s"
          },
          {
            "key": "io.cilium.k8s.policy.namespace",
            "value": "default",
            "source": "k8s"
          },
          {
            "key": "io.cilium.k8s.policy.uid",
            "value": "f213c6b2-c87b-449c-a66c-e19a288062ba",
            "source": "k8s"
          }
        ]
      }

#. After making a DNS request, the FQDN to IP mapping should be available via
   ``cilium fqdn cache list``:

   .. code-block:: shell-session

      # cilium fqdn cache list
      Endpoint   Source   FQDN                  TTL    ExpirationTime             IPs
      725        lookup   api.github.com.       3600   2023-02-10T18:16:05.842Z   140.82.121.6
      725        lookup   support.github.com.   3600   2023-02-10T18:16:09.371Z   185.199.111.133,185.199.109.133,185.199.110.133,185.199.108.133


#. If the traffic is allowed, then these IPs should have corresponding local identities via
   ``cilium identity list | grep <IP>``:

   .. code-block:: shell-session

      # cilium identity list | grep -A 1 140.82.121.6
      16777230   cidr:140.82.121.6/32
           reserved:world
