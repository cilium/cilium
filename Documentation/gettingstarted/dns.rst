.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_dns:

****************************************************
Locking down external access with DNS-based policies
****************************************************

This document serves as an introduction for using Cilium to enforce DNS-based
security policies for Kubernetes pods.

.. include:: gsg_requirements.rst

Deploy the Demo Application
===========================

DNS-based policies are very useful for controlling access to services running outside the Kubernetes cluster. DNS acts as a persistent service identifier for both external services provided by AWS, Google, Twilio, Stripe, etc., and internal services such as database clusters running in private subnets outside Kubernetes. CIDR or IP-based policies are cumbersome and hard to maintain as the IPs associated with external services can change frequently. The Cilium DNS-based policies provide an easy mechanism to specify access control while Cilium manages the harder aspects of tracking DNS to IP mapping.

In this guide we will learn about:  
 
- Controlling egress access to services outside the cluster using DNS-based policies
- Using patterns (or wildcards) to whitelist a subset of DNS domains
- Combining DNS, port and L7 rules for restricting access to external service  

In line with our Star Wars theme examples, we will use a simple scenario where the empire's ``mediabot`` pods need access to Twitter for managing the empire's tweets. The pods shouldn't have access to any other external service.

.. parsed-literal::

    $ kubectl create -f \ |SCM_WEB|\/examples/kubernetes-dns/dns-sw-app.yaml
    $ kubectl get po
    NAME                             READY   STATUS    RESTARTS   AGE
    pod/mediabot                     1/1     Running   0          14s  


Apply DNS Egress Policy
=======================

The following Cilium network policy allows ``mediabot`` pods to only access ``api.twitter.com``. 

.. literalinclude:: ../../examples/kubernetes-dns/dns-matchname.yaml

Let's take a closer look at the policy: 

* The first egress section uses ``toFQDNs: matchName`` specification to allow egress to ``api.twitter.com``. The destination DNS should match exactly the name specified in the rule. The ``endpointSelector`` allows only pods with labels ``class: mediabot, org:empire`` to have the egress access.
* The second egress section allows ``mediabot`` pods to access ``kube-dns`` service. Note that ``rules: dns`` instructs Cilium to inspect and allow DNS lookups matching specified patterns. In this case, inspect and allow all DNS queries.  
 
Note that with this policy the ``mediabot`` doesn't have access to any internal cluster service other than ``kube-dns``. Refer to :ref:`Network Policy` to learn more about policies for controlling access to internal cluster services.

Let's apply the policy:

.. parsed-literal::

  $ kubectl create -f \ |SCM_WEB|\/examples/kubernetes-dns/dns-matchname.yaml

Testing the policy, we see that ``mediabot`` has access to ``api.twitter.com`` but doesn't have access to any other external service, e.g., ``help.twitter.com``. 

.. parsed-literal::

    $ kubectl exec -it mediabot -- curl -sL https://api.twitter.com
    ...
    ...

    $ kubectl exec -it mediabot -- curl -sL https://help.twitter.com
    ^C  

DNS Policies Using Patterns 
===========================

The above policy controlled DNS access based on exact match of the DNS domain name. Often, it is required to allow access to a subset of domains. Let's say, in the above example, ``mediabot`` pods need access to any Twitter sub-domain, e.g., the pattern ``*.twitter.com``. We can achieve this easily by changing the ``toFQDN`` rule to use ``matchPattern`` instead of ``matchName``.

.. literalinclude:: ../../examples/kubernetes-dns/dns-pattern.yaml

.. parsed-literal::

  $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes-dns/dns-pattern.yaml

Test that ``mediabot`` has access to multiple Twitter services for which the DNS matches the pattern ``*.twitter.com``. It is important to note and test that this doesn't allow access to ``twitter.com`` because the ``*.`` in the pattern requires one subdomain to be present in the DNS name. You can simply add more ``matchName`` and ``matchPattern`` clauses to extend the access. 
(See :ref:`DNS based` policies to learn more about specifying DNS rules using patterns and names.)

.. parsed-literal:: 
  
   $ kubectl exec -it mediabot -- curl -sL https://help.twitter.com
   ...

   $ kubectl exec -it mediabot -- curl -sL https://about.twitter.com
   ... 

   $ kubectl exec -it mediabot -- curl -sL https://twitter.com
   ^C 
 
Combining DNS, Port and L7 Rules
================================

The DNS-based policies can be combined with port (L4) and API (L7) rules to further restrict the access. In our example, we will restrict ``mediabot`` pods to access Twitter services only on ports ``443``. The ``toPorts`` section in the policy below achieves the port-based restrictions along with the DNS-based policies. 

.. literalinclude:: ../../examples/kubernetes-dns/dns-port.yaml

.. parsed-literal::

  $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes-dns/dns-port.yaml

Testing, the access to ``https://help.twitter.com`` on port ``443`` will succeed but the access to ``http://help.twitter.com`` on port ``80`` will be denied.

.. parsed-literal:: 
  
   $ kubectl exec -it mediabot -- curl https://help.twitter.com
   ...

   $ kubectl exec -it mediabot -- curl http://help.twitter.com
   ^C

Refer to :ref:`l4_policy` and :ref:`l7_policy` to learn more about Cilium L4 and L7 network policies.  

Clean-up
========

.. parsed-literal::

   $ kubectl delete -f \ |SCM_WEB|\/examples/kubernetes-dns/dns-sw-app.yaml
   $ kubectl delete cnp fqdn
