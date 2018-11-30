.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

****************************************
Getting Started Using DNS-Based Policies
****************************************

This document serves as an introduction for using Cilium to enforce DNS-based
security policies for Kubernetes pods.

.. include:: gsg_intro.rst
.. include:: minikube_intro.rst
.. include:: cilium_install.rst

Step 2: Deploy the Demo Application
===================================

DNS-based policies are very useful for controlling access to services running outside the Kubernetes cluster. Whether it is cloud services such as S3, DynamoDB, RDS, etc. or private VPC services outside the cluster, DNS provides persistent identity for these external services. CIDR or IP-based policies are cumbersome and hard to maintain as the IPs associated with external services can change frequently. The Cilium DNS-based policies provide an easy mechanism to specify access control while leaving the harder aspects of resolving and enforcing IP-based filters to Cilium. 

In this guide we will learn about:  
 
- Controlling egress access to services outside the cluster using DNS-based policies
- Using patterns (or wildcards) to whitelist a subset of DNS domains
- Combining DNS and port rules for restricting access to external service  

Step 3: Create Example App
==========================

In line with our Star Wars theme examples, we will use simple scenario with two pods, ``mediabot`` and ``spaceship``. The ``mediabot`` pod needs access to Twitter API services for managing the empire's tweets. However, the ``spaceship`` pods shouldn't have any external service access for obvious reasons. 

.. parsed-literal::

    $ kubectl create -f \ |SCM_WEB|\/examples/minikube/dns-sw-app.yaml
    $ kubectl get po
    NAME                             READY   STATUS    RESTARTS   AGE
    pod/mediabot                     1/1     Running   0          14s
    pod/spaceship                    1/1     Running   0          14s  

Step 4: Apply DNS Egress Policy
===============================


The following Cilium network policy allows **only** ``mediabot`` pods to access ``api.twitter.com``. 

.. literalinclude:: ../../examples/policies/getting-started/dns-matchname.yaml

Let's take a closer look at the policy: 

* The first egress section uses ``toFQDNs: matchName`` specification to allow egress to ``api.twitter.com``. The destination DNS should match exactly the name specified in the rule. The ``endpointSelector`` allows only pods with labels ``class: mediabot`` to have the egress access.
* The second egress section allows all pods in the ``default`` namespace to access ``kube-dns`` service. Note that ``rules: dns`` instructs Cilium to inspect and allow DNS lookups matching specified patterns. In this case, inspect and allow all DNS queries. 

Let's apply the policy:

.. parsed-literal::

  $ kubectl create -f \ |SCM_WEB|\/examples/policies/getting-started/dns-matchname.yaml

Testing the policy, we see that ``mediabot`` has access to ``api.twitter.com`` but doesn't have access to any other external service, for e.g., ``help.twitter.com``. And ``spaceship`` pod doesn't have access to twitter. 

.. parsed-literal::

    $ kubectl exec -it mediabot -- curl -sL https://api.twitter.com
    ...
    ...

    $ kubectl exec -it mediabot -- curl -sL https://help.twitter.com
    ^C 

    $ kubectl exec -it spaceship -- curl -sL https://api.twitter.com
    ^C  

Step 5: DNS Policies Using Patterns 
===================================

The above policy controlled DNS access based on exact match of the DNS domain name. Often it is required to allow access to a subset of domains. Let's say, in the above example, ``mediabot`` pods need access to any Twitter sub-domain, i.e., the pattern ``*.twitter.com``. We can achieve this easily by changing the ``toFQDN`` rule to use ``matchPattern`` instead of ``matchName``.

.. literalinclude:: ../../examples/policies/getting-started/dns-pattern.yaml

.. parsed-literal::

  $ kubectl apply -f \ |SCM_WEB|\/examples/policies/getting-started/dns-pattern.yaml

Test that ``mediabot`` has access to multiple Twitter services for which the DNS matches the pattern ``*.twitter.com``. Important to note and test that this doesn't allow access to ``twitter.com`` because the ``*.`` in the pattern requires one subdomain to be present in the DNS name. You can simply add more ``matchName`` and ``matchPattern`` clauses to extend the access. 
(See :ref:`DNS based` policies to learn more about specifying DNS rules using patterns and names.)

.. parsed-literal:: 
  
   $ kubectl exec -it mediabot -- curl -sL https://help.twitter.com
   ...

   $ kubectl exec -it mediabot -- curl -sL https://about.twitter.com
   ... 

   $ kubectl exec -it mediabot -- curl -sL https://twitter.com
   ^C 
 
Step 6: Combining DNS and Port Rules
====================================

The DNS-based access can be restricted to a specific port by adding an L4 rules section. Continuing with the example, we will restrict access to Twitter services to port ``443``. 

.. literalinclude:: ../../examples/policies/getting-started/dns-port.yaml

.. parsed-literal::

  $ kubectl apply -f \ |SCM_WEB|\/examples/policies/getting-started/dns-port.yaml

Testing, the access to ``https://help.twitter.com`` on port ``443`` will succeed but access to ``http://help.twitter.com`` on port ``80`` will be blocked.

.. parsed-literal:: 
  
   $ kubectl exec -it mediabot -- curl -sL https://help.twitter.com
   ...

   $ kubectl exec -it mediabot -- curl -sL http://help.twitter.com
   ^C  

Step 7: Clean-up
================

.. parsed-literal::

   $ kubectl delete -f \ |SCM_WEB|\/examples/minikube/dns-sw-app.yaml
   $ kubectl delete cnp to-fqdn
