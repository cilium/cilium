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

DNS-based policies are very useful for controlling access to services running outside the Kubernetes cluster. DNS provides persistent identity both for external services provided by AWS, Google, Twilio, Stripe, etc., and internal services such as database clusters running in private subnets outside Kubernetes. CIDR or IP-based policies are cumbersome and hard to maintain as the IPs associated with external services can change frequently. The Cilium DNS-based policies provide an easy mechanism to specify access control while Cilium manages the harder aspects of tracking DNS to IP mapping.

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


Step 3: Apply DNS Egress Policy
===============================

The following Cilium network policy allows ``mediabot`` pods to only access ``api.twitter.com``. 

.. literalinclude:: ../../examples/kubernetes-dns/dns-matchname.yaml

Let's take a closer look at the policy: 

* The first egress section uses ``toFQDNs: matchName`` specification to allow egress to ``api.twitter.com``. The destination DNS should match exactly the name specified in the rule. The ``endpointSelector`` allows only pods with labels ``class: mediabot, org:empire`` to have the egress access.
* The second egress section allows ``mediabot`` pods to access ``kube-dns`` service. Note that ``rules: dns`` instructs Cilium to inspect and allow DNS lookups matching specified patterns. In this case, inspect and allow all DNS queries.  
 
Note that with this policy the ``mediabot`` doesn't have access to any internal cluster service other than ``kube-dns``. Refer :ref:`Network Policy` to learn more about policies for controlling access to internal cluster services.

Let's apply the policy:

.. parsed-literal::

  $ kubectl create -f \ |SCM_WEB|\/examples/kubernetes-dns/dns-matchname.yaml

Testing the policy, we see that ``mediabot`` has access to ``api.twitter.com`` but doesn't have access to any other external service, for e.g., ``help.twitter.com``. 

.. parsed-literal::

    $ kubectl exec -it mediabot -- curl -sL https://api.twitter.com
    ...
    ...

    $ kubectl exec -it mediabot -- curl -sL https://help.twitter.com
    ^C  

Step 4: DNS Policies Using Patterns 
===================================

The above policy controlled DNS access based on exact match of the DNS domain name. Often, it is required to allow access to a subset of domains. Let's say, in the above example, ``mediabot`` pods need access to any Twitter sub-domain, for e.g., the pattern ``*.twitter.com``. We can achieve this easily by changing the ``toFQDN`` rule to use ``matchPattern`` instead of ``matchName``.

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
 
Step 5: Combining DNS, Port and L7 Rules
========================================

The DNS-based policies can be combined with port (L4) and API (L7) rules to further restrict the access. In our example, we will restrict ``mediabot`` pods to:

* Access Twitter services only on ports ``443`` and port ``80``. The ``toPorts`` section in the policy below achieves the port-based restrictions.
* On port ``80``, restrict access to only perform ``HTTP GET``. The ``rules: http`` section in the policy below achieves the L7 restrictions for port ``80``.

(Refer :ref:`l4_policy` and :ref:`l7_policy` to learn more about L4 and L7 Cilium network policies.)


.. literalinclude:: ../../examples/kubernetes-dns/dns-port-l7.yaml

.. parsed-literal::

  $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes-dns/dns-port-l7.yaml

Testing, the access to ``https://help.twitter.com`` on port ``443`` will succeed for both ``GET`` and ``POST``. Only ``GET`` will succeed for ``http://help.twitter.com`` on port ``80``, any other ``HTTP`` action will result in ``Access denied``. 

.. parsed-literal:: 
  
   $ kubectl exec -it mediabot -- curl -XGET https://help.twitter.com
   ...

   $ kubectl exec -it mediabot -- curl -XPOST https://help.twitter.com
   ...

   $ kubectl exec -it mediabot -- curl -XGET http://help.twitter.com
   ...

   $ kubectl exec -it mediabot -- curl -XPOST http://help.twitter.com
   Access denied


Step 6: Clean-up
================

.. parsed-literal::

   $ kubectl delete -f \ |SCM_WEB|\/examples/kubernetes-dns/dns-sw-app.yaml
   $ kubectl delete cnp fqdn
