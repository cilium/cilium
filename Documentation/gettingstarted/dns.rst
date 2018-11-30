.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

****************************************
Getting Started Using DNS-Based Policies
****************************************

This document serves as an introduction for using Cilium to enforce DNS-based
security policies for Kubernetes services.

.. include:: gsg_intro.rst
.. include:: minikube_intro.rst
.. include:: cilium_install.rst

Step 2: Deploy the Demo Application
===================================

DNS-based policies are very useful for controlling access to services running outside the Kubernetes cluster. The CIDR-based policies are cumbersome and hard to maintain as the IPs associated with services can change frequently. The DNS-based policies provide a easy mechanism to specify access control while leaving the harder aspects of resolving and enforcing IP-based filters to Cilium. 

In our Star Wars-inspired example, there are three microservices applications and an external service to test the egress DNS policies.

- *deathstar* is a Kubernetes service serving HTTP requests and is backed by two pods.
- *tiefighter* and *xwing* are client pods to test the DNS based egress policies
- http://starwars.covalent.link is the external service outside of Kubernetes cluster

**Application Topology for Cilium and Kubernetes**

.. image:: images/cilium_http_gsg.png
   :scale: 30 %

The file ``http-sw-app.yaml`` contains a `Kubernetes Deployment <https://kubernetes.io/docs/concepts/workloads/controllers/deployment/>`_ for each of the three services.

.. parsed-literal::

    $ kubectl create -f \ |SCM_WEB|\/examples/minikube/http-sw-app.yaml
    $ kubectl get pods,svc
    NAME                             READY     STATUS    RESTARTS   AGE
    po/deathstar-76995f4687-2mxb2    1/1       Running   0          1m
    po/deathstar-76995f4687-xbgnl    1/1       Running   0          1m
    po/tiefighter                    1/1       Running   0          1m
    po/xwing                         1/1       Running   0          1m

    NAME             TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)   AGE
    svc/deathstar    ClusterIP   10.109.254.198   <none>        80/TCP    3h
    svc/kubernetes   ClusterIP   10.96.0.1        <none>        443/TCP   3h


Step 3: Check Current Access
============================

Since we have not enforced any policies, both *tiefigher* and *xwing* will be able to access all the external services. 

.. parsed-literal::

    $ kubectl exec -it xwing -- curl starwars.covalent.link/naboo/landing-request
    Ship landed
    $ kubectl exec -it tiefighter -- curl starwars.covalent.link/naboo/landing-request
    Ship landed


Step 4: Apply DNS Egress Policy
===============================

We will enforce a policy which allows *tiefighter* to reach **only** the ``starwars.covalent.link`` service but doesn't allow *xwing* to reach any external service. The DNS-based policy is captured by the ``toFQDNs`` section which:

- Uses labels to identify pods that are allowed to access an external service (in this example, all pods with ``org=empire``). With this approach, any future pods that match labels will automatically get the access to the external service while others will not. 
- Uses DNS names for specifying the external service instead of IP addresses (in this example ``starwars.covalent.link``). In future if the IP addresses of endpoints for the external service change, we don't have to track and update the network policies. Cilium takes care of handling the changes in IPs associated with the DNS.

.. literalinclude:: ../../examples/minikube/dns_policy.yaml

.. parsed-literal::

  $ kubectl create -f \ |SCM_WEB|\/examples/minikube/dns_policy.yaml


Testing the policy, we see that *tiefighter* has access to the external service but doesn't have access to any other external service. And *xwing* doesn't have access to any external service including ``starwars.covalent.link``. 

.. parsed-literal::

   $ kubectl exec -it tiefighter -- curl starwars.covalent.link/naboo/landing-request
   Landing request granted.

   ! Welcome to Planet Naboo !

   $ kubectl exec -it tiefighter -- curl google.com
   ^C

   $ kubectl exec -it xwing -- curl starwars.covalent.link/naboo/landing-request
   ^C


Step 5: Extending DNS Policy With L7 Rules
==========================================

Cilium L3, L4 and L7 policies are modular and can be combined with each other to enforce granular controls. So the DNS-based policies can be combined with port and L7 level rules for enforcing tighter access control. This is particularly useful if you have multi-tenant services in your VPC such as Kafka, Cassandra, Memcache, or HTTP-based services, which require restricted access for each tenant

Continuing with our example, we will restrict the *tiefighter* access to only perform ``HTTP GET landing-request`` on the external service.

.. literalinclude:: ../../examples/minikube/dns_policy_with_l7.yaml

.. parsed-literal::

  $ kubectl create -f \ |SCM_WEB|\/examples/minikube/dns_policy_with_l7.yaml

Testing the policy, you can see that *tiefighter* gets access denied while requesting any other operations from the external service. 

.. parsed-literal:: 
  
   $ kubectl exec -it tiefighter -- curl starwars.covalent.link/naboo/landing-request
   Landing request granted.

   ! Welcome to Planet Naboo !

   $ kubectl exec -it tiefighter -- curl starwars.covalent.link/naboo/stats
   Access denied
   
Step 6: Clean-up
================

.. parsed-literal::

   $ kubectl delete -f \ |SCM_WEB|\/examples/minikube/http-sw-app.yaml
   $ kubectl delete cnp to-fqdn

