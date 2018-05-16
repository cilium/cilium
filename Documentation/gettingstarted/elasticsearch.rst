**************************************
Getting Started Securing Elasticsearch 
**************************************

This document serves as an introduction for using Cilium to enforce Elasticsearch-aware
security policies.  It is a detailed walk-through of getting a single-node
Cilium environment running on your machine. It is designed to take 15-30
minutes.

.. include:: gsg_intro.rst
.. include:: minikube_intro.rst
.. include:: cilium_install.rst

Step 2: Deploy the Demo Application
===================================

With Cilium running, we can deploy our demo Elasticsearch application. The demo application aligns with our tradition of using Star Wars-themed examples. We go back to the time when Vader had recently been converted to the Dark side. Darth Sidious wanted to share some of the books that he had authored. The books were stored in a Elasticsearch database and exposed via service of the same name. Both Sidious and Vader accessed these books using *python-based clients* running in Kubernetes pods. 

.. image:: images/cilium_es_gsg_topology.png

The file ``es-sw-app.yaml`` will deploy the Elasticsearch service which stores Sidious' books and it will create one Vader and Sidious client pods each.

.. parsed-literal::

    $ kubectl create -f \ |SCM_WEB|\/examples/kubernetes-es/es-sw-app.yaml
      serviceaccount "elasticsearch" created
      service "elasticsearch" created
      replicationcontroller "es" created
      role "elasticsearch" created
      rolebinding "elasticsearch" created
      deployment "sidious" created
      deployment "vader" created

    $ kubectl get svc,pods
      NAME                TYPE           CLUSTER-IP       EXTERNAL-IP   PORT(S)                         AGE
      svc/elasticsearch   ClusterIP      10.100.148.190   <pending>     9200:32048/TCP,9300:31071/TCP   3m
      svc/kubernetes      ClusterIP      10.96.0.1        <none>        443/TCP                         18m

      NAME                         READY     STATUS    RESTARTS   AGE
      po/es-mpzh2                  1/1       Running   0          3m
      po/sidious                   1/1       Running   0          3m
      po/vader                     1/1       Running   0          3m

Step 3: Security Risks for Elasticsearch Access
===============================================

A fundamental security concern for Elasticsearch service is *what client services should be allowed to access which content and perform what actions*. This is an access control problem at the API-layer (i.e L7-layer). In this example, the security challenge for Darth Sidious is that he does not trust Vader, a newly converted apprentice. So he is very worried that Vader can manipulate and ``PUT`` new versions of his books! Sidious wants Vader to have only ``GET`` access including ability to *search* the database. But he does not want Vader to have "PUT" access. Run the following commands to see that both Sidious and Vader have ``GET`` and ``PUT`` access to the Elasticsearch service.

.. parsed-literal::

    $ kubectl exec sidious -- python create.py
      Creating/Updating Books
      created :  {'_index': 'sidious', '_type': 'tome', '_id': '1', '_version': 3, 'result': 'created', '_shards': {'total': 2, 'successful': 1, 'failed': 0}, 'created': True}
      created :  {'_index': 'sidious', '_type': 'tome', '_id': '2', '_version': 4, 'result': 'created', '_shards': {'total': 2, 'successful': 1, 'failed': 0}, 'created': True}    
    
    $ kubectl exec sidious -- python get_search.py 
      Searching for Books by Darth Sidious
      Got 2 Hits:
      {'_index': 'sidious', '_type': 'tome', '_id': '2', '_score': 1.0, '_source': {'author': 'sidious', 'title': 'Welcome to the Dark Side'}}
      {'_index': 'sidious', '_type': 'tome', '_id': '1', '_score': 1.0, '_source': {'author': 'sidious', 'title': 'Convert Jedi to Dark Side: 101'}}
      Get Book 1 by Darth Sidious
      {'author': 'sidious', 'title': 'Convert Jedi to Dark Side: 101'}

Good that Sidious has access to perform PUT and GET. Let's see what happens when Vader has both ``GET`` and ``PUT`` access. Vader can completely modify the books! (Note the change in book titles e.g. *Why convert a Jedi!*) 

.. parsed-literal::

    $ kubectl exec vader -- python update.py 
      Creating/Updating Books
      updated :  {'_index': 'sidious', '_type': 'tome', '_id': '1', '_version': 4, 'result': 'updated', '_shards': {'total': 2, 'successful': 1, 'failed': 0}, 'created': False}
      updated :  {'_index': 'sidious', '_type': 'tome', '_id': '2', '_version': 5, 'result': 'updated', '_shards': {'total': 2, 'successful': 1, 'failed': 0}, 'created': False}

    $ kubectl exec vader -- python get_search.py 
      Searching for Books by Darth Sidious
      Got 2 Hits:
      {'_index': 'sidious', '_type': 'tome', '_id': '2', '_score': 1.0, '_source': {'author': 'sidious', 'title': 'Force is Same for Dark Side and Jedi'}}
      {'_index': 'sidious', '_type': 'tome', '_id': '1', '_score': 1.0, '_source': {'author': 'sidious', 'title': 'Why Convert a Jedi!'}}
      Get Book 1 by Darth Sidious
      {'author': 'sidious', 'title': 'Why Convert a Jedi!'}


Step 4: Securing Elasticsearch Using Cilium
===========================================

Fortunately, the empire DevOps team is using Cilium for their Kubernetes cluster. Cilium provides L7 visibility and security policies to control Elasticsearch API access. In this case, Sidious orders to get the following policy pushed which gives his pods both ``GET`` and ``PUT`` access but restricts Vader's pods to only ``GET`` access.

.. literalinclude:: ../../examples/kubernetes-es/es-policy.yaml


Cilium follows the white-list, zero privilege model for security. A *CiliumNetworkPolicy* contains a list of rules that define allowed requests, meaning that requests that do not match any rules are denied as invalid. 

In this example, the policy rules are defined for inbound traffic (i.e., "ingress") connections to *elasticsearch* service. Note that the endpoints selected as backend for the service are defined by the *selector* labels. *Selector* labels are same concept as Kubernetes uses to define the service. In this example, label ``component: es`` defines the pods that are part of the elasticsearch service.

Since this is an ingress rule, we also see the labels used to identify the ``fromEndpoints`` which are calling into the elasticsearch service. One set of ``fromEndpoints`` are identified by labels ``name: sidious, role: lord`` (i.e. all Sith Lords named Sidious). These endpoints have both GET and PUT access as seen in the http rules section. Whereas the other ``fromEndpoints`` identified by labels ``name: vader, role: apprentice`` (i.e. all apprentice named Vader) only have GET access to specific paths including *search*. 

Apply this Elasticsearch-aware network security policy using ``kubectl``:

.. parsed-literal::

    $ kubectl create -f \ |SCM_WEB|\/examples/kubernetes-es/es-sw-policy.yaml
      ciliumnetworkpolicy "secure-empire-es" created

Testing the security policy, Sidious still has both the ``GET`` and ``PUT`` access. But Vader now only has ``GET`` access and any attempts to ``PUT`` results in access denied. 

.. parsed-literal::

    $ kubectl exec sidious -- python create.py 
      Creating/Updating Books
      updated :  {'_index': 'sidious', '_type': 'tome', '_id': '1', '_version': 5, 'result': 'updated', '_shards': {'total': 2, 'successful': 1, 'failed': 0}, 'created': False}
      updated :  {'_index': 'sidious', '_type': 'tome', '_id': '2', '_version': 6, 'result': 'updated', '_shards': {'total': 2, 'successful': 1, 'failed': 0}, 'created': False}

    $ kubectl exec sidious -- python get_search.py
      Searching for Books by Darth Sidious
      Got 2 Hits:
      {'_index': 'sidious', '_type': 'tome', '_id': '2', '_score': 1.0, '_source': {'author': 'sidious', 'title': 'Welcome to the Dark Side'}}
      {'_index': 'sidious', '_type': 'tome', '_id': '1', '_score': 1.0, '_source': {'author': 'sidious', 'title': 'Convert Jedi to Dark Side: 101'}}
      Get Book 1 by Darth Sidious
      {'author': 'sidious', 'title': 'Convert Jedi to Dark Side: 101'}

    $ kubectl exec vader -- python get_search.py
      Searching for Books by Darth Sidious
      Got 2 Hits:
      {'_index': 'sidious', '_type': 'tome', '_id': '2', '_score': 1.0, '_source': {'author': 'sidious', 'title': 'Welcome to the Dark Side'}}
      {'_index': 'sidious', '_type': 'tome', '_id': '1', '_score': 1.0, '_source': {'author': 'sidious', 'title': 'Convert Jedi to Dark Side: 101'}}
      Get Book 1 by Darth Sidious
      {'author': 'sidious', 'title': 'Convert Jedi to Dark Side: 101'}
    

    $ kubectl exec vader -- python update.py
      PUT http://elasticsearch.default.svc.cluster.local:9200/sidious/tome/1 [status:403 request:0.007s]
      Undecodable raw error response from server: Expecting value: line 1 column 1 (char 0)
      Creating/Updating Books
      Traceback (most recent call last):
        File "update.py", line 10, in <module>
          res = es.index(index="sidious", doc_type="tome", id=1, body=book1)
        ...
        ...
      elasticsearch.exceptions.AuthorizationException: TransportError(403, 'Access denied\r\n')
      command terminated with exit code 1
    
Step 5: Bonus
=============

Another common problem that the DevOps team encountered was accidental/deliberate deletion of the books. So with the above Cilium security policy, they are able to restrict ``DELETE`` calls as well! Run below commands to confirm that neither Sidious nor Vader can delete the books.

.. parsed-literal::

    $ kubectl exec vader -- python delete.py
      DELETE http://elasticsearch.default.svc.cluster.local:9200/sidious/tome/1 [status:403 request:0.006s]
      Deleting Book 1
      Undecodable raw error response from server: Expecting value: line 1 column 1 (char 0)
      Traceback (most recent call last):
        File "delete.py", line 6, in <module>
          res = es.delete(index="sidious", doc_type="tome", id=1)
        ...
        ...
      elasticsearch.exceptions.AuthorizationException: TransportError(403, 'Access denied\r\n')
      command terminated with exit code 1

    $ kubectl exec sidious -- python delete.py
      DELETE http://elasticsearch.default.svc.cluster.local:9200/sidious/tome/1 [status:403 request:0.005s]
      Undecodable raw error response from server: Expecting value: line 1 column 1 (char 0)
      Deleting Book 1
      Traceback (most recent call last):
        File "delete.py", line 6, in <module>
          res = es.delete(index="sidious", doc_type="tome", id=1)
        ...
        ...
      elasticsearch.exceptions.AuthorizationException: TransportError(403, 'Access denied\r\n')
      command terminated with exit code 1

Step 6: Clean Up
================

You have now installed Cilium, deployed a demo app, and tested Elasticsearch-aware network security policies. To clean up, run:

::

    $ minikube delete
