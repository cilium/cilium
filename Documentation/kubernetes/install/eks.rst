.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _k8s_install_eks:

*******************************************
Installation on AWS EKS using etcd operator
*******************************************

.. note::

  This is a beta level feature. Be cautious and verify the installation before
  you run this in production.

Create EKS Cluster
==================

#. Create an EKS cluster and add some worker nodes by following steps 1-3 in
   the official EKS documentation:

   `Getting Started with Amazon EKS <https://docs.aws.amazon.com/eks/latest/userguide/getting-started.html>`_

   When asked to select an AMI. We recommend to use the *EKS-optimized AMI* as
   suggested by the guide itself.

   After following the guide, you should have a cluster up and running:

   .. code:: bash

       kubectl get nodes
       NAME                                            STATUS    ROLES     AGE       VERSION
       ip-192-168-100-2.us-west-2.compute.internal     Ready     <none>    3m        v1.10.3
       ip-192-168-134-237.us-west-2.compute.internal   Ready     <none>    2m        v1.10.3
       ip-192-168-224-75.us-west-2.compute.internal    Ready     <none>    2m        v1.10.3

   .. code:: bash

       kubectl -n kube-system get pods
       NAME                       READY     STATUS    RESTARTS   AGE
       aws-node-4wbp6             1/1       Running   1          2m
       aws-node-d5fb2             1/1       Running   1          2m
       aws-node-mxwfb             1/1       Running   0          2m
       kube-dns-7cc87d595-sjcgw   3/3       Running   0          27m
       kube-proxy-jk4lk           1/1       Running   0          2m
       kube-proxy-phn6c           1/1       Running   0          2m
       kube-proxy-rctvn           1/1       Running   0          2m

#. Tell the aws-node agent to disable SNAT for all traffic

   .. code:: bash

       kubectl -n kube-system set env ds aws-node AWS_VPC_K8S_CNI_EXTERNALSNAT=true

#. Assign a fixed security identity to ``kube-dns`` by  adding the label ``io.cilium.fixed-identity: kube-dns``

   .. code:: bash

       # if using kube-dns
       kubectl patch -n kube-system deployment/kube-dns --type merge -p '{"spec":{"template":{"metadata":{"labels":{"io.cilium.fixed-identity":"kube-dns"}}}}}'
       
       # if using coredns
       kubectl patch -n kube-system deployment/coredns --type merge -p '{"spec":{"template":{"metadata":{"labels":{"io.cilium.fixed-identity":"kube-dns"}}}}}'

   This step allows Cilium to bring up ``kube-dns`` networking and enforce
   security policies before etcd is up. (Note: By default, kubernetes keeps the old ReplicaSet 
   but those sets are not running. When the deployment is deleted all ReplicaSets will be cleaned up 
   and they are not left in the users's cluster.)

Prepare etcd operator
=====================

#. Dependencies
   
   The certificate generation scripts have dependencies on ``cfssl`` and ``cfssljson``, which can be downloaded 
   from `here <https://pkg.cfssl.org/>`_ . Make sure to copy the binaries in a directory which is in your ``PATH`` 
   variable. Alternatively, if you have Go installed, then you can also get the libraries using 
   ``go get -u github.com/cloudflare/cfssl/cmd/cfssl`` 
   and ``go get -u github.com/cloudflare/cfssl/cmd/cfssljson``. 

#. Generate and deploy etcd certificates

   This certificate will be used to secure the communication between Cilium
   agents and the etcd cluster.

   .. code:: bash

       cd examples/kubernetes/addons/etcd-operator
       tls/certs/gen-cert.sh cluster.local

   Deploy the etcd certificates:

   .. code:: bash

       tls/deploy-certs.sh

#. Deploy the etcd operator

   .. code:: bash

       kubectl apply -f 00-crd-etcd.yaml

Deploy Cilium + etcd
====================

Deploy Cilium including an etcd deployment:

.. code:: bash

    cd examples/kubernetes/addons/etcd-operator
    kubectl apply -f .

Give it some time to come up as both the etcd cluster and Cilium are being
deployed in parallel. Cilium will provide basic networking to etcd in a heavily
restricted policy environment and then automatically connect to etcd as soon as
the cluster becomes available.

Verify installation
===================

Verify that everything is up and running:

.. code:: bash

    kubectl -n kube-system get pods
    NAME                            READY     STATUS    RESTARTS   AGE
    aws-node-9tj2v                  1/1       Running   0          1h
    aws-node-gt8gt                  1/1       Running   0          1h
    aws-node-xx8sc                  1/1       Running   0          1h
    cilium-54gxk                    1/1       Running   0          9m
    cilium-etcd-5t2cvng8jw          1/1       Running   0          8m
    cilium-etcd-f2rlpccpcq          1/1       Running   0          7m
    cilium-etcd-rh66gsbgqb          1/1       Running   0          8m
    cilium-qjqv8                    1/1       Running   0          9m
    cilium-sfjd2                    1/1       Running   0          9m
    etcd-operator-84dd99cfd-69q4b   1/1       Running   0          8m
    kube-dns-7cc87d595-sjcgw        3/3       Running   0          1h
    kube-proxy-jk4lk                1/1       Running   0          1h
    kube-proxy-phn6c                1/1       Running   0          1h
    kube-proxy-rctvn                1/1       Running   0          1h

.. code:: bash

    kubectl -n kube-system exec -ti cilium-qjqv8 cilium-health status
    Probe time:   2018-08-20T14:37:50Z
    Nodes:
      ip-192-168-100-2.us-west-2.compute.internal (localhost):
        Host connectivity to 192.168.100.2:
          ICMP:          OK, RTT=250.203µs
          HTTP via L3:   OK, RTT=427.923µs
        Endpoint connectivity to 10.2.107.177:
          ICMP:   OK, RTT=257.911µs
      ip-192-168-134-237.us-west-2.compute.internal:
        Host connectivity to 192.168.134.237:
          ICMP:          OK, RTT=831.244µs
          HTTP via L3:   OK, RTT=1.746408ms
        Endpoint connectivity to 10.237.49.249:
          ICMP:          OK, RTT=860.772µs
          HTTP via L3:   OK, RTT=1.848061ms
      ip-192-168-224-75.us-west-2.compute.internal:
        Host connectivity to 192.168.224.75:
          ICMP:          OK, RTT=530.695µs
          HTTP via L3:   OK, RTT=1.234267ms
        Endpoint connectivity to 10.75.69.203:
          ICMP:          OK, RTT=669.397µs
          HTTP via L3:   OK, RTT=1.273788ms
