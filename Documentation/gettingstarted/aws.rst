.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

***********************************************
Locking down external access using AWS metadata
***********************************************

This document serves as an introduction to using Cilium to enforce policies
based on AWS instances metadata. It is a detailed walk-through of getting a
single-node Cilium environment running on your machine. It is designed to take
15-30 minutes with some experience running Kubernetes.

.. include:: gsg_requirements.rst

Create AWS secrets
==================

Before installing Cilium, a new Kubernetes Secret with the AWS Tokens needs to
be added to your Kubernetes cluster. This Secret will allow Cilium to gather
information from the AWS API which is needed to implement ToGroups policies.

AWS Access keys and IAM role
------------------------------

To create a new access token the `following guide can be used
<https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html#cli-quick-configuration>`_.
These keys need to have certain permissions set:

.. code-block:: javascript

    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "ec2:Describe*",
                "Resource": "*"
            }
        ]
    }

As soon as you have the access tokens, the following secret needs to be added,
where it must to be encoded in base64:


.. code-block:: yaml
    :name: cilium-secret.yaml

    apiVersion: v1
    kind: Secret
    metadata:
      name: cilium-aws
      namespace: kube-system
    type: Opaque
    data:
      AWS_ACCESS_KEY_ID: ""
      AWS_SECRET_ACCESS_KEY: ""
      AWS_DEFAULT_REGION: ""

To encode in base64, the following script can be used:

.. parsed-literal::

    $ echo -n "eu-west-1"  | base64
    ZXUtd2VzdC0x

This secret stores the AWS credentials, which will be used to connect the AWS
API.

.. parsed-literal::

    $ kubectl create -f cilium-secret.yaml


To validate that the credentials are correct, the following pod can be created
for debugging purposes:

.. code-block:: yaml

    apiVersion: v1
    kind: Pod
    metadata:
      name: testing-aws-pod
      namespace: kube-system
    spec:
      containers:
      - name: aws-cli
        image: mesosphere/aws-cli
        command: ['sh', '-c', 'sleep 3600']
        env:
          - name: AWS_ACCESS_KEY_ID
            valueFrom:
              secretKeyRef:
                name: cilium-aws
                key: AWS_ACCESS_KEY_ID
                optional: true
          - name: AWS_SECRET_ACCESS_KEY
            valueFrom:
              secretKeyRef:
                name: cilium-aws
                key: AWS_SECRET_ACCESS_KEY
                optional: true
          - name: AWS_DEFAULT_REGION
            valueFrom:
              secretKeyRef:
                name: cilium-aws
                key: AWS_DEFAULT_REGION
                optional: true

To list all of the available AWS instances, the following command can be used:

.. parsed-literal::

   $ kubectl  -n kube-system exec -ti testing-aws-pod -- aws ec2 describe-instances

It is important for this demo that ``kube-dns`` is working correctly. To know the
status of ``kube-dns`` you can run the following command:
::

    $ kubectl get deployment kube-dns -n kube-system
    NAME       DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
    kube-dns   1         1         1            1           13h

Where at least one pod should be available.


Create a sample policy
======================

Deploy a demo application:
----------------------------

In this case we're going to use a demo application that is used in other guides.
These manifests will create three microservices applications: *deathstar*,
*tiefighter*, and *xwing*. In this case, we are only going to use our *xwing*
microservice to secure communications to existing AWS instances.

.. parsed-literal::

    $ kubectl create -f \ |SCM_WEB|\/examples/minikube/http-sw-app.yaml
    service "deathstar" created
    deployment "deathstar" created
    deployment "tiefighter" created
    deployment "xwing" created


Kubernetes will deploy the pods and service in the background. Running ``kubectl
get pods,svc`` will inform you about the progress of the operation.  Each pod
will go through several states until it reaches ``Running`` at which point the
pod is ready.

::

    $ kubectl get pods,svc
    NAME                             READY     STATUS    RESTARTS   AGE
    po/deathstar-76995f4687-2mxb2    1/1       Running   0          1m
    po/deathstar-76995f4687-xbgnl    1/1       Running   0          1m
    po/tiefighter                    1/1       Running   0          1m
    po/xwing                         1/1       Running   0          1m

    NAME             TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)   AGE
    svc/deathstar    ClusterIP   10.109.254.198   <none>        80/TCP    3h
    svc/kubernetes   ClusterIP   10.96.0.1        <none>        443/TCP   3h

Policy Language:
-----------------

**ToGroups** rules can be used to define policy in relation to cloud providers, like AWS.

.. code-block:: yaml

    ---
    kind: CiliumNetworkPolicy
    apiVersion: cilium.io/v2
    metadata:
      name: to-groups-sample
      namespace: default
    spec:
      endpointSelector:
        matchLabels:
          org: alliance
          class: xwing
      egress:
      - toPorts:
        - ports:
          - port: '80'
            protocol: TCP
        toGroups:
        - aws:
            securityGroupsIds:
            - 'sg-0fef46100a88d03c3'

This policy allows traffic from pod *xwing* to any AWS instance that is in
the security group with ID ``sg-0fef46100a88d03c3``.

Validate that derived policy is in place
----------------------------------------

Every time that a new policy with ToGroups rules is added, an equivalent policy
(also called "derivative policy"), will be created. This policy will contain the
set of CIDRs that correspond to the specification in ToGroups, e.g., the IPs of
all instances that are part of a specified security group. The list of IPs will
be updated periodically.

.. parsed-literal::

    $ kubectl get cnp
    NAME                                                             AGE
    to-groups-sample                                                 11s
    to-groups-sample-togroups-044ba7d1-f491-11e8-ad2e-080027d2d952   10s

Eventually, the derivative policy will contain IPs in the ToCIDR section:

.. parsed-literal::

   $ kubectl get cnp to-groups-sample-togroups-044ba7d1-f491-11e8-ad2e-080027d2d952


.. code-block:: yaml

    apiVersion: cilium.io/v2
    kind: CiliumNetworkPolicy
    metadata:
      creationTimestamp: 2018-11-30T11:13:52Z
      generation: 1
      labels:
        io.cilium.network.policy.kind: derivative
        io.cilium.network.policy.parent.uuid: 044ba7d1-f491-11e8-ad2e-080027d2d952
      name: to-groups-sample-togroups-044ba7d1-f491-11e8-ad2e-080027d2d952
      namespace: default
      ownerReferences:
      - apiVersion: cilium.io/v2
        blockOwnerDeletion: true
        kind: CiliumNetworkPolicy
        name: to-groups-sample
        uid: 044ba7d1-f491-11e8-ad2e-080027d2d952
      resourceVersion: "34853"
      selfLink: /apis/cilium.io/v2/namespaces/default/ciliumnetworkpolicies/to-groups-sample-togroups-044ba7d1-f491-11e8-ad2e-080027d2d952
      uid: 04b289ba-f491-11e8-ad2e-080027d2d952
    specs:
    - egress:
      - toCIDRSet:
        - cidr: 34.254.113.42/32
        - cidr: 172.31.44.160/32
        toPorts:
        - ports:
          - port: "80"
            protocol: TCP
      endpointSelector:
        matchLabels:
          any:class: xwing
          any:org: alliance
          k8s:io.kubernetes.pod.namespace: default
      labels:
      - key: io.cilium.k8s.policy.name
        source: k8s
        value: to-groups-sample
      - key: io.cilium.k8s.policy.uid
        source: k8s
        value: 044ba7d1-f491-11e8-ad2e-080027d2d952
      - key: io.cilium.k8s.policy.namespace
        source: k8s
        value: default
      - key: io.cilium.k8s.policy.derived-from
        source: k8s
        value: CiliumNetworkPolicy
    status:
      nodes:
        k8s1:
          enforcing: true
          lastUpdated: 2018-11-30T11:28:03.907678888Z
          localPolicyRevision: 28
          ok: true

The derivative rule should contain the following information:

- *metadata.OwnerReferences*: that contains the information about the ToGroups
  policy.

- *specs.Egress.ToCIDRSet*:  the list of private and public IPs of the instances
  that correspond to the spec of the parent policy.

- *status*: whether or not the policy is enforced yet, and when the policy was
  last updated.

The Cilium Endpoint status for the *xwing* should have policy enforcement
enabled only for egress connectivity:

.. parsed-literal::

    $ kubectl get cep xwing
    NAME    ENDPOINT ID   IDENTITY ID   POLICY ENFORCEMENT   ENDPOINT STATE   IPV4         IPV6
    xwing   23453         63929         egress               ready            10.10.0.95   f00d::a0a:0:0:22cf

In this example, *xwing* pod can only connect to ``34.254.113.42/32`` and
``172.31.44.160/32`` and connectivity to other IP will be denied.
