.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
      http://docs.cilium.io

.. _troubleshooting_k8s:

***************
Troubleshooting
***************

Verifying the installation
==========================

Check the status of the `DaemonSet` and verify that all desired instances are in
"ready" state:

.. code:: bash

        $ kubectl --namespace kube-system get ds
        NAME      DESIRED   CURRENT   READY     NODE-SELECTOR   AGE
        cilium    1         1         0         <none>          3s

In this example, we see a desired state of 1 with 0 being ready. This indicates
a problem. The next step is to list all cilium pods by matching on the label
``k8s-app=cilium`` and also sort the list by the restart count of each pod to
easily identify the failing pods:

.. code:: bash

        $ kubectl --namespace kube-system get pods --selector k8s-app=cilium \
                  --sort-by='.status.containerStatuses[0].restartCount'
        NAME           READY     STATUS             RESTARTS   AGE
        cilium-813gf   0/1       CrashLoopBackOff   2          44s

Pod ``cilium-813gf`` is failing and has already been restarted 2 times. Let's
print the logfile of that pod to investigate the cause:

.. code:: bash

        $ kubectl --namespace kube-system logs cilium-813gf
        INFO      _ _ _
        INFO  ___|_| |_|_ _ _____
        INFO |  _| | | | | |     |
        INFO |___|_|_|_|___|_|_|_|
        INFO Cilium 0.8.90 f022e2f Thu, 27 Apr 2017 23:17:56 -0700 go version go1.7.5 linux/amd64
        CRIT kernel version: NOT OK: minimal supported kernel version is >= 4.8

In this example, the cause for the failure is a Linux kernel running on the
worker node which is not meeting :ref:`admin_system_reqs`.

If the cause for the problem is not apparent based on these simple steps,
please come and seek help on our `Slack channel`.

Migrating Cilium TPR to CRD
===========================

Prior to Kubernetes 1.7, Cilium Network Policy (CNP) objects were imported as a `Kubernetes ThirdPartyResource (TPRs) <https://kubernetes.io/docs/tasks/access-kubernetes-api/migrate-third-party-resource/>`_.
In Kubernetes ``>=1.7.0``, TPRs are now deprecated, and will be removed in Kubernetes 1.8. TPRs are  replaced by `Custom Resource Definitions (CRDs) <https://kubernetes.io/docs/concepts/api-extension/custom-resources/#customresourcedefinitions>`_.  Thus, as part of the upgrade process to Kubernetes 1.7, Kubernetes has provided documentation for `migrating TPRs to CRDS <http://cilium.link/migrate-tpr>`_. 

The following instructions document how to migrate CiliumNetworkPolicies existing as TPRs from a Kubernetes cluster which was previously running versions ``< 1.7.0`` to CRDs on a Kubernetes cluster running versions ``>= 1.7.0``. This is meant to correspond to steps 4-6 of the `aforementioned guide <http://cilium.link/migrate-tpr>`_.

Cilium adds the CNP CRD automatically; check to see that the CNP CRD has been added by Cilium:

.. code:: bash

       $ kubectl get customresourcedefinition
       NAME                              KIND
       ciliumnetworkpolicies.cilium.io   CustomResourceDefinition.v1beta1.apiextensions.k8s.io

Save your existing CNPs which were previously added as TPRs:

.. code:: bash

       $ kubectl get ciliumnetworkpolicies --all-namespaces -o yaml > cnps.yaml

Change the version of the Cilium API from v1 to v2 in the YAML file to which you just saved your old CNPs. The Cilium API is versioned to account for the change from TPR to CRD:

.. code:: bash

       $ cp cnps.yaml cnps.yaml.new
       $ # Edit the version
       $ vi cnps.yaml.new
       $ # The diff of the old vs. new YAML file should be similar to the output below.
       $ diff cnps.yaml cnps.yaml.new
       3c3
       < - apiVersion: cilium.io/v1
       ---
       > - apiVersion: cilium.io/v2
       10c10
       <     selfLink: /apis/cilium.io/v1/namespaces/default/ciliumnetworkpolicies/guestbook-web-deprecated
       ---
       >     selfLink: /apis/cilium.io/v2/namespaces/default/ciliumnetworkpolicies/guestbook-web-deprecated

Delete your old CNPs:

.. code:: bash

       $ kubectl delete ciliumnetworkpolicies --all
       $ kubectl delete thirdpartyresource cilium-network-policy.cilium.io

Add the changed CNPs back as CRDs:

.. code:: bash

       $ kubectl create -f cnps.yaml.new

Check that your CNPs are added:

.. code:: bash

       $ kubectl get ciliumnetworkpolicies
       NAME                       KIND
       guestbook-web-deprecated   CiliumNetworkPolicy.v2.cilium.io
       multi-rules-deprecated     CiliumNetworkPolicy.v2.cilium.io   Policy to test multiple rules in a single file   2 item(s)

Now if you try to create a CNP as a TPR, you will get an error:

.. code:: bash

       $ Error from server (BadRequest): error when creating "cilium-tpr.yaml": the API version in the data (cilium.io/v1) does not match the expected API version (cilium.io/v2)
