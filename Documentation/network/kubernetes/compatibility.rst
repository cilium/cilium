.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k8scompatibility:

************************
Kubernetes Compatibility
************************

Cilium is compatible with multiple Kubernetes API Groups. Some are deprecated
or beta, and may only be available in specific versions of Kubernetes.

All Kubernetes versions listed are e2e tested and guaranteed to be compatible
with Cilium. Older and newer Kubernetes versions, while not listed, will depend
on the forward / backward compatibility offered by Kubernetes.

+------------------------+---------------------------+----------------------------------+
| k8s Version            | k8s NetworkPolicy API     | CiliumNetworkPolicy              |
+------------------------+---------------------------+----------------------------------+
|                        |                           | ``cilium.io/v2`` has a           |
| 1.28, 1.29, 1.30, 1.31 | * `networking.k8s.io/v1`_ | :term:`CustomResourceDefinition` |
+------------------------+---------------------------+----------------------------------+

As a general rule, Cilium aims to run e2e tests using the latest build from the
development branch against currently supported Kubernetes versions defined in
`Kubernetes Patch Releases <https://kubernetes.io/releases/patch-releases/>`_
page.

Once a release branch gets created from the development branch, Cilium typically
does not change the Kubernetes versions it uses to run e2e tests for the entire
maintenance period of that particular release.

Additionally, Cilium runs e2e tests against various cloud providers' managed
Kubernetes offerings using multiple Kubernetes versions. See the following links
for the current test matrix for each cloud provider:

- :git-tree:`AKS <.github/actions/azure/k8s-versions.yaml>`
- :git-tree:`EKS <.github/actions/eks/k8s-versions.yaml>`
- :git-tree:`GKE <.github/actions/gke/k8s-versions.yaml>`

Cilium CRD schema validation
============================

Cilium uses a CRD for its Network Policies in Kubernetes. This CRD might have
changes in its schema validation, which allows it to verify the correctness of
a Cilium Clusterwide Network Policy (CCNP) or a Cilium Network Policy (CNP).

The CRD itself has an annotation, ``io.cilium.k8s.crd.schema.version``, with the
schema definition version. By default, Cilium automatically updates the CRD, and
its validation, with a newer one.

The following table lists all Cilium versions and their expected schema
validation version:

.. include:: compatibility-table.rst

.. _networking.k8s.io/v1: https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#networkpolicy-v1-networking-k8s-io
