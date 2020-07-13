.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _identity-relevant-labels:

*********************************
Limiting Identity-Relevant Labels
*********************************

We recommend that operators in larger environments limit the set of
identity-relevant labels to avoid frequent creation of new security identities.
Many Kubernetes labels are not useful for policy enforcement or visibility. A
few good examples of such labels include timestamps or hashes. These labels,
when included in evaluation, cause Cilium to generate a unique identity for each
pod instead of a single identity for all of the pods that comprise a service or
application.

By default, Cilium evaluates the following labels:

================================ ==============================================
Label                            Description
-------------------------------- ----------------------------------------------
k8s:io.kubernetes.pod.namespace  Include all io.kubernetes.pod.namespace labels
k8s:app.kubernetes.io            Include all app.kubernetes.io labels
k8s:!io.kubernetes               Ignore all io.kubernetes labels
k8s:kubernetes.io                Ignore all other kubernetes.io labels
k8s:beta.kubernetes.io           Ignore all beta.kubernetes.io labels
k8s:k8s.io                       Ignore all k8s.io labels
k8s:!pod-template-generation     Ignore all pod-template-generation labels
k8s:!pod-template-hash           Ignore all pod-template-hash labels
k8s:!controller-revision-hash    Ignore all controller-revision-hash labels
k8s:!annotation.*                Ignore all annotation labels
k8s:!etcd_node                   Ignore all etcd_node labels
================================ ==============================================

Configuring Identity-Relevant Labels
------------------------------------

To limit the labels used for evaluating Cilium identities, edit the Cilium
ConfigMap object using "kubectl edit cm -n kube-system cilium-config"
and insert a line to define the labels to include or exclude.

.. code-block:: yaml

    apiVersion: v1
    data:
    ...
      kube-proxy-replacement: partial
      labels: ...
      masquerade: "true"
      monitor-aggregation: medium
    ...


After saving the ConfigMap, restart the Cilium Agents to pickup the new labels
setting.

Existing identities will not change as a result of this new configuration. To
apply the new label setting to existing identities, restart the associated pods.
Upon restart, new identities will be created. The old identities will be garbage
collected by the Cilium Operator once they are no longer used by any Cilium
endpoints.

When specifying multiple labels to evaluate, provide the list of labels as a
space-separated string.

.. code-block:: bash

	 labels: "prefix:labelA prefix:labelB"

Including Labels
----------------

Labels can be defined as a list of labels to include. Only the labels specified
will be used to evaluate Cilium identities:

.. code-block:: bash

    labels: "k8s:io.kubernetes.pod.namespace k8s:k8s-app k8s:app k8s:name"

The above configuration would only include the following labels when evaluating
Cilium identities:

- io.kubernetes.pod.namespace=*
- k8s-app=*
- app=*
- name=*

Excluding Labels
----------------

Labels can also be specified as a list of exclusions. Exclude a label by placing
an exclamation mark after colon separating the prefix and label. When defined as a
list of exclusions, Cilium will include the set of default labels, but will
exclude any matches in the provided list when evaluating Cilium identities:

.. code-block:: bash

    labels: "k8s:!controller-uid k8s:!job-name"

The provided example would cause Cilium to exclude any of the following label
matches:

- k8s:controller-uid=*
- k8s:job-name=*
