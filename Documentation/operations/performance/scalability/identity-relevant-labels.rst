.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _identity-relevant-labels:

*********************************
Limiting Identity-Relevant Labels
*********************************

We recommend that operators with larger environments limit the set of
identity-relevant labels to avoid frequent creation of new security identities.
Many Kubernetes labels are not useful for policy enforcement or visibility. A
few good examples of such labels include timestamps or hashes. These labels,
when included in evaluation, cause Cilium to generate a unique identity for each
pod instead of a single identity for all of the pods that comprise a service or
application.

By default, Cilium considers all labels to be relevant for identities, with the
following exceptions:

================================== ==============================================
Label                               Description
---------------------------------- ----------------------------------------------
``any:!io.kubernetes``             Ignore all ``io.kubernetes`` labels
``any:!kubernetes\.io``            Ignore all other ``kubernetes\.io`` labels
``any:!beta.kubernetes\.io``       Ignore all ``beta\.kubernetes\.io`` labels
``any:!k8s\.io``                   Ignore all ``k8s\.io`` labels
``any:!pod-template-generation``   Ignore all ``pod-template-generation`` labels
``any:!pod-template-hash``         Ignore all ``pod-template-hash`` labels
``any:!controller-revision-hash``  Ignore all ``controller-revision-hash`` labels
``any:!annotation.*``              Ignore all ``annotation`` labels
``any:!etcd_node``                 Ignore all ``etcd_node`` labels
================================== ==============================================

The above label patterns are all *exclusive label patterns*, that is to say
they define which label keys should be ignored. These are identified by the
presence of the ``!`` character.

Label configurations that do not contain the ``!`` character are *inclusive
label patterns*. Once at least one inclusive label pattern is added, only
labels that match the inclusive label configuration may be considered relevant
for identities. Additionally, when at least one inclusive label pattern is
configured, the following inclusive label patterns are automatically added to
the configuration:

========================================== =====================================================
Label                                      Description
------------------------------------------ -----------------------------------------------------
``reserved:.*``                            Include all ``reserved:`` labels
``any:io\.kubernetes\.pod\.namespace``     Include all ``io.kubernetes.pod.namespace`` labels
``any:io\.cilium\.k8s\.namespace\.labels`` Include all ``io.cilium.k8s.namespace.labels`` labels
``any:app\.kubernetes\.io``                Include all ``app.kubernetes.io`` labels
========================================== =====================================================



Configuring Identity-Relevant Labels
------------------------------------

To limit the labels used for evaluating Cilium identities, edit the Cilium
ConfigMap object using ``kubectl edit cm -n kube-system cilium-config`` and
insert a line to define the label patterns to include or exclude. Alternatively,
this attribute can also be set via helm option ``--set labels=<values>``.

.. code-block:: yaml

    apiVersion: v1
    data:
    ...
      kube-proxy-replacement: partial
      labels:  "k8s:io.kubernetes\\.pod\\.namespace k8s:k8s-app k8s:app k8s:name"
      enable-ipv4-masquerade: "true"
      monitor-aggregation: medium
    ...

.. note:: The double backslash in ``\\.`` is required to escape the slash in
          the YAML string so that the regular expression contains ``\.``.

Label patterns are regular expressions that are implicitly anchored at the
start of the label. For example ``example\.com`` will match labels that start
with ``example.com``, whereas ``.*example\.com`` will match labels that contain
``example.com`` anywhere. Be sure to escape periods in domain names to avoid
the pattern matching too broadly and therefore including or excluding too many
labels.

Upon defining a custom list of label patterns in the ConfigMap, Cilium adds the
provided list of label patterns to the default list of label patterns. After
saving the ConfigMap, restart the Cilium Agents to pickup the new label pattern
setting.

.. code-block:: shell-session

    kubectl delete pods -n kube-system -l k8s-app=cilium

Existing identities will not change as a result of this new configuration. To
apply the new label pattern setting to existing identities, restart the
associated pods. Upon restart, new identities will be created. The old
identities will be garbage collected by the Cilium Operator once they are no
longer used by any Cilium endpoints.

When specifying multiple label patterns to evaluate, provide the list of labels
as a space-separated string.

Including Labels
----------------

Labels can be defined as a list of labels to include. Only the labels specified
and the default inclusive labels will be used to evaluate Cilium identities:

.. code-block:: yaml

    labels: "k8s:io.kubernetes\\.pod\\.namespace k8s:k8s-app k8s:app k8s:name"

The above configuration would only include the following label keys when
evaluating Cilium identities:

- k8s:k8s-app
- k8s:app
- k8s:name
- reserved:.*
- io\.kubernetes\.pod\.namespace
- io\.cilium\.k8s.namespace\.labels
- app\.kubernetes\.io

Note that ``k8s:io\.kubernetes\.pod\.namespace`` is already included in default
label ``io\.kubernetes\.pod\.namespace``.

Labels with the same prefix as defined in the configuration will also be
considered. This lists some examples of label keys that would also be evaluated
for Cilium identities:

- k8s-app-team
- app-production
- name-defined

When a single inclusive label is added to the filter, all labels not defined
in the default list will be excluded. For example, pods running with the
security labels ``team=team-1, env=prod`` will have the label ``env=prod``
ignored as soon Cilium is started with the filter ``k8s:team``.

Excluding Labels
----------------

Label patterns can also be specified as a list of exclusions. Exclude labels
by placing an exclamation mark after colon separating the prefix and pattern.
When defined as a list of exclusions, Cilium will include the set of default
labels, but will exclude any matches in the provided list when evaluating
Cilium identities:

.. code-block:: yaml

    labels: "k8s:!controller-uid k8s:!job-name"

The provided example would cause Cilium to exclude any of the following label
matches:

- k8s:controller-uid
- k8s:job-name
