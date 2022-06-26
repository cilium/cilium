.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _argocd_issues:

***********************************
Issues Deploying Cilium with ArgoCD
***********************************

There have been a lot of reports from users hitting issues with ArgoCD. This documentation 
page outlines some of the known issues.

Known issues with solutions
===========================
The following are some known issues with ArgoCD that have solutions. Click on them to 
see their solutions on GitHub.

- `ArgoCD deletes CustomResourceDefinitions that Cilium uses to implement networking and security <https://github.com/cilium/cilium/issues/17349>`__.
- `ciliumid not found  <https://github.com/cilium/cilium/issues/17614>`__.
- `Out-of-sync issues for cilium using ArgoCD <https://github.com/cilium/cilium/issues/14550>`__.
- `CiliumEndpoint missing for a pod <https://github.com/cilium/cilium/issues/17047>`__.
- `hubble-relay: failed to create gRPC client <https://github.com/cilium/cilium/issues/16361>`__.
- `Add a configmap checksum to automatically roll daemonset <https://github.com/cilium/cilium/issues/14331>`__.
- `Cilium does not recognise identity thus got policy denied <https://github.com/cilium/cilium/issues/14284>`__.
- `Intermittent 504 error from service when using ingress network policy <https://github.com/cilium/cilium/issues/13240>`__.

.. note::
    
    If you have an issue with ArgoCD that's not outlined above, check this 
    `list of ArgoCD-related issues on GitHub <https://github.com/cilium/cilium/issues?q=is%3Aissue+argocd+is%3Aclosed>`__. 
    If you can't find an issue that relates to yours, create one and/or seek help on the :term:`Slack channel`. 
    With Cilium contributors across the globe, someone is almost always available to help.