.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k8s_quick_install:

******************
Quick Installation
******************

This guides takes you through the quick installation procedure.  The default
settings will store all required state using Kubernetes custom resource
definitions (CRDs). This is the simplest installation method as it only depends
on Kubernetes and does not require additional external dependencies. It is a
good option for environments up to about 250 nodes. For bigger environments or
for environments which want to leverage the clustermesh functionality, a
kvstore set up is required which can be set up using an
:ref:`k8s_install_etcd` or using the :ref:`k8s_install_etcd_operator`.

Should you encounter any issues during the installation, please refer to the
:ref:`troubleshooting_k8s` section and / or seek help on the `Slack channel`.

Please consult the Kubernetes :ref:`k8s_requirements` for information on  how
you need to configure your Kubernetes cluster to operate with Cilium.


Install Cilium
==============

.. parsed-literal::

    kubectl create -f \ |SCM_WEB|\/install/kubernetes/quick-install.yaml

.. include:: k8s-install-validate.rst
