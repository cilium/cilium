.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

Special Interest Groups
=======================

All SIGs
--------

The following is a list of special interest groups (SIG) that are meeting on a
regular interval. See the respective slack channel for exact meeting cadence
and meeting links.

====================== ===================================== ============= ================================================================================
SIG                    Meeting                               Slack         Description
====================== ===================================== ============= ================================================================================
Datapath               Wednesdays, 08:00 PT                  #sig-datapath Owner of all eBPF- and Linux-kernel-related datapath code.
Documentation          None                                  #sig-docs     All documentation related discussions
Envoy                  Biweekly on Thursdays, 09:00 PT       #sig-envoy    Envoy, Istio and maintenance of all L7 protocol parsers.
Hubble                 Thursdays, 09:00 PT                   #sig-hubble   Owner of all Hubble-related code: Server, UI, CLI and Relay.
Policy                 None                                  #sig-policy   All topics related to policy. The SIG is responsible for all security relevant APIs and the enforcement logic.
Release Management     None                                  #launchpad    Responsible for the release management and backport process.
====================== ===================================== ============= ================================================================================

How to create a SIG
-------------------

1. Open a new `GitHub issue <https://github.com/cilium/cilium/issues>`_
2. Specify the title "SIG-Request: <Name>"
3. Provide a description
4. Find two Cilium committers to support the SIG.
5. Ask on #development to get the Slack channel and Zoom meeting created
6. Submit a PR to update the documentation to get your new SIG listed

Slack
=====

The Cilium community is maintaining an active Slack channel. Click `here
<https://cilium.herokuapp.com>`_ to request an invite. 

Slack channels
--------------


==================== ============================================================
Name                 Purpose
==================== ============================================================
#development         Development discussions
#ebpf                eBPF-specific questions
#general             General user discussions & questions
#git                 GitHub notifications
#kubernetes          Kubernetes specific questions
#sig-*               SIG specific discussions
#testing             CI and testing related discussions
==================== ============================================================

.. _`Policy-Zoom`: https://zoom.us/j/878657504
