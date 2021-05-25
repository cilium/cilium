.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

Weekly Community Meeting
========================

The Cilium contributors gather every Wednesday at 8am PDT, 17:00 CEST, for a
one-hour Zoom call open to everyone. During that time, we discuss:

- the statuses of the next releases for each supported Cilium release
- the current state of our CI: flakes being investigated and upcoming
  changes
- the development items for the next release
- miscellaneous topics during the open session

If you want to discuss something during the next meeting's open session,
you can add it to `the meeting's Google doc
<https://docs.google.com/document/d/1Y_4chDk4rznD6UgXPlPvn3Dc7l-ZutGajUv1eF0VDwQ/edit#>`_.
The Zoom link to the meeting is available in the #development Slack
channel and in `the meeting notes
<https://docs.google.com/document/d/1Y_4chDk4rznD6UgXPlPvn3Dc7l-ZutGajUv1eF0VDwQ/edit#>`_.

Slack
=====

Our Cilium & eBPF Slack is the main discussion space for the Cilium community.
Click `here <https://cilium.herokuapp.com>`_ to request an invite. 

Slack channels
--------------

==================== ====================================
Name                 Purpose
==================== ====================================
#general             General user discussions & questions
#hubble              Questions on Hubble
#kubernetes          Kubernetes-specific questions
#networkpolicy       Questions on network policies
#release             Release announcements only
==================== ====================================

You can join the following channels if you are looking to contribute to
Cilium:

==================== ====================================
Name                 Purpose
==================== ====================================
#development         Development discussions
#git                 GitHub notifications
#sig-*               SIG-specific discussions (see below)
#testing             Testing and CI discussions
==================== ====================================

If you are interested in eBPF, then the following channels are for you:

==================== ====================================================================
Name                 Purpose
==================== ====================================================================
#ebpf                eBPF-specific questions
#ebpf-lsm            Questions on BPF LSM
#ebpf-news           Contributions to the `eBPF Updates <https://ebpf.io/blog>`_
#libbpf-go           Questions on the `eBPF Go library <https://github.com/cilium/ebpf>`_
==================== ====================================================================


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
Datapath               Thursdays, 08:00 PT                   #sig-datapath Owner of all eBPF- and Linux-kernel-related datapath code.
Documentation          None                                  #sig-docs     All documentation related discussions
Envoy                  On demand                             #sig-envoy    Envoy, Istio and maintenance of all L7 protocol parsers.
Hubble                 During community meeting              #sig-hubble   Owner of all Hubble-related code: Server, UI, CLI and Relay.
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
