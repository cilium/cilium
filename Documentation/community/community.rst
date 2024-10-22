.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _community-meeting:

Community Meetings
==================

The Cilium contributors gather regularly for a Zoom call open to everyone.
During that time, we discuss:

- Status of the next releases for each supported Cilium release
- Current state of our CI: flakes being investigated and upcoming changes
- Development items for the next release
- Any other community-relevant topics during the open session

If you want to discuss something during the next meeting's open session, you
can add it to the meeting's Google doc. The Zoom link to the meeting is
available in the ``#development`` Slack channel and in the meeting notes.

Weekly Community Meeting
------------------------

This is a weekly meeting for all contributors.

- Date: Every Wednesday at 8:00 AM US/Pacific (Los Angeles)
- Meeting notes: `Google Doc <https://docs.google.com/document/d/1Y_4chDk4rznD6UgXPlPvn3Dc7l-ZutGajUv1eF0VDwQ/edit#>`__

Monthly APAC Community Meeting
------------------------------

This is a monthly community meeting held at APAC friendly time.

- Date: Every third Wednesday at 4:30 UTC
- Meeting notes: `Google Doc <https://docs.google.com/document/d/1egv4qLydr0geP-GjQexYKm4tz3_tHy-LCBjVQcXcT5M/edit#>`__

Slack
=====

Our `Cilium & eBPF Slack <Cilium Slack_>`_ is the main discussion space for the
Cilium community.

Slack channels
--------------

======================== ======================================================
Name                     Purpose
======================== ======================================================
``#general``             General user discussions & questions
``#hubble``              Questions on Hubble
``#kubernetes``          Kubernetes-specific questions
``#networkpolicy``       Questions on network policies
``#release``             Release announcements only
``#service-mesh``        Questions on Cilium Service Mesh
``#tetragon``            Questions on Tetragon
======================== ======================================================

You can join the following channels if you are looking to contribute to
Cilium code, documentation, or website:

======================== ======================================================
Name                     Purpose
======================== ======================================================
``#development``         Development discussions around Cilium
``#ebpf-go-dev``         Development discussion for the `eBPF Go library`_
``#git``                 GitHub notifications
``#sig-``\*              SIG-specific discussions (see below)
``#testing``             Testing and CI discussions
``#cilium-website``      Development discussions around cilium.io
======================== ======================================================

If you are interested in eBPF, then the following channels are for you:

======================== ======================================================
Name                     Purpose
======================== ======================================================
``#ebpf``                General eBPF questions
``#ebpf-go``             Questions on the `eBPF Go library`_
``#ebpf-lsm``            Questions on BPF Linux Security Modules (LSM)
``#echo-news``           Contributions to `eCHO News`_
``#ebpf-for-windows``    Discussions around eBPF for Windows
======================== ======================================================

.. _eBPF Go library: https://github.com/cilium/ebpf
.. _eCHO News: https://cilium.io/newsletter/

Our Slack hosts channels for eBPF and Cilium-related events online and in
person.

======================== ======================================================
Name                     Purpose
======================== ======================================================
``#ciliumcon``           CiliumCon
``#ctf``                 Cilium and eBPF capture-the-flag challenges
``#ebpf-summit``         eBPF Summit
======================== ======================================================

How to create a Slack channel
-----------------------------

1. Open a new `GitHub issue in the cilium/community repo <https://github.com/cilium/community/issues>`_
2. Specify the title "Slack: <Name>"
3. Provide a description
4. Find two Cilium committers to comment in the issue that they approve the
   creation of the Slack channel
5. Not all Slack channels need to be listed on this page, but you can submit a
   PR if you would like to include it here

Special Interest Groups
=======================

All SIGs
--------

The following is a list of special interest groups (SIGs) that are meeting on a
regular interval. See the respective slack channel for exact meeting cadence
and meeting links.

====================== ============================================== ======================= ============================================================================
SIG                    Meeting                                        Slack                   Description
====================== ============================================== ======================= ============================================================================
BGP                    None                                           ``#sig-bgp``            Border Gateway Protocol (BGP) discussions.
Cluster Mesh           None                                           ``#sig-clustermesh``    Cluster Mesh discussions.
Datapath               On demand                                      ``#sig-datapath``       Development discussions for Linux and eBPF code used in Cilium.
Documentation          None                                           ``#sig-docs``           Documentation, Helm references, and translations.
Envoy                  On demand                                      ``#sig-envoy``          Envoy, Istio and maintenance of all L7 protocol parsers.
Hubble                 During community meeting                       ``#sig-hubble``         All Hubble-related code: Server, UI, CLI and Relay.
Modularization         None                                           ``#sig-modularization`` Discussions around further modularizing the cilium/cilium codebase.
Policy                 `First Tuesday <https://isogo.to/sig-policy>`_ ``#sig-policy``         Network policy and enforcement.
Release Management     None                                           ``#launchpad``          Release management and backport coordination.
Scalability            Fourth Thursday of the month                   ``#sig-scalability``    Cilium scalability discussions.                                     
====================== ============================================== ======================= ============================================================================

How to create a SIG
-------------------

1. Open a new `GitHub issue in the cilium/cilium repo <https://github.com/cilium/cilium/issues>`_
2. Specify the title "SIG-Request: <Name>"
3. Provide a description
4. Find two Cilium committers to support the SIG
5. Ask on ``#development`` to get the Slack channel and Zoom meeting created
6. Submit a PR to update the documentation to get your new SIG listed

