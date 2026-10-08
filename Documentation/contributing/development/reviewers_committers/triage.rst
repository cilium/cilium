.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _triage:

Issue Triage Process
====================

The Cilium project receives dozens of issue reports via GitHub each week.
Many of these issues may be resolved naturally through the process of community
collaboration, but sometimes the community needs a little help to clarify how
to reproduce an issue and which area of the project the issue relates to. With
a little bit of help from a triager, community members can connect with one
another in order to mitigate and solve issues that affect them.

This document describes the triage process, which is typically performed by
one primary person in a triager rotation each week. This person is supported
asynchronously by a wider group of community triage members in the
`#triage`_ Slack channel.

The main goal of the triage process is to identify critical issues that impact
a wide range of users in order to help the community prioritize those issues.
This process also helps community members to gather more information that can
lead to solutions to the problems that are reported. And finally, a long term
goal of this process is to share knowledge about different areas of Cilium,
thereby helping triagers to become more familiar with the different use cases
of the project.

.. _#triage: https://cilium.slack.com/archives/C0AJNJZ3B44

Process
-------

Triaging Bugs
^^^^^^^^^^^^^

Triaging bugs means interacting with the reporter until the issue is clear and
can be labeled with the corresponding area.

The main goal of this activity is identifying crucial issues that could impact
users, and gathering more info so that we can drive towards solutions to those
issues. We want to identify serious bugs and fix them.

Triagers inspect the `triage queue`_ during their assigned week to identify
issues that need assistance.

Issues are removed from this filter when they have the following labels added:

*   ``area/datapath``
*   ``area/agent``
*   ``area/hubble``
*   ``area/CI``
*   ``area/CI-improvement``
*   ``kind/feature``

Issues are also removed from this filter when they have the following types
set:

*   Enhancement
*   Task

A triager should typically expect to spend around 5-10 minutes per issue to
assess the overall impact, project area, severity, reproducibility, regressions,
and related work. You may want to spend more time on tricky issues. If the reporter
is actively engaging in debugging the issue and providing feedback, it is reasonable
(but not expected) to spend more time engaging with the reporter on the issue.
While the triager might be in a position to help mitigate or resolve the issue,
the triager is not expected to solve each issue.


Coordination
^^^^^^^^^^^^

The triagers will be organized by a Google Spreadsheet. Triagers will be organized
with their schedule of when they are expected to be the triager. If you cannot make
it for the week of your triage, you are expected to find another triager to swap
with.

Triagers are in the Cilium OSS #triage Slack Channel. Support for the current triager
can be found there. Due to how spread out the Cilium community is, for now
this will be asynchronous, but can be changed in the future if needed.


Guide
-----

As the triager, you should typically try to work through the `triage queue`_
roughly once a day, with the following steps in mind for each issue you encounter:

.. _triage queue: https://github.com/cilium/cilium/issues?q=is%3Aissue%20is%3Aopen%20sort%3Aupdated-asc%20label%3Aneeds%2Ftriage%20-label%3Aarea%2Fdatapath%20-label%3Aarea%2Fagent%20-label%3Aarea%2Fhubble%20-label%3Aarea%2FCI%20-label%3Aarea%2FCI-improvement%20-label%3Akind%2Ffeature%20-label%3Akind%2Fenhancement%20-type%3Atask%20-type%3AEnhancement%20-label%3Aneed-more-info

#. Assess: is the impact, reproduction steps and focus area clear to you?

    If the issue isn't clear enough request for more information like a sysdump or
    steps to replicate the issue. Add label ``need-more-info``. Issues that have the
    ``need-more-info`` label will not appear in the `triage queue`_ until the original
    reporter responds back to the issue.

#. Is it a regression?

    For GH issues that have the "Regression" section filled out or otherwise look
    like regressions, (for example: "this worked before but it's not working
    now") add the ``kind/regression`` label.

#. Label the issue

    If the issue seems to be reproducible, apply one of the following labels:

        * ``area/agent``
        * ``area/clustermesh``
        * ``area/datapath``
        * ``area/hubble``
        * ``area/operator``
        * ``area/servicemesh``

    Every issue that is triaged _must_ have one of the above labels.

    When in doubt which label to use, start a thread in the `#triage`_ channel in
    Cilium Slack.

#. Apply other labels if necessary

    If possible, add other labels that are relevant to the issue, such as ``sig/k8s``
    or ``feature/encryption``. Once you have added these labels, remove the
    ``needs/triage`` label.

Try to achieve an empty queue. There is no date filter, as that means
explicitly ignoring older issues. If an issue is not relevant, it should be
closed. If the queue grows faster than we can handle, raise a discussion about
the workload in #development.
