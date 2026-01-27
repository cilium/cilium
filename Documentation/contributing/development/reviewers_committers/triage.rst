.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _triage:

Triaging Issues
===============

The Triager role involves a one week rotation of looking at incoming
bugs in Cilium and triaging them, as well as helping with merging and
testing external contributions.

Tasks
-----
Tasks are listed by order of importance.

1. Merging and Pushing Contributions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

As the title indicates, this part involves looking at community contributions
and seeing them through to completion. This involves approving workflows and
calling ``/test``, pulling in code owners and, ultimately, merging the PR when
it is ready. The amount of effort put on these should be proportional to the
effort put in by the contributor.

If a (somewhat) large contribution comes in that requires long-term help, the
Triager takes care of pairing up the contributor with someone from
the corresponding area, who can then help guide the
contribution even if it takes several weeks.

PRs that are ready to merge
~~~~~~~~~~~~~~~~~~~~~~~~~~~

`cilium/cilium: ready to merge PRs
<https://github.com/cilium/cilium/pulls?q=is%3Aopen+is%3Apr+label%3Aready-to-merge>`_

Guidelines for merging:

*   You should basically never be bypassing branch protections, even for
    docs-only PRs. It's better to run ``/test`` regardless, and that should be
    able to determine which tests are required. People should not be setting
    ``ready-to-merge`` manually, we should always run ``/test``. If that runs
    more CI than it should, that is a problem with CI.
*   Once all required tests have passed, reviews are in, and discussions are
    resolved, have a maintainer push the merge button without needing to bypass branch
    protections. The button doesn't have to be green.
*   `Maintainer's Little Helper
    <https://github.com/cilium/maintainer-little-helper>`_ does not, at the
    time of writing, know about the requirement to resolve discussions, so it
    may flag PRs as ready-to-merge even when you can't click the merge button.
    In this case, review the discussions and see if there are any outstanding
    discussions, and if not, close them.

PRs that may need attention
~~~~~~~~~~~~~~~~~~~~~~~~~~~

`Cilium community contributions (open, unassigned, not draft)
<https://github.com/cilium/cilium/pulls?q=is%3Aopen+is%3Apr+no%3Aassignee+draft%3Afalse+label%3Akind%2Fcommunity-contribution+sort%3Aupdated-asc+-author%3Aapp%2Frenovate>`_


*   Work your way forward from the oldest-updated PRs. PRs with recent
    activity are likely being interacted with by other team members.
*   Apply ``kind/*`` and ``release-note/*`` labels, external contributors
    cannot apply labels.
*   Approve workflows and run ``/test``.
*   Link or create issues for persistent flakes. See the `CI failure triage guide <https://docs.cilium.io/en/stable/contributing/testing/ci/#ci-failure-triage>`_ for further guidance.
*   Remind the person if feedback was positive but there's been no progress, either from reviewer or author side.
*   Kindly ask for rebases if conflicts emerge, or if e.g. things changed in CI that are causing a job to fail.
*   Make sure PRs contain no fixup or merge commits before merging them. Merge
    PRs if the button is green. Do not override branch protection.
*   If the contributor does not appear to be making progress on the PR, mark
    the PR as draft and add a comment similar to:

    *I've marked this PR as draft while you work through the feedback in the
    PR above. When you're ready to continue with review & testing of the PR,
    please click "Ready for Review" at the bottom of the page.*

2. Triaging Bugs
^^^^^^^^^^^^^^^^

Triaging bugs means interacting with the reporter until the issue is clear and
can be labeled with the corresponding area.

The main goal of this activity is identifying crucial issues that could impact
users, and gathering more info so that we can drive towards solutions to those
issues. We want to identify serious bugs and fix them.

Handle these GitHub issues: `cilium/cilium issues that need Triager attention
<https://github.com/cilium/cilium/issues?q=is%3Aissue+is%3Aopen+label%3Aneeds%2Ftriage+-label%3Aarea%2Fdatapath+-label%3Aarea%2Fagent+-label%3Aarea%2Fhubble+-label%3Aarea%2FCI+-label%3Aarea%2FCI-improvement+-label%3Akind%2Ffeature+-label%3Akind%2Fenhancement+-label%3Akind%2Ftask>`_

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

The effort we spend should be proportional to the reporter's effort. This
typically means a 5-10 minute assessment of overall impact, project area, severity, reproducibility,
regressions, and related work.

If the issue isn't clear enough request for more information like a sysdump or
steps to replicate the issue. Add label ``need-more-info``. Adding
``need-more-info`` will remove the issue from display in the filter, until the
original poster responds, when automation will change ``need-more-info`` to
``info-completed``. This allows issues that are logged with not enough
information and no followup to not waste Triager time looking at them.

For GH issues that have the "Regression" section filled out or otherwise look
like regressions, (for example: "this worked before but it's not working
now") add the ``kind/regression`` label.

If it has enough information but is not a regression, decide if it's
``area/agent``, ``area/datapath`` or ``area/hubble``. When in doubt which one is
it, bring it up in #development channel on Slack.

Every issue in ``cilium/cilium`` should have ``area/agent``, ``area/datapath``
or ``area/hubble`` once it has enough information.
If possible add ``"area/*"`` labels and more specific labels, like
``sig/k8s`` or ``area/clustermesh``.

Once you have added ``area/agent``, ``area/datapath`` or ``area/hubble`` remove
the ``needs/triage`` label.

Try to achieve an empty queue. There is no date filter, as that means
explicitly ignoring older issues. If an issue is not relevant, it should be
closed. If the queue grows faster than we can handle, raise a discussion about the workload in #development.
