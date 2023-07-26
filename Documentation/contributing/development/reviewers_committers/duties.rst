.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _weekly_duties:

Weekly duties
=============

Some members of the committers team will have rotational duties that change
every week. The following steps describe how to perform those duties. Please
submit changes to these steps if you have found a better way to perform each
duty.

* `People with the top hat this week <https://github.com/orgs/cilium/teams/tophat/members>`_

Pull request review process
---------------------------

.. note::

   These instructions assume that whoever is reviewing is a member of the
   Cilium GitHub organization or has the status of a committer. This is
   required to obtain the privileges to modify GitHub labels on the pull
   request.

Dedicated expectation time for review duties: Follow the next steps 1 to 2
times per day.

#. Review all PRs needing a review `from you <https://github.com/cilium/cilium/pulls?q=is%3Apr+is%3Aopen+draft%3Afalse+team-review-requested%3Acilium%2Ftophat+sort%3Aupdated-asc>`_,
   following the :ref:`review_process`.

#. If this PR was opened by a non-committer (e.g. external contributor) please
   assign yourself to that PR and make sure to keep track the PR gets reviewed
   and merged. This may extend beyond your assigned week for Janitor duty.

   If the contributor is a Cilium committer, then they are responsible for
   getting the PR in a ready to be merged state by adding the ``ready-to-merge``
   label, once all reviews have been addressed and CI checks are successful, so
   that the janitor can merge it (see below).

   If this PR is a backport PR (e.g. with the label ``kind/backport``) and
   no-one else has reviewed the PR, review the changes as a sanity check.
   If any individual commits deviate from the original patch, request review from
   the original author to validate that the backport was correctly applied.

#. Review overall correctness of the PR according to the rules specified in the
   section :ref:`submit_pr`.

   Set the labels accordingly, a bot called maintainer's little helper might
   automatically help you with this.


   +--------------------------------+---------------------------------------------------------------------------+
   | Labels                         | When to set                                                               |
   +================================+===========================================================================+
   | ``dont-merge/needs-sign-off``  | Some commits are not signed off                                           |
   +--------------------------------+---------------------------------------------------------------------------+
   | ``needs-rebase``               | PR is outdated and needs to be rebased                                    |
   +--------------------------------+---------------------------------------------------------------------------+

#. Validate that bugfixes are marked with ``kind/bug`` and validate whether the
   assessment of backport requirements as requested by the submitter conforms
   to the :ref:`backport_criteria`.


   +--------------------------+---------------------------------------------------------------------------+
   | Labels                   | When to set                                                               |
   +==========================+===========================================================================+
   | ``needs-backport/X.Y``   | PR needs to be backported to these stable releases                        |
   +--------------------------+---------------------------------------------------------------------------+

#. If the PR is subject to backport, validate that the PR does not mix bugfix
   and refactoring of code as it will heavily complicate the backport process.
   Demand for the PR to be split.

#. Validate the ``release-note/*`` label and check the PR title for release
   note suitability. Put yourself into the perspective of a future release
   notes reader with lack of context and ensure the title is precise but brief.

   +-----------------------------------+--------------------------------------------------------------------------------------------------------+
   | Labels                            | When to set                                                                                            |
   +===================================+========================================================================================================+
   | ``dont-merge/needs-release-note`` | Do NOT merge PR, needs a release note                                                                  |
   +-----------------------------------+--------------------------------------------------------------------------------------------------------+
   | ``release-note/bug``              | This is a non-trivial bugfix and is a user-facing bug                                                  |
   +-----------------------------------+--------------------------------------------------------------------------------------------------------+
   | ``release-note/major``            | This is a major feature addition, e.g. Add MongoDB support                                             |
   +-----------------------------------+--------------------------------------------------------------------------------------------------------+
   | ``release-note/minor``            | This is a minor feature addition, e.g. Add support for a Kubernetes version                            |
   +-----------------------------------+--------------------------------------------------------------------------------------------------------+
   | ``release-note/misc``             | This is a not user-facing change , e.g. Refactor endpoint package, a bug fix of a non-released feature |
   +-----------------------------------+--------------------------------------------------------------------------------------------------------+
   | ``release-note/ci``               | This is a CI feature or bug fix.                                                                       |
   +-----------------------------------+--------------------------------------------------------------------------------------------------------+

#. Check for upgrade compatibility impact and if in doubt, set the label
   ``upgrade-impact`` and discuss in the Slack channel or in the weekly meeting.

   +--------------------------+---------------------------------------------------------------------------+
   | Labels                   | When to set                                                               |
   +==========================+===========================================================================+
   | ``upgrade-impact``       | The code changes have a potential upgrade impact                          |
   +--------------------------+---------------------------------------------------------------------------+

#. When all review objectives for all ``CODEOWNERS`` are met, all CI tests have
   passed, and all reviewers have approved the requested changes, merge the PR
   by clicking in the "Rebase and merge" button.

#. Merge PRs with the ``ready-to-merge`` label set `here <https://github.com/cilium/cilium/pulls?q=is%3Apr+is%3Aopen+draft%3Afalse+sort%3Aupdated-asc+label%3Aready-to-merge+>`_

#. If the PR is a backport PR, update the labels of cherry-picked PRs with the command included at the end of the original post. For example:

   .. code-block:: shell-session

       $ for pr in 12589 12568; do contrib/backporting/set-labels.py $pr done 1.8; done

Triage issues
-------------

Dedicated expectation time for triage duties: 15/30 minutes per
day. Works best if done first thing in the working day.

#. Ensure that:

   #. `Issues opened by community users are tracked down <https://github.com/cilium/cilium/issues?q=is%3Aissue+is%3Aopen+no%3Aassignee+sort%3Aupdated-desc>`_:

       #. Add the label ``kind/community-report``;
       #. If feasible, try to reproduce the issue described;
       #. Assign a member that is responsible for that code section to that GitHub
          issue;
       #. If it is a relevant bug to the rest of the committers, bring the issue
          up in the weekly meeting. For example:

          * The issue may impact an upcoming release; or
          * The resolution is unclear and assistance is needed to make progress; or
          * The issue needs additional attention from core contributors to
            confirm the resolution is the right path.

   #. `Issues recently commented are not left out unanswered <https://github.com/cilium/cilium/issues?q=is%3Aissue+is%3Aopen+sort%3Aupdated-desc+label%3Akind%2Fcommunity-report>`_:

       #. If there is someone already assigned to that GitHub issue and that
          committer hasn't provided an answer to that user for a while, ping
          that committer directly on Slack;
       #. If the issue cannot be solved, bring the issue up in the weekly
          meeting.

Backporting community PRs
-------------------------

Dedicated expectation time for backporting duties: 60 minutes, twice per
week depending on releases that need to be performed at the moment.

Even if the next release is not imminently planned, it is still important to
perform backports to keep the process smooth and to catch potential regressions
in stable branches as soon as possible. If backports are delayed, this can also
delay releases which is important to avoid especially if there are
security-sensitive bug fixes that require an immediate release.

If you can't backport a PR due technical constraints feel free to contact the
original author of that PR directly so they can backport the PR themselves.

Follow the :ref:`backport_process` guide to know how to perform this task.

Coordination
++++++++++++

In general, the committer with the top hat should coordinate with other core
team members in the #launchpad Slack channel in order to understand the status
of the review, triage and backport duties. This is especially important when
the top hat is rotated from one committer to another, as well as when a release
is planned for the upcoming week.

An example interaction in #launchpad:

::

    Starting backport round for v1.7 and v1.8 now

If there are many backports to be done, then splitting up the rounds can be
beneficial. Typically, backporters opt to start a round in the beginning of the
week and then another near the end of the week.

By the start / end of the week, if there are other backport PRs that haven't
been merged, then please coordinate with the previous / next backporter to
check what the status is and establish who will work on getting the backports
into the tree (for instance by investigating CI failures and addressing review
feedback). Ensure that the responsibility for driving the PRs forward is clear.
