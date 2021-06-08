.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io


.. _howto_contribute:

How To Contribute
=================

Clone and Provision Environment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Make sure you have a `GitHub account <https://github.com/join>`_
#. Clone the cilium repository into your ``GOPATH``.

   .. code-block:: shell-session

      mkdir -p $GOPATH/src/github.com/cilium
      cd $GOPATH/src/github.com/cilium
      git clone https://github.com/cilium/cilium.git
      cd cilium

#. Set up your :ref:`dev_env`.
#. Check the GitHub issues for `good tasks to get started
   <https://github.com/cilium/cilium/issues?q=is%3Aopen+is%3Aissue+label%3Agood-first-issue>`_.

.. _submit_pr:

Submitting a pull request
~~~~~~~~~~~~~~~~~~~~~~~~~

Contributions must be submitted in the form of pull requests against the github
repository at: https://github.com/cilium/cilium.

#. Fork the Cilium repository to your own personal GitHub space or request
   access to a Cilium developer account on Slack
#. Push your changes to the topic branch in your fork of the repository.
#. Submit a pull request on https://github.com/cilium/cilium.

Before hitting the submit button, please make sure that the following
requirements have been met:

#. Each commit compiles and is functional on its own to allow for bisecting of
   commits.
#. All code is covered by unit and/or runtime tests where feasible.
#. All changes have been tested and checked for regressions by running the
   existing testsuite against your changes. See the :ref:`testsuite` section
   for additional details.
#. All commits contain a well written commit description including a title,
   description and a ``Fixes: #XXX`` line if the commit addresses a particular
   GitHub issue. Note that the GitHub issue will be automatically closed when
   the commit is merged.

   ::

        apipanic: Log stack at debug level

        Previously, it was difficult to debug issues when the API panicked
        because only a single line like the following was printed:

        level=warning msg="Cilium API handler panicked" client=@ method=GET
        panic_message="write unix /var/run/cilium/cilium.sock->@: write: broken
        pipe"

        This patch logs the stack at this point at debug level so that it can at
        least be determined in developer environments.

        Fixes: #4191

        Signed-off-by: Joe Stringer <joe@cilium.io>

   .. note:

       Make sure to include a blank line in between commit title and commit
       description.

   .. note:

       Passing the ``-s`` option to ``git commit`` will add the
       ``Signed-of-by:`` line to your commit message automatically.

#. If any of the commits fixes a particular commit already in the tree, that
   commit is referenced in the commit message of the bugfix. This ensures that
   whoever performs a backport will pull in all required fixes:

   ::

      daemon: use endpoint RLock in HandleEndpoint

      Fixes: a804c7c7dd9a ("daemon: wait for endpoint to be in ready state if specified via EndpointChangeRequest")

      Signed-off-by: André Martins <andre@cilium.io>

   .. note:

      The proper format for the ``Fixes:`` tag referring to commits is to use
      the first 12 characters of the git SHA followed by the full commit title
      as seen above without breaking the line.

#. If you change CLI arguments of any binaries in this repo, the CI will reject your PR if you don't
   also update the command reference docs. To do so, make sure to run the ``postcheck`` make target.

   .. code-block:: shell-session

      $ make postcheck
      $ git add Documentation/cmdref
      $ git commit

#. All commits are signed off. See the section :ref:`dev_coo`.

#. Document any user-facing or breaking changes in ``Documentation/install/upgrade.rst``.

#. (optional) Pick the appropriate milestone for which this PR is being
   targeted, e.g. ``1.6``, ``1.7``. This is in particular important in the time
   frame between the feature freeze and final release date.

#. If you have permissions to do so, pick the right release-note label. These
   labels will be used to generate the release notes which will primarily be
   read by users.

   +-----------------------------------+--------------------------------------------------------------------------------------------------------+
   | Labels                            | When to set                                                                                            |
   +===================================+========================================================================================================+
   | ``release-note/bug``              | This is a non-trivial bugfix and is a user-facing bug                                                  |
   +-----------------------------------+--------------------------------------------------------------------------------------------------------+
   | ``release-note/major``            | This is a major feature addition, e.g. Add MongoDB support                                             |
   +-----------------------------------+--------------------------------------------------------------------------------------------------------+
   | ``release-note/minor``            | This is a minor feature addition, e.g. Add support for a Kubernetes version                            |
   +-----------------------------------+--------------------------------------------------------------------------------------------------------+
   | ``release-note/misc``             | This is a not user-facing change , e.g. Refactor endpoint package, a bug fix of a non-released feature |
   +-----------------------------------+--------------------------------------------------------------------------------------------------------+
   | ``release-note/ci``               | This is a CI feature of bug fix.                                                                       |
   +-----------------------------------+--------------------------------------------------------------------------------------------------------+

#. Verify the release note text. If not explicitly changed, the title of the PR
   will be used for the release notes. If you want to change this, you can add
   a special section to the description of the PR.
   These release notes are primarily going to be read by users so it is
   important that release notes for bugs, major and minor features do not
   contain internal details of Cilium functionality which sometimes are
   irrelevant for users.

   Example of a bad release note
   ::

      ```release-note
      Fix concurrent access in k8s watchers structures
      ```

   Example of a good release note
   ::

      ```release-note
      Fix panic when Cilium received an invalid Cilium Network Policy from Kubernetes
      ```

   .. note::

      If multiple lines are provided, then the first line serves as the high
      level bullet point item and any additional line will be added as a sub
      item to the first line.

#. If you have permissions, pick the right labels for your PR:

   +------------------------------+---------------------------------------------------------------------------+
   | Labels                       | When to set                                                               |
   +==============================+===========================================================================+
   | ``kind/bug``                 | This is a bugfix worth mentioning in the release notes                    |
   +------------------------------+---------------------------------------------------------------------------+
   | ``kind/enhancement``         | This enhances existing functionality in Cilium                            |
   +------------------------------+---------------------------------------------------------------------------+
   | ``kind/feature``             | This is a feature                                                         |
   +------------------------------+---------------------------------------------------------------------------+
   | ``release-blocker/X.Y``      | This PR should block the next X.Y release                                 |
   +------------------------------+---------------------------------------------------------------------------+
   | ``needs-backport/X.Y``       | PR needs to be backported to these stable releases                        |
   +------------------------------+---------------------------------------------------------------------------+
   | ``backport/X.Y``             | This is backport PR, may only be set as part of :ref:`backport_process`   |
   +------------------------------+---------------------------------------------------------------------------+
   | ``upgrade-impact``           | The code changes have a potential upgrade impact                          |
   +------------------------------+---------------------------------------------------------------------------+
   | ``area/*`` (Optional)        | Code area this PR covers                                                  |
   +------------------------------+---------------------------------------------------------------------------+

   .. note:

      If you do not have permissions to set labels on your pull request. Leave
      a comment and a core team member will add the labels for you. Most
      reviewers will do this automatically without prior request.

#. Open a draft pull request. GitHub provides the ability to create a Pull
   Request in "draft" mode. On the "New Pull Request" page, below the pull
   request description box there is a button for creating the pull request.
   Click the arrow and choose "Create draft pull request". If your PR is still a
   work in progress, please select this mode. You will still be able to run the
   CI against it. Once the PR is ready for review you can click in "Ready for
   review" button at the bottom of the page" and reviewers will start reviewing.
   When you are actively changing your PR, set it back to draft PR mode to
   signal that reviewers do not need to spend time reviewing the PR right now.
   When it is ready for review again, mark it as such.

.. image:: https://i1.wp.com/user-images.githubusercontent.com/3477155/52671177-5d0e0100-2ee8-11e9-8645-bdd923b7d93b.gif
    :align: center

Getting a pull request merged
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. As you submit the pull request as described in the section :ref:`submit_pr`.
   One of the reviewers will start a CI run by replying with a comment
   ``test-me-please`` as described in :ref:`trigger_phrases`. If you are a
   core team member, you may trigger the CI run yourself.

   #. Hound: basic ``golang/lint`` static code analyzer. You need to make the
      puppy happy.
   #. :ref:`ci_jenkins`: Will run a series of tests:

      #. Unit tests
      #. Single node runtime tests
      #. Multi node Kubernetes tests

      If a CI test fails which seems unrelated to your PR, it may be a flaky
      test. Follow the process described in :ref:`ci_failure_triage`.

#. As part of the submission, GitHub will have requested a review from the
   respective code owners according to the ``CODEOWNERS`` file in the
   repository.

   #. Address any feedback received from the reviewers
   #. You can push individual commits to address feedback and then rebase your
      branch at the end before merging.

#. Owners of the repository will automatically adjust the labels on the pull
   request to track its state and progress towards merging.

#. Once the PR has been reviewed and the CI tests have passed, the PR will be
   merged by one of the repository owners. In case this does not happen, ping
   us on Slack.

#. If reviewers have requested changes and those changes have been addressed,
   re-request a review for the reviewers that have requested changes. Otherwise,
   those reviewers will not be notified and your PR will not receive any
   reviews. If the PR is considerably large (e.g. with more than 200 lines
   changed and/or more than 6 commits) create new commit for each review. This
   will make the review process smoother as GitHub has limitations that
   prevents reviewers from only seeing the new changes added since the last time
   they have reviewed a PR. Once all reviews are addressed those commits should
   be squashed against the commit that introduced those changes. This can be
   easily accomplished by the usage of ``git rebase -i origin/master`` and in
   that windows, move these new commits below the commit that introduced the
   changes and replace the work ``pick`` with ``fixup``. In the following
   example, commit ``d2cb02265`` will be meld into ``9c62e62d8`` and commit
   ``146829b59`` will be meld into ``9400fed20``.

       ::

           pick 9c62e62d8 docs: updating contribution guide process
           fixup d2cb02265 joe + paul + chris changes
           pick 9400fed20 docs: fixing typo
           fixup 146829b59 Quetin and Maciej reviews

   Once this is done you can perform push force into your branch and request for
   your PR to be merged.


Pull requests review process for committers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Every committer in the `committers team <https://github.com/orgs/cilium/teams/committers/members>`_
   belongs to `one or more other teams in the Cilium organization <https://github.com/orgs/cilium/teams/team/teams>`_
   if you would like to be added or removed from any team, please contact any
   of the `maintainers <https://github.com/orgs/cilium/teams/maintainers/members>`_.

#. Once a PR is open, GitHub will automatically pick which `teams <https://github.com/orgs/cilium/teams/team/teams>`_
   should review the PR using the ``CODEOWNERS`` file. Each committer can see
   the PRs they need to review by filtering by reviews requested.
   A good filter is provided in this `link <https://github.com/cilium/cilium/pulls?q=is%3Apr+is%3Aopen+draft%3Afalse+assignee%3A%40me+sort%3Aupdated-asc>`_
   so make sure to bookmark it. If a PR review is assigned to one or more
   committers, they are expected to review that PR. Once they have performed
   their review, they should remove themselves from the list of assignees.

#. Belonging to a team does not mean that a committer should know every single
   line of code the team is maintaining. For this reason it is recommended
   that once you have reviewed a PR, if you feel that another pair of eyes is
   needed, you should re-request a review from the appropriate team. In the
   example below, the committer belonging to the CI team is re-requesting a
   review for other team members to review the PR. This allows other team
   members belonging to the CI team to see the PR as part of the PRs that
   require review in the `filter provided above <https://github.com/cilium/cilium/pulls?q=is%3Apr+is%3Aopen+draft%3Afalse+review-requested%3A%40me+sort%3Aupdated-asc>`_

   .. image:: ../../images/re-request-review.png
      :align: center
      :scale: 50%

#. When all review objectives for all ``CODEOWNERS`` are met, all required CI
   tests have passed and a proper release label as been set, you may set the
   ``ready-to-merge`` label to indicate that all criteria have been met.
   Maintainer's little helper might set this label automatically if the previous
   requirements were met.

   +--------------------------+---------------------------+
   | Labels                   | When to set               |
   +==========================+===========================+
   | ``ready-to-merge``       | PR is ready to be merged  |
   +--------------------------+---------------------------+

Weekly duties
~~~~~~~~~~~~~

Some members of the committers team will have rotational duties that change
every week. The following steps describe how to perform those duties. Please
submit changes to these steps if you have found a better way to perform each
duty.

* `People on Janitor hat this week <https://github.com/orgs/cilium/teams/janitors/members>`_
* `People on Triage hat this week <https://github.com/orgs/cilium/teams/triage/members>`_
* `People on Backport hat this week <https://github.com/orgs/cilium/teams/backporter/members>`_

Pull request review process for Janitors team
---------------------------------------------

.. note::

   These instructions assume that whoever is reviewing is a member of the
   Cilium GitHub organization or has the status of a contributor. This is
   required to obtain the privileges to modify GitHub labels on the pull
   request.

Dedicated expectation time for each member of Janitors team: Follow the next
steps 1 to 2 times per day. Works best if done first thing in the working day.

#. Review all PRs requesting for review in `for you <https://github.com/cilium/cilium/pulls?q=is%3Apr+is%3Aopen+draft%3Afalse+review-requested%3A%40me+sort%3Aupdated-asc>`_;

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
   | ``release-note/ci``               | This is a CI feature of bug fix.                                                                       |
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

Triage issues for Triage team
-----------------------------

Dedicated expectation time for each member of Triage team: 15/30 minutes per
day. Works best if done first thing in the working day.

#. Committers belonging to the `Triage team <https://github.com/orgs/cilium/teams/triage>`_
   should make sure that:

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

Backporting PR for Backport team
--------------------------------

Dedicated expectation time for each member of Backport team: 60 minutes per
week depending on releases that need to be performed at the moment.

Even if the next release is not imminently planned, it is still important to
perform backports to keep the process smooth and to catch potential regressions
in stable branches as soon as possible. If backports are delayed, this can also
delay releases which is important to avoid especially if there are
security-sensitive bug fixes that require an immediate release.

In addition, when a backport PR is open, the person opening it is responsible to
drive it to completion, even if it stretches after the assigned week of
backporting hat. If this is not feasible (e.g. PTO), you are responsible to
initiate handover of the PR to the next week's backporters.

If you can't backport a PR due technical constraints feel free to contact the
original author of that PR directly so they can backport the PR themselves.

Follow the :ref:`backport_process` guide to know how to perform this task.

.. _dev_coo:

Coordination
++++++++++++

In general, coordinating in the #launchpad Slack channel with the other hat
owner for the week is encouraged. It can reduce your workload and it will avoid
backporting conflicts such as opening a PR with the same backports. Such
discussions will typically revolve around which branches to tackle and which
day of the week.

An example interaction in #launchpad:

::

    Starting backport round for v1.7 and v1.8 now
    cc @other-hat-wearer

The other hat owner can then handle v1.9 and v1.10 backports the next day, for
example.

If there are many backports to be done, then splitting up the rounds can be
beneficial. Typically, backporters opt to start a round in the beginning of the
week and then another near the end of the week.

By the start / end of the week, if there are other backport PRs that haven't
been merged, then please coordinate with the previous / next backporter to
check what the status is and establish who will work on getting the backports
into the tree (for instance by investigating CI failures and addressing review
feedback). There's leeway to negotiate depending on who has time available.

Developer's Certificate of Origin
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To improve tracking of who did what, we've introduced a "sign-off"
procedure.

The sign-off is a simple line at the end of the explanation for the
commit, which certifies that you wrote it or otherwise have the right to
pass it on as open-source work. The rules are pretty simple: if you can
certify the below:

::

    Developer Certificate of Origin
    Version 1.1

    Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
    1 Letterman Drive
    Suite D4700
    San Francisco, CA, 94129

    Everyone is permitted to copy and distribute verbatim copies of this
    license document, but changing it is not allowed.


    Developer's Certificate of Origin 1.1

    By making a contribution to this project, I certify that:

    (a) The contribution was created in whole or in part by me and I
        have the right to submit it under the open source license
        indicated in the file; or

    (b) The contribution is based upon previous work that, to the best
        of my knowledge, is covered under an appropriate open source
        license and I have the right under that license to submit that
        work with modifications, whether created in whole or in part
        by me, under the same open source license (unless I am
        permitted to submit under a different license), as indicated
        in the file; or

    (c) The contribution was provided directly to me by some other
        person who certified (a), (b) or (c) and I have not modified
        it.

    (d) I understand and agree that this project and the contribution
        are public and that a record of the contribution (including all
        personal information I submit with it, including my sign-off) is
        maintained indefinitely and may be redistributed consistent with
        this project or the open source license(s) involved.

then you just add a line saying:

::

   Signed-off-by: Random J Developer <random@developer.example.org>

Use your real name (sorry, no pseudonyms or anonymous contributions.)

