.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io


.. _howto_contribute:

How To Contribute
=================

Clone and Provision Environment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Make sure you have a `GitHub account <https://github.com/signup/free>`_
#. Clone the cilium repository

   ::

      go get -d github.com/cilium/cilium
      cd $GOPATH/src/github.com/cilium/cilium

#. Set up your :ref:`dev_env`
#. Check the GitHub issues for `good tasks to get started
   <https://github.com/cilium/cilium/issues?q=is%3Aopen+is%3Aissue+label%3Agood-first-issue>`_.

.. _submit_pr:

Submitting a pull request
~~~~~~~~~~~~~~~~~~~~~~~~~

Contributions must be submitted in the form of pull requests against the github
repository at: `<https://github.com/cilium/cilium>`_

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

        Signed-off-by: Joe Stringer <joe@covalent.io>

   .. note:

       Make sure to include a blank line in between commit title and commit
       description.

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

#. All commits are signed off. See the section :ref:`dev_coo`.

#. Pick the appropriate milestone for which this PR is being targeted to, e.g.
   ``1.1``, ``1.2``. This is in particular important in the time frame between
   the feature freeze and final release date.

#. Pick the right release-note label

   +--------------------------+---------------------------------------------------------------------------+
   | Labels                   | When to set                                                               |
   +==========================+===========================================================================+
   | ``release-note/bug``     | This is a non-trivial bugfix                                              |
   +--------------------------+---------------------------------------------------------------------------+
   | ``release-note/major``   | This is a major feature addition, e.g. Add MongoDB support                |
   +--------------------------+---------------------------------------------------------------------------+
   | ``release-note/minor``   | This is a minor feature addition, e.g. Refactor endpoint package          |
   +--------------------------+---------------------------------------------------------------------------+

#. Verify the release note text. If not explicitly changed, the title of the PR
   will be used for the release notes. If you want to change this, you can add
   a special section to the description of the PR.

   ::

      ```release-note
      This is a release note text
      ```

   .. note::

      If multiple lines are provided, then the first line serves as the high
      level bullet point item and any additional line will be added as a sub
      item to the first line.

#. Pick the right labels for your PR:

   +------------------------------+---------------------------------------------------------------------------+
   | Labels                       | When to set                                                               |
   +==============================+===========================================================================+
   | ``kind/bug``                 | This is a bugfix worth mentioning in the release notes                    |
   +------------------------------+---------------------------------------------------------------------------+
   | ``kind/enhancement``         | This is an enhancement/feature                                            |
   +------------------------------+---------------------------------------------------------------------------+
   | ``priority/release-blocker`` | This PR should block the current release                                  |
   +------------------------------+---------------------------------------------------------------------------+
   | ``area/*``                   | Code area this PR covers                                                  |
   +------------------------------+---------------------------------------------------------------------------+
   | ``needs-backport/X.Y``       | PR needs to be backported to these stable releases                        |
   +------------------------------+---------------------------------------------------------------------------+
   | ``pending-review``           | PR is immediately ready for review                                        |
   +------------------------------+---------------------------------------------------------------------------+
   | ``wip``                      | PR is still work in progress, signals reviewers to hold.                  |
   +------------------------------+---------------------------------------------------------------------------+
   | ``backport/X.Y``             | This is backport PR, may only be set as part of :ref:`backport_process`   |
   +------------------------------+---------------------------------------------------------------------------+
   | ``upgrade-impact``           | The code changes have a potential upgrade impact                          |
   +------------------------------+---------------------------------------------------------------------------+

   .. note:

      If you do not have permissions to set labels on your pull request. Leave
      a comment and a core team member will add the labels for you. Most
      reviewers will do this automatically without prior request.

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


Pull request review process
---------------------------

.. note::

   These instructions assume that whoever is reviewing is a member of the
   Cilium GitHub organization or has the status of a contributor. This is
   required to obtain the privileges to modify GitHub labels on the pull
   request.

#. Review overall correctness of the PR according to the rules specified in the
   section :ref:`submit_pr`.

   Set the label accordingly.


   +--------------------------------+---------------------------------------------------------------------------+
   | Labels                         | When to set                                                               |
   +================================+===========================================================================+
   | ``dont-merge/needs-sign-off``  | Some commits are not signed off                                           |
   +--------------------------------+---------------------------------------------------------------------------+
   | ``needs-rebase``               | PR is outdated and needs to be rebased                                    |
   +--------------------------------+---------------------------------------------------------------------------+

#. As soon as a PR has the label ``pending-review``, review the code and
   request changes as needed by using the GitHub ``Request Changes`` feature or
   by using Reviewable.

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

   +-----------------------------------+---------------------------------------------------------------------------+
   | Labels                            | When to set                                                               |
   +===================================+===========================================================================+
   | ``dont-merge/needs-release-note`` | Do NOT merge PR, needs a release note                                     |
   +-----------------------------------+---------------------------------------------------------------------------+
   | ``release-note/bug``              | This is a non-trivial bugfix                                              |
   +-----------------------------------+---------------------------------------------------------------------------+
   | ``release-note/major``            | This is a major feature addition                                          |
   +-----------------------------------+---------------------------------------------------------------------------+
   | ``release-note/minor``            | This is a minor feature addition                                          |
   +-----------------------------------+---------------------------------------------------------------------------+

#. Check for upgrade compatibility impact and if in doubt, set the label
   ``upgrade-impact`` and discuss in the Slack channel.

   +--------------------------+---------------------------------------------------------------------------+
   | Labels                   | When to set                                                               |
   +==========================+===========================================================================+
   | ``upgrade-impact``       | The code changes have a potential upgrade impact                          |
   +--------------------------+---------------------------------------------------------------------------+

#. When everything looks OK, approve the changes.

#. When all review objectives for all ``CODEOWNERS`` are met and all CI tests
   have passed, you may set the ``ready-to-merge`` label to indicate that all
   criteria have been met.

   +--------------------------+---------------------------------------------------------------------------+
   | Labels                   | When to set                                                               |
   +==========================+===========================================================================+
   | ``ready-to-merge``       | PR is ready to be merged                                                  |
   +--------------------------+---------------------------------------------------------------------------+

.. _dev_coo:

Developer's Certificate of Origin
---------------------------------

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

.. toctree::

   ../../commit-access

