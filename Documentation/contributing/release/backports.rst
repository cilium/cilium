.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _backport_process:

Backporting process
===================

.. _backport_criteria:

Backport Criteria
-----------------

Committers may nominate PRs that have been merged into main as candidates for
backport into stable releases if they affect the stable production usage
of community users.

Backport Criteria for Current Minor Release
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Criteria for inclusion into the next stable release of the current latest
minor version of Cilium, for example in a ``v1.2.z`` release prior to the
release of version ``v1.3.0``:

- All bugfixes
- Debug tool improvements

Backport Criteria for X.Y-1.Z and X.Y-2.Z
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Criteria for the inclusion into the next stable release of the prior two minor
versions of Cilium, for example in a ``v1.0.z`` or ``v1.1.z`` release prior to
the release of version ``v1.3.0``:

- Security relevant fixes
- Major bugfixes relevant to the correct operation of Cilium
- Debug tool improvements

Backport Criteria for documentation changes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Changes to Cilium's documentation should generally be subject to backports for
all supported branches to which they apply (all supported branches containing
the parent features to which the modified sections relate).

The motivation is that users can then simply look at the branch of the
documentation related to the version they are deploying, and find the latest
correct instructions for their version.

Proposing PRs for backporting
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PRs are proposed for backporting by adding a ``needs-backport/X.Y`` label to
them. Normally this is done by the author when the PR is created or one of the
maintainers when the PR is reviewed. When proposing PRs that have already been
merged, also add a comment to the PR to ensure that the backporters are
notified.

Marking PRs to be backported by the author
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For PRs which need to be backported, but are likely to run into conflicts or
other difficulties, the author has the option of adding the ``backport/author``
label. This will exclude the PR from backporting automation, and the author is
expected to perform the backport themselves.

Backporting Guide for the Backporter
------------------------------------

Cilium PRs that are marked with the label ``needs-backport/X.Y`` need to be
backported to the stable branch ``X.Y``. The following steps summarize the
process for backporting these PRs:

* One-time setup
* Preparing PRs for backport
* Cherry-picking commits into a backport branch
* Posting the PR and updating GitHub labels

.. _backport_setup:

One-time Setup
~~~~~~~~~~~~~~

#. Make sure you have a GitHub developer access token with the ``public_repos``
   ``workflow``, ``read:user`` scopes available. You can do this directly from
   https://github.com/settings/tokens or by opening GitHub and then navigating
   to: User Profile -> Settings -> Developer Settings -> Personal access token
   -> Generate new token.

#. The scripts referred to below need to be run on Linux, they do not work on
   macOS. It is recommended to create a container using (``contrib/backporting/Dockerfile``),
   as it will have all the correct versions of dependencies / libraries.

   .. code-block:: shell-session

      $ export GITHUB_TOKEN=<YOUR_GITHUB_TOKEN>

      $ docker build -t cilium-backport contrib/backporting/.

      $ docker run -e GITHUB_TOKEN -v $(pwd):/cilium -v "$HOME/.ssh":/home/user/.ssh \
            -it cilium-backport /bin/bash

   .. note::

      If you are running on a mac OS, and see ``/home/user/.ssh/config: line 3:
      Bad configuration option: usekeychain`` error message while running any of
      the backporting scripts, comment out the line ``UseKeychain yes``.

#. Once you have a setup ready, you need to configure git to have your name and
   email address to be used in the commit messages:

   .. code-block:: shell-session

      $ git config --global user.name "John Doe"
      $ git config --global user.email johndoe@example.com

#. Add remotes for the Cilium upstream repository and your Cilium repository fork.

   .. code-block:: shell-session

      $ git remote add johndoe git@github.com:johndoe/cilium.git
      $ git remote add upstream https://github.com/cilium/cilium.git

#. Skip this step if you have created a setup using the pre-defined Dockerfile.
   This guide makes use of several tools to automate the backporting process.
   The basics require ``bash`` and ``git``, but to automate interactions with
   github, further tools are required.

   +--------------------------------------------------------------+-----------+---------------------------------------------------------+
   | Dependency                                                   | Required? | Download Command                                        |
   +==============================================================+===========+=========================================================+
   | bash                                                         | Yes       | N/A (OS-specific)                                       |
   +--------------------------------------------------------------+-----------+---------------------------------------------------------+
   | git                                                          | Yes       | N/A (OS-specific)                                       |
   +--------------------------------------------------------------+-----------+---------------------------------------------------------+
   | jq                                                           | Yes       | N/A (OS-specific)                                       |
   +--------------------------------------------------------------+-----------+---------------------------------------------------------+
   | python3                                                      | Yes       | `Python Downloads <https://www.python.org/downloads/>`_ |
   +--------------------------------------------------------------+-----------+---------------------------------------------------------+
   | `PyGithub <https://pypi.org/project/PyGithub/>`_             | Yes       | ``pip3 install PyGithub``                               |
   +--------------------------------------------------------------+-----------+---------------------------------------------------------+
   | `Github hub CLI (>= 2.8.3) <https://github.com/github/hub>`_ | Yes       | N/A (OS-specific)                                       |
   +--------------------------------------------------------------+-----------+---------------------------------------------------------+

   Verify your machine is correctly configured by running

   .. code-block:: shell-session

      $ go run ./tools/dev-doctor --backporting

Preparation
~~~~~~~~~~~

Pull requests that are candidates for backports to the X.Y stable release are
tracked through the following links:

* PRs with the needs-backport/X.Y label (\ |CURRENT_RELEASE|: :github-backport:`GitHub Link<needs-backport>`)
* PRs with the backport-pending/X.Y label (\ |CURRENT_RELEASE|: :github-backport:`GitHub Link<backport-pending>`)
* The X.Y GitHub project (\ |NEXT_RELEASE|: :github-project:`GitHub Link<>`)

Make sure that the Github labels are up-to-date, as this process will deal with
all commits from PRs that have the ``needs-backport/X.Y`` label set (for a
stable release version X.Y). If any PRs contain labels such as
``backport-pending/X.Y``, ensure that the backport for that PR have been merged
and if so, change the label to ``backport-done/X.Y``.

Creating the Backports Branch
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Check whether there are any `outstanding backport PRs for the target branch
   <https://github.com/cilium/cilium/pulls?q=is%3Aopen+is%3Apr+label%3Akind%2Fbackports>`__.
   If there are already backports for that branch, create a thread in the
   #launchpad channel in Slack and reach out to the author to coordinate
   triage, review and merge of the existing PR into the target branch.

#. Run ``contrib/backporting/start-backport`` for the release version that
   you intend to backport PRs for. This will pull the latest repository commits
   from the Cilium repository (assumed to be the git remote ``origin``), create
   a new branch, and runs the ``contrib/backporting/check-stable`` script to
   fetch the full set of PRs to backport.

   .. code-block:: shell-session

      $ GITHUB_TOKEN=xxx contrib/backporting/start-backport 1.0

   .. note::

      This command will leave behind a file in the current directory with a
      name based upon the release version and the current date in the form
      ``vRELEASE-backport-YYYY-MM-DD.txt`` which contains a prepared backport
      pull-request description so you don't need to write one yourself.

#. Cherry-pick the commits using the ``main`` branch git SHAs listed, starting
   from the oldest (top), working your way down and fixing any merge
   conflicts as they appear. Note that for PRs that have multiple
   commits you will want to check that you are cherry-picking oldest
   commits first. The ``cherry-pick`` script accepts multiple arguments,
   in which case it will attempt to apply each commit in the order
   specified on the command line until one cherry pick fails or every
   commit is cherry-picked.

   .. code-block:: shell-session

      $ contrib/backporting/cherry-pick <oldest-commit-sha>
      ...
      $ contrib/backporting/cherry-pick <newest-commit-sha>

   Conflicts may be resolved by applying changes or backporting other
   PRs to completely avoid conflicts. Backporting entire PRs is preferred if the
   changes in the dependent PRs are small. `This stackoverflow.com question
   <https://stackoverflow.com/questions/17818167/find-a-pull-request-on-github-where-a-commit-was-originally-created>`_
   describes how to determine the original PR corresponding to a particular
   commit SHA in the GitHub UI.

   If a conflict is resolved by modifying a commit during backport, describe
   the changes made in the commit message and collect these to add to the
   backport PR description when creating the PR below. This helps to direct
   backport reviewers towards which changes may deviate from the original
   commits to ensure that the changes are correctly backported. This can be
   fairly simple, for example inside the commit message of the modified commit::

       commit f0f09158ae7f84fc8d888605aa975ce3421e8d67
       Author: Joe Stringer <joe@cilium.io>
       Date:   Tue Apr 20 16:48:18 2021 -0700

           contrib: Automate digest PR creation

           [ upstream commit 893d0e7ec5766c03da2f0e7b8c548f7c4d89fcd7 ]

           [ Backporter's notes: Dropped conflicts in .github/ issue template ]

           There's still some interactive bits here just for safety, but one less
           step in the template.

           Signed-off-by: Joe Stringer <joe@cilium.io>

   **It is the backporter's responsibility to check that the backport commits
   they are preparing are identical to the original commits**. This can be
   achieved by preparing the commits, then running ``git show <commit>`` for
   both the original upstream commit and the prepared backport, and read
   through the commits side-by-side, line-by-line to check that the changes are
   the same. If there is any uncertainty about the backport, reach out to the
   original author directly to coordinate how to prepare the backport for the
   target branch.

#. For backporting commits that update cilium-builder and cilium-runtime images,
   the backporter should build new images as described in :ref:`update_cilim_builder_runtime_images`.

#. (Optional) If there are any commits or pull requests that are tricky or
   time-consuming to backport, consider reaching out for help on Slack. If the
   commit does not cherry-pick cleanly, please mention the necessary changes in
   the pull request description in the next section.

Creating the Backport Pull Request
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The backport pull-request may be created via CLI tools, or alternatively
you can use the GitHub web interface to achieve these steps.

Via Command-Line Tools (Recommended)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

These steps require all of the tools described in the :ref:`backport_setup`
section above. It pushes the git tree, creates the pull request and updates
the labels for the PRs that are backported, based on the
``vRELEASE-backport-YYYY-MM-DD.txt`` file in the current directory.

   .. code-block:: shell-session

      $ GITHUB_TOKEN=xxx contrib/backporting/submit-backport

The script takes up to three positional arguments::

      usage: submit-backport [branch version] [pr-summary] [your remote]

- The first parameter is the version of the branch against which the PR should
  be done, and defaults to the version passed to ``start-backport``.
- The second one is the name of the file containing the text summary to use for
  the PR, and defaults to the file created by ``start-backport``.
- The third one is the name of the git remote of your (forked) repository to
  which your changes will be pushed. It defaults to the git remote
  which matches ``github.com/<your github username>/cilium``.

Via GitHub Web Interface
^^^^^^^^^^^^^^^^^^^^^^^^

#. Push your backports branch to your fork of the Cilium repo.

   .. code-block:: shell-session

      $ git push -u <remote_for_your_fork> HEAD

#. Create a new PR from your branch towards the feature branch you are
   backporting to. Note that by default Github creates PRs against the
   ``main`` branch, so you will need to change it. The title and
   description for the pull request should be based upon the
   ``vRELEASE-backport-YYYY-MM-DD.txt`` file that was generated by the scripts
   above.

   .. note::

       The ``vRELEASE-backport-YYYY-MM-DD.txt`` file will include:

          .. code-block:: RST

                Once this PR is merged, you can update the PR labels via:
                ```upstream-prs
                $ for pr in AAA BBB ; do contrib/backporting/set-labels.py $pr done VVV; done
                ```

       The ``upstream-prs`` tag `is required
       <https://github.com/cilium/release/blob/3c5fc2bdc38f8d290349a612a03cc83655f57a51/pkg/github/labels.go#L26>`_,
       so add it if you manually write the message.


#. Label the new backport PR with the backport label for the stable branch such
   as ``backport/X.Y`` as well as ``kind/backports`` so that it is easy to find
   backport PRs later.

#. Mark all PRs you backported with the backport pending label
   ``backport-pending/X.Y`` and clear the ``needs-backport/X.Y`` label. This
   can be done with the command printed out at the bottom of the output from
   the ``start-backport`` script above (``GITHUB_TOKEN`` needs to be set for
   this to work).

Running the CI Against the Pull Request
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To validate a cross-section of various tests against the PRs, backport PRs
should be validated in the CI by running all CI targets. This can be triggered
by adding a comment to the PR with exactly the text ``/test-backport-x.x``,
where ``x.x`` is the target version as described in :ref:`trigger_phrases`.
The comment must not contain any other characters.

After the Backports are Merged
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

After the backport PR is merged, if the person who merged the PR didn't take
care of it already, mark all backported PRs with ``backport-done/X.Y`` label
and clear the ``backport-pending/X.Y`` label(s). If the backport pull request
description was generated using the scripts above, then the full command is
listed in the pull request description.

.. code-block:: shell-session

   $ GITHUB_TOKEN=xxx for pr in 12589 12568; do contrib/backporting/set-labels.py $pr done 1.8; done

Backporting Guide for Others
----------------------------

Original Committers and Reviewers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Committers should mark PRs needing backport as ``needs-backport/X.Y``, based on
the `backport criteria <backport_criteria_>`_. It is up to the reviewers to
confirm that the backport request is reasonable and, if not, raise concerns on
the PR as comments. In addition, if conflicts are foreseen or significant
changes to the PR are necessary for older branches, consider adding the
``backport/author`` label to mark the PR to be backported by the author.

At some point, changes will be picked up on a backport PR and the committer will
be notified and asked to approve the backport commits. Confirm that:

#. All the commits from the original PR have been indeed backported.
#. In case of conflicts, the resulting changes look good.

Merger
~~~~~~

When merging a backport PR, set the labels of the backported PRs to
``done``. Typically, backport PRs include a line on how do that. E.g.,:

.. code-block:: shell-session

    $ GITHUB_TOKEN=xxx for pr in 12894 12621 12973 12977 12952; do contrib/backporting/set-labels.py $pr done 1.8; done
