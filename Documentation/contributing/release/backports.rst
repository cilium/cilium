.. only:: not (epub or latex or html)
  
    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _backport_process:

Backporting process
===================

.. _backport_criteria:

Backport Criteria
-----------------

Committers may nominate PRs that have been merged into master as candidates for
backport into stable_releases if they affect the stable production usage
of community users.

Backport criteria for current minor release
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Criteria for inclusion into the next stable release of the current latest
minor version of Cilium, for example in a ``v1.2.z`` release prior to the
release of version ``v1.3.0``:

- All bugfixes

Backport criteria for X.Y-1.Z and X.Y-2.Z
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Criteria for the inclusion into the next stable release of the prior two minor
versions of Cilium, for example in a ``v1.0.z`` or ``v1.1.z`` release prior to
the release of version ``v1.3.0``:

- Security relevant fixes
- Major bugfixes relevant to the correct operation of Cilium


Backporting guide
-----------------

Cilium PRs that are marked with the label ``needs-backport/X.Y`` need to be
backported to the stable branch ``X.Y``. The following steps summarize
the process for backporting these PRs.

1. Make sure the Github labels are up-to-date, as this process will
   deal with all commits from PRs that have the ``needs-backport/X.Y`` label
   set (for a stable release version X.Y). If any PRs contain labels such as
   ``backport-pending/X.Y``, ensure that the backport for that PR have been
   merged and if so, change the label to ``backport-done/X.Y``.

2. The scripts referred to below need to be run in Linux, they do not
   work on OSX.  You can use the cilium dev VM for this, but you need
   to configure git to have your name and email address to be used in
   the commit messages:

   .. code-block:: bash

      $ git config --global user.name "John Doe"
      $ git config --global user.email johndoe@example.com

3. Make sure you have your a GitHub developer access token
   available. For details, see `contrib/backporting/README.md
   <https://github.com/cilium/cilium/blob/master/contrib/backporting/README.md>`_
4. Fetch the repo, e.g., ``git fetch``
5. Check a new branch for your backports based on the stable branch for that
   version, e.g., ``git checkout -b pr/v1.0-backport-YY-MM-DD origin/v1.0``
6. Run the ``check-stable`` script, referring to your Github access
   token, this will list the commits that need backporting, from the
   newest to oldest:

   .. code-block:: bash

      $ GITHUB_TOKEN=xxx contrib/backporting/check-stable 1.0

   .. note::
      ``contrib/backporting/check-stable`` accepts a second argument to
      specify a path to write a nicely-formatted pull request message to.
      This can be used alongside
      `Github command-line tools <https://github.com/node-gh/gh>`__ to
      send the pull request from the command line in steps 9-10 via
      ``gh pull-request -b vX.Y -l backport/vX.Y -F <path>``.

7. Cherry-pick the commits using the master git SHAs listed, starting
   from the oldest (bottom), working your way up and fixing any merge
   conflicts as they appear. Note that for PRs that have multiple
   commits you will want to check that you are cherry-picking oldest
   commits first. The ``cherry-pick`` script accepts multiple arguments,
   in which case it will attempt to apply each commit in the order
   specified on the command line until one cherry pick fails or every
   commit is cherry-picked.

   .. code-block:: bash

      $ contrib/backporting/cherry-pick <oldest-commit-sha>
      ...
      $ contrib/backporting/cherry-pick <newest-commit-sha>

8. Push your backports branch to cilium repo, e.g., ``git push -u origin pr/v1.0-backports-YY-MM-DD``
9. In Github, create a new PR from your branch towards the feature
   branch you are backporting to. Note that by default Github creates
   PRs against the master branch, so you will need to change it.
10. Label the new backport PR with the backport label for the stable branch
    such as ``backport/X.Y`` so that it is easy to find backport PRs later.
11. Mark all PRs you backported with the backport pending label ``backport-pending/X.Y``
    and clear the ``needs-backport/vX.Y`` label. This can be via the GitHub
    interface, or using the backport script ``contrib/backporting/set-labels.py``, e.g.:

    .. code-block:: bash

        # Set PR 1234's v1.0 backporting labels to pending
        $ contrib/backporting/set-labels.py 1234 pending 1.0

    .. note::

        ``contrib/backporting/set-labels.py`` requires Python 3 and
        `PyGithub <https://pypi.org/project/PyGithub/>`_ installed.

12. After the backport PR is merged, mark all backported PRs with
    ``backport-done/X.Y`` label and clear the ``backport-pending/X.Y`` label(s).

    .. code-block:: bash

        # Set PR 1234's v1.0 backporting labels to done
        contrib/backporting/set-labels.py 1234 done 1.0.
