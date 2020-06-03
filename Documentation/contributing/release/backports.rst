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

Committers may nominate PRs that have been merged into master as candidates for
backport into stable releases if they affect the stable production usage
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
backported to the stable branch ``X.Y``. The following steps summarize the
process for backporting these PRs:

* One-time setup
* Preparing PRs for backport
* Cherry-picking commits into a backport branch
* Posting the PR and updating GitHub labels

.. _backport_setup:

One-time setup
~~~~~~~~~~~~~~

#. The scripts referred to below need to be run on Linux, they do not
   work on macOS. You can use the cilium dev VM for this, but you need
   to configure git to have your name and email address to be used in
   the commit messages:

   .. code-block:: bash

      $ git config --global user.name "John Doe"
      $ git config --global user.email johndoe@example.com

#. Make sure you have a GitHub developer access token with the ``public_repos``
   scope available. For details, see `contrib/backporting/README.md
   <https://github.com/cilium/cilium/blob/master/contrib/backporting/README.md>`_

#. This guide makes use of several tools to automate the backporting process.
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
   | python3                                                      | No        | `Python Downloads <https://www.python.org/downloads/>`_ |
   +--------------------------------------------------------------+-----------+---------------------------------------------------------+
   | `PyGithub <https://pypi.org/project/PyGithub/>`_             | No        | ``pip3 install PyGithub``                               |
   +--------------------------------------------------------------+-----------+---------------------------------------------------------+
   | `Github hub CLI <https://github.com/github/hub>`_            | No        | N/A (OS-specific)                                       |
   +--------------------------------------------------------------+-----------+---------------------------------------------------------+

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

Creating the backports branch
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Run ``contrib/backporting/start-backport`` for the release version that
   you intend to backport PRs for. This will pull the latest repository commits
   from the Cilium repository (assumed to be the git remote ``origin``), create
   a new branch, and runs the ``contrib/backporting/check-stable`` script to
   fetch the full set of PRs to backport.

   .. code-block:: bash

      $ GITHUB_TOKEN=xxx contrib/backporting/start-backport 1.0

   .. note::

      This command will leave behind a file in the current directory with a
      name based upon the release version and the current date in the form
      ``vRELEASE-backport-YYYY-MM-DD.txt`` which contains a prepared backport
      pull-request description so you don't need to write one yourself.

#. Cherry-pick the commits using the master git SHAs listed, starting
   from the oldest (top), working your way down and fixing any merge
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

#. (Optional) If there are any commits or pull requests that are tricky or
   time-consuming to backport, consider reaching out for help on Slack. If the
   commit does not cherry-pick cleanly, please mention the necessary changes in
   the pull request description in the next section.

#. Push your backports branch to cilium repo.

   .. code-block:: bash

      $ git push -u origin HEAD

Creating the backport pull request
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The backport pull-request may be created via CLI tools, or alternatively
you can use the GitHub web interface to achieve these steps.

Via command-line tools
^^^^^^^^^^^^^^^^^^^^^^

These steps require all of the tools described in the :ref:`backport_setup`
section above. It pushes the git tree, creates the pull request and updates
the labels for the PRs that are backported, based on the
``vRELEASE-backport-YYYY-MM-DD.txt`` file in the current directory.

   .. code-block:: bash

      # contrib/backporting/submit-backport

Via GitHub web interface
^^^^^^^^^^^^^^^^^^^^^^^^

#. Create a new PR from your branch towards the feature branch you are
   backporting to. Note that by default Github creates PRs against the
   ``master`` branch, so you will need to change it. The title and
   description for the pull request should be based upon the
   ``vRELEASE-backport-YYYY-MM-DD.txt`` file that was generated by the scripts
   above.

#. Label the new backport PR with the backport label for the stable branch such
   as ``backport/X.Y`` as well as ``kind/backports`` so that it is easy to find
   backport PRs later.

#. Mark all PRs you backported with the backport pending label
   ``backport-pending/X.Y`` and clear the ``needs-backport/vX.Y`` label. This
   can be done with the command printed out at the bottom of the output from
   the ``start-backport`` script above (``GITHUB_TOKEN`` needs to be set for
   this to work).

Running the CI against the pull request
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To validate a cross-section of various tests against the PRs, backport PRs
should be validated in the CI by running all CI targets. This can be triggered
by adding a comment to the PR with exactly the text ``test-backport-x.x``, where ``x.x`` is the target version.
The comment must not contain any other characters.

After the backports are merged
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

After the backport PR is merged, mark all backported PRs with
``backport-done/X.Y`` label and clear the ``backport-pending/X.Y`` label(s). If
the backport pull request description was generated using the scripts above,
then the full command is listed in the pull request description.

.. code-block:: bash

   # Set PR 1234's v1.0 backporting labels to done
   contrib/backporting/set-labels.py 1234 done 1.0.
