.. only:: not (epub or latex or html)
  
    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _release_management:

Release Management
------------------

This section describes the release cadence and all release related processes.

Release Cadence
~~~~~~~~~~~~~~~

Cilium schedules a minor release every 6 weeks. Each minor release is performed
by incrementing the ``Y`` in the version format ``X.Y.Z``. The group of
committers can decide to increment ``X`` instead to mark major milestones in
which case ``Y`` is reset to 0.

.. _stable_releases:

Stable releases
~~~~~~~~~~~~~~~

The committers can nominate PRs merged into master as required for backport
into the stable release branches. Upon necessity, stable releases are published
with the version ``X.Y.Z+1``. Stable releases are regularly released in high
frequency or on demand to address major incidents.

In order to guarantee stable production usage while maintaining a high release
cadence, the following stable releases will be maintained:

* Stable backports into the last two releases
* :ref:`lts` release for extended long term backport coverage


Backport criteria for X.Y.Z+n
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Criteria for the inclusion into latest stable release branch, i.e. what goes
into ``v1.1.x`` before ``v1.2.0`` has been released:

- All bugfixes

Backport criteria for X.Y-1.Z
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Criteria for the inclusion into the stable release branch of the previous
release, i.e. what goes into ``v1.0.x``, before ``v1.2.0`` has been released:

- Security relevant fixes
- Major bugfixes relevant to the correct operation of Cilium

.. _lts:

LTS
~~~

The group of committers nominates a release to be a long term stable release.
Such releases are guaranteed to receive backports for major and security
relevant bugfixes. LTS releases will be declared end of life after 6 months.
The group of committers will nominate and start supporting a new LTS release
before the current LTS expires. If for some reason, no release can be declared
LTS before the current LTS release expires, the current LTS lifetime will be
extended.

Given the current 6 weeks release cadence, the development teams will aim at
declaring every 3rd release to be an LTS to guarantee enough time overlap
between LTS release.

Current LTS releases
^^^^^^^^^^^^^^^^^^^^

+----------------------+---------------------------+-----------------------+
| Release              | Original Release Date     | Scheduled End of Life |
+======================+===========================+=======================+
| 1.0                  | 2018-04-24                | 2018-10-24            |
+----------------------+---------------------------+-----------------------+

.. _generic_release_process:

Generic Release Process
~~~~~~~~~~~~~~~~~~~~~~~

This process applies to all releases other than minor releases, this includes:

* Stable releases
* Release candidates

If you intent to release a new minor release, see the
:ref:`minor_release_process` section instead.

.. note:: The following commands have been validated when ran in the VM
          used in the Cilium development process. See :ref:`dev_env` for
          detailed instructions about setting up said VM.

GitHub template process
~~~~~~~~~~~~~~~~~~~~~~~

#. File a `new release issue <https://github.com/cilium/cilium/issues/new?assignees=&labels=kind%2Frelease&template=release_template.md&title=vX.Y.Z+release>`_
   on GitHub, updating the title to reflect the version that will be released.

#. Follow the steps in the issue template to prepare the release.

Reference steps for the template
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Ensure that the necessary backports have been completed and merged. See
   :ref:`backport_process`.

   #. Update GitHub project and create ``vX.Y.Z+1`` project if applicable.
   #. Update PRs / issues that were added to the ``vX.Y.Z`` project, but didn't
      make it into this release into the ``vX.Y.Z+1`` project.

#. Create a new project named "X.Y.Z+1" to automatically track the backports
   for that particular release. `Direct Link: <https://github.com/cilium/cilium/projects/new>`_

#. Checkout the desired stable branch and pull it:

   ::

       git checkout v1.0; git pull

#. Run the release preparation script:

   ::

      contrib/release/start-release.sh

  .. note::

       Check to see if the ``AUTHORS`` file has any formatting errors (for
       instance, indentation mismatches) as well as duplicate contributor
       names, and correct them accordingly.

#. Update the ``cilium_version`` and ``cilium_tag`` variables in
   ``examples/getting-started/Vagrantfile``

#. Add all modified files using ``git add`` and create a pull request with the
   title ``Prepare for release v1.0.3``.

#. Prepare a pull request for the changes:

   ::

      contrib/release/submit-release.sh

#. Follow standard procedures to get the aforementioned PR merged into the
   desired stable branch. See :ref:`submit_pr` for more information about this
   process.

#. Checkout out the stable branch and pull your merged changes:

   ::

       git checkout v1.0; git pull

#. Create and push release tags to GitHub:

   ::

      contrib/release/tag-release.sh

   .. note::

       There are two tags that correspond to the same release because GitHub
       recommends using ``vx.y.z`` for release version formatting, and ReadTheDocs,
       which hosts the Cilium documentation, requires the version to be in format
       ``x.y.z`` For more information about how ReadTheDocs does versioning, you can
       read their `Versions Documentation <https://docs.readthedocs.io/en/latest/versions.html>`_.

#. Wait for DockerHub to prepare all docker images.

#. `Publish a GitHub release <https://github.com/cilium/cilium/releases/>`_:

   Following the steps above, the release draft will already be prepared.
   Preview the description and then publish the release.

#. Prepare Helm changes for the release using the `Cilium Helm Charts Repository <https://github.com/cilium/charts/>`_
   and push the changes into that repository (not the main cilium repository):

   ::

      ./prepare_artifacts.sh /path/to/cilium/repository/checked/out/to/release/commit
      git push

#. Prepare Helm changes for the dev version of the branch using the `Cilium Helm Charts Repository <https://github.com/cilium/charts/>`_
   for the vX.Y helm charts, and push the changes into that repository (not the main cilium repository):

   In the ``cilium/cilium`` repository:

   #. ``git checkout vx.y -b vx.z-dev``
   #. Change the ``VERSION`` file to ``x.y-dev``
   #. Run ``make -C install/kubernetes``

   In the ``cilium/charts`` repository:

   ::

      ./prepare_artifacts.sh /path/to/cilium/repository/checked/out/to/release/commit
      git push

   After pushing you can revert all the changes made in the local branch
   ``x.y-dev`` from ``cilium/cilium``.


#. Announce the release in the ``#general`` channel on Slack. Sample text:

   ::

      :cilium-new: **Announcement:** Cilium vX.Y.Z has been released :tada:

      <If security release or major bugfix, short summary of fix here>

      For more details, see the release notes:
      https://github.com/cilium/cilium/releases/tag/vX.Y.Z

#. Create a new git branch based on the master branch to update ``README.rst``:

   ::

      git checkout -b pr/bump-readme-vX.Y.Z origin/master
      contrib/release/bump-readme.sh
      # (Commit changes & submit PR)

#. Bump the version of Cilium used in the Cilium upgrade tests to use the new release

   Please reach out on the ``#development`` channel on Slack for assistance with
   this task.

#. Update the ``stable`` tags for ``cilium``, ``cilium-operator``,
   ``cilium-operator-aws``, ``cilium-operator-azure``,
   ``cilium-operator-generic``, ``cilium-docker-plugin`` and ``hubble-relay``
   on DockerHub, for the latest version of Cilium. For example, if the latest
   version is ``1.8``, then for all patch releases on the ``1.8`` line, this
   step should be performed. Once ``1.9`` is out for example, then this is no
   longer required for ``1.8``.

   **Note**, the DockerHub UI will not allow you to modify the ``stable`` tag
   directly. You will need to delete it, and then create a new, updated one.

#. Update the following external tools and guides to point to the released
   Cilium version. This step is only required on a new minor release like going
   from ``1.8`` to ``1.9``.

    * `kubeadm <https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/>`_
    * `kops <https://github.com/kubernetes/kops/>`_
    * `kubespray <https://github.com/kubernetes-sigs/kubespray/>`_

.. _minor_release_process:

Minor Release Process
~~~~~~~~~~~~~~~~~~~~~

On Freeze date
^^^^^^^^^^^^^^

#. Fork a new release branch from master:

   ::

       git checkout master; git pull
       git checkout -b v1.2
       git push

#. Protect the branch using the GitHub UI to disallow direct push and require
   merging via PRs with proper reviews.

#. Replace the contents of the ``CODEOWNERS`` file with the following to reduce
   code reviews to essential approvals:

   ::

        * @cilium/janitors
        api/ @cilium/api
        pkg/apisocket/ @cilium/api
        pkg/monitor/payload @cilium/api
        pkg/policy/api/ @cilium/api
        pkg/proxy/accesslog @cilium/api

#. Commit changes, open a pull request against the new ``v1.2`` branch, and get
   the pull request merged

   ::

       git checkout -b pr/prepare-v1.2
       git add [...]
       git commit
       git push

#. Follow the :ref:`generic_release_process` to release ``v1.2.0-rc1``.

#. Create the following GitHub labels:

   #. ``backport-pending/1.2``
   #. ``backport-done/1.2``
   #. ``backport/1.2``
   #. ``needs-backport/1.2``

#. Prepare the master branch for the next development cycle:

   ::

       git checkout master; git pull

#. Update the ``VERSION`` file to contain ``v1.2.90``
#. Add the ``VERSION`` file using ``git add`` and create & merge a PR titled
   ``Prepare for 1.3.0 development``.
#. Update the release branch on
    `Jenkins <https://jenkins.cilium.io/job/cilium-ginkgo/job/cilium/>`_ to be
    tested on every change and Nightly.
#. (Only 1.0 minor releases) Tag newest 1.0.x Docker image as ``v1.0-stable``
   and push it to Docker Hub. This will ensure that Kops uses latest 1.0 release by default.



For the final release
^^^^^^^^^^^^^^^^^^^^^

#. Follow the :ref:`generic_release_process` to create the final replace and replace
   ``X.Y.0-rcX`` with ``X.Y.0``.

.. _backport_process:

Backporting process
~~~~~~~~~~~~~~~~~~~

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
