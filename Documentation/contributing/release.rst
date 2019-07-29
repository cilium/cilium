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

#. Ensure that the necessary backports have been completed and merged. See
   :ref:`backport_process`.
#. Checkout the desired stable branch and pull it:

   ::

       git checkout v1.0; git pull

#. Create a branch for the release pull request:

   ::

       git checkout -b pr/prepare-v1.0.3

#. Update the ``VERSION`` file to represent ``X.Y.Z+1``
#. If this is the first release after creating a new release branch. Adjust the
   image pull policy for all ``.sed`` files in ``install/kubernetes/ciliumm/values.yaml`` from
   ``Always`` to ``IfNotPresent``.
#. Update the image tag versions in the examples:

   ::

       make -C install/kubernetes clean all

#. Update the ``cilium_version`` and ``cilium_tag`` variables in
   ``examples/getting-started/Vagrantfile``

#. Update the ``AUTHORS file``

   ::

       make update-authors


   .. note::

       Check to see if the ``AUTHORS`` file has any formatting errors (for
       instance, indentation mismatches) as well as duplicate contributor
       names, and correct them accordingly.


#. Generate the ``NEWS.rst`` addition based off of the prior release tag
   (e.g., if you are generating the ``NEWS.rst`` for v1.0.3):

   ::

       git shortlog v1.0.2.. > add-to-NEWS.rst

#. Add a new section to ``NEWS.rst``:

    ::

        v1.0.3
        ======

        ::

            <<contents of add-to-NEWS.rst>>
            [...]
            <<end of add-to-NEWS.rst>>

#. Add all modified files using ``git add`` and create a pull request with the
   title ``Prepare for release v1.0.3``. Add the backport label to the PR which
   corresponds to the branch for which the release is being performed, e.g.
   ``backport/1.0``.

   .. note::

       Make sure to create the PR against the desired stable branch. In this
       case ``v1.0``


#. Follow standard procedures to get the aforementioned PR merged into the
   desired stable branch. See :ref:`submit_pr` for more information about this
   process.

#. Checkout out the stable branch and pull your merged changes:

   ::

       git checkout v1.0; git pull

#. Create release tags:

   ::

       git tag -a v1.0.3 -m 'Release v1.0.3'
       git tag -a 1.0.3 -m 'Release 1.0.3'

   .. note::

       There are two tags that correspond to the same release because GitHub
       recommends using ``vx.y.z`` for release version formatting, and ReadTheDocs,
       which hosts the Cilium documentation, requires the version to be in format
       ``x.y.z`` For more information about how ReadTheDocs does versioning, you can
       read their `Versions Documentation <https://docs.readthedocs.io/en/latest/versions.html>`_.

#. Build the binaries and push it to the release bucket:

   ::

       DOMAIN=releases.cilium.io ./contrib/release/uploadrev v1.0.3


   This step will print a markdown snippet which you will need when crafting
   the GitHub release so make sure to keep it handy.

   .. note:

       This step requires valid AWS credentials to be available via the
       environment variables ``AWS_ACCESS_KEY_ID`` and
       ``AWS_SECRET_ACCESS_KEY``. Ping in the ``#development`` channel on Slack
       if you have no access. It also requires the aws-cli tools to be installed.

#. Build the container images and push them

   ::

      DOCKER_IMAGE_TAG=v1.0.3 make docker-image
      docker push cilium/cilium:v1.0.3

   .. note:

      This step requires you to login with ``docker login`` first and it will
      require your Docker hub ID to have access to the ``Cilium`` organization.
      You can alternatively trigger a build on DockerHub directly if you have
      credentials to do so.

#. Push the git release tag

   ::

       git push --tags

#. `Create a GitHub release <https://github.com/cilium/cilium/releases/new>`_:

   #. Choose the correct target branch, e.g. ``v1.0``
   #. Choose the correct target tag, e.g. ``v1.0.3``
   #. Title: ``1.0.3``
   #. Check the ``This is a pre-release`` box if you are releasing a release
      candidate.
   #. Fill in the release description:

      ::

           Changes
           -------

           ```
           << contents of NEWS.rst for this release >>
           ```

           Release binaries
           ----------------

           << contents of snippet outputed by uploadrev >>

   #. Preview the description and then publish the release

#. Announce the release in the ``#general`` channel on Slack

#. Bump the version of Cilium used in the Cilium upgrade tests to use the new release

   Please reach out on the ``#development`` channel on Slack for assistance with
   this task.

#. Update the external tools and guides to point to the released Cilium version:

    * `kubeadm <https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/>`_
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
