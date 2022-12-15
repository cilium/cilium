.. only:: not (epub or latex or html)
  
    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _minor_release_process:

Feature Release Process
=======================

This document describes the process for creating a major or minor feature
release of Cilium.

On Freeze date
--------------

Create the branch
~~~~~~~~~~~~~~~~~

#. Fork a new release branch from master:

   .. code-block:: shell-session

       git checkout master; git pull origin master
       git checkout -b vX.Y
       git push

#. Protect the branch using the GitHub UI to disallow direct push and require
   merging via PRs with proper reviews. `Direct link <https://github.com/cilium/cilium/settings/branches>`_

#. Update the contents of the ``CODEOWNERS`` file to reduce code reviews to
   essential approvals:

   #. Keep ``* @cilium/tophat`` fallback entry.
   #. Keep ``/.github/workflows/`` entry for CI/CD security.
   #. Keep all ``@cilium/api`` and @cilium/sig-hubble-api assignments for API
      stability on the release branch.
   #. Remove everything else so that it is handled by the Top Hat.

#. Delete files that are no longer necessary in the tree.

   .. code-block:: shell-session

       $ git rm stable.txt \
         .github/dependabot.yml .github/renovate.json \
         .github/pull_request_template.md \
         .github/ISSUE_TEMPLATE/*
         .github/workflows/close-stale-issues.yml \
         .github/workflows/ci-images-* \
         .github/workflows/lint-codeowners.yaml \
         .github/workflows/test*fuzz* \
         .github/workflows/test*l4lb* \
         .github/workflows/conformance*

   .. warning::

       The above will delete all conformance tests from the branch. Most of
       these have the stable branch workflow defined on the main branch, but
       it is important to check whether all of these will continue to run on
       the new branch.

#. Create a new project named "X.Y.Z" to automatically track the backports
   for that particular release. `Direct Link: <https://github.com/cilium/cilium/projects/new>`_

#. Copy the following files from the previous release ``vX.Y-1``
   change the contents to be relevant for the release ``vX.Y``. For
   ``.github/maintainers-little-helper.yaml``, set the ``project:`` to be the
   generated link created by the previous step. The link should be something
   like: ``https://github.com/cilium/cilium/projects/NNN``.

   ::

      .github/maintainers-little-helper.yaml
      .github/workflows/build-images-ci.yaml
      .github/workflows/build-images-hotfixes.yaml
      .github/workflows/build-images-releases.yaml

   Possibly useful commands for the above (substitute ``vX_Y`` and ``vX.Y``):

   .. code-block:: shell-session

       $ sed -i 's/\(ci_\)master/\1vX_Y/g' .github/workflows/*
       $ sed -i 's/\(:\)latest/\1vX.Y/g' .github/workflows/*
       $ sed -i 's/master/v1.13/g' .github/workflows/lint-* \
             .github/workflows/documentation.yaml \
             .github/workflows/test*smoke*
       $ vim $(git grep -l master -- .github/workflows/)

#. Set the right version for the ``CustomResourceDefinitionSchemaVersion`` in
   the ``pkg/k8s/...`` by following these instructions:

   Run ``./Documentation/check-crd-compat-table.sh vX.Y``

#. Double check the changes above vs. the commit created last time a new
   branch was created from the main branch.

#. Commit changes, open a pull request against the new ``vX.Y`` branch, and get
   the pull request merged

   .. code-block:: shell-session

       git checkout -b pr/prepare-vX.Y
       git add [...]
       git commit -s
       gh create -B vX.Y

#. Create the following GitHub labels:

   #. ``backport-pending/X.Y``
   #. ``backport-done/X.Y``
   #. ``backport/X.Y``
   #. ``needs-backport/X.Y``

Update the main branch's CI
~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Checkout to master and update the ``.github/maintainers-little-helper.yaml`` to have
   all the necessary configurations for the backport of the new ``vX.Y`` branch.
   Specifically, ensure that:

   * The project at the top of the file points to the "next" release,
   * A new section is added for the upcoming release that is being prepared, and
   * The section for the oldest release is removed.

   .. code-block:: shell-session

       $ git checkout -b pr/master-cilium-actions-update origin/master
       $ git grep -l vX.Y-1 .github/
       .github/dependabot.yml
       .github/maintainers-little-helper.yaml
       .github/renovate.json
       .github/workflows/ci-images-garbage-collect.yaml
       .github/workflows/conformance-externalworkloads-v1.12.yaml
       .github/workflows/lint-build-commits.yaml
       .github/workflows/loki.yaml
       .github/workflows/tests-l4lb-v1.12.yaml
       $ # check each file above and add the relevant vX.Y config in each
       $ git add ...

#. Make a copy of the per-branch CI configurations from the previous version.

   Make sure to update the ``vX.Y`` and ``vX.Y-1`` values in the command below.
   Note that the ``$OLD_VER`` uses an escape to avoid matching digests!

   .. code-block:: shell-session

      $ export OLD_VER="X\.Y-1"
      $ export NEW_VER="X.Y"
      $ for f in .github/workflows/*v${OLD_VER}*; do \
            cat $f \
            | sed 's/'${OLD_VER}'/'${NEW_VER}'/g' \
            > $(echo $f | sed 's/'${OLD_VER}'/'${NEW_VER}'/g'); \
        done
      $ git add .github/workflows/*${NEW_VER}*

#. Commit the changes, open a PR and get it merged.

   .. code-block:: shell-session

       $ git commit -s
       $ gh create -B vX.Y

Prepare for the next release candidate
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Continue with the next steps only after the previous steps are merged into
   the main branch.

#. Mark all open PRs with ``needs-backport/x.y`` that have the milestone ``x.y``

#. Change the VERSION file to contain the next ``rc`` version. For example,
   if we are branching v1.2 and still in the RC phase we need to change the
   VERSION file to contain the ``v1.2.0-rcX``

#. Set the branch as "Active" and the "Privacy Level" to "Private" in the
   readthedocs Admin page. (Replace ``v1.2`` with the right branch)
   ``https://readthedocs.org/dashboard/cilium/version/v1.2/``

#. Since this is the first release being made from a new branch, please
   follow the :ref:`generic_release_process` to release ``v1.2.0-rc1``.

#. Alert in the testing channel that a new jenkins job needs to be created for
   this new branch.


Prepare for the next development cycle
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Prepare the master branch for the next development cycle:

   .. code-block:: shell-session

       git checkout master; git pull

#. Update the ``VERSION`` file to contain ``v1.2.90``
#. Add the ``VERSION`` file using ``git add`` and create & merge a PR titled
   ``Prepare for 1.3.0 development``.
#. Update the release branch on
    `Jenkins <https://jenkins.cilium.io/>`_ to be
    tested on every change and Nightly.
#. Update Grafana dashboards in `Grafana <https://grafana.com/orgs/cilium/dashboards>`_.
   Install the dashboards available in ``./examples/kubernetes/addons/prometheus``
   and use them to upload them to Grafana.


For the final release
---------------------

#. Follow the :ref:`generic_release_process` to create the final replace and replace
   ``X.Y.0-rcX`` with ``X.Y.0``.

#. Announce to Slack with a more thorough release text. Sample text:

   ::

      @channel :cilium-new: **Announcement:** Cilium 1.7.0 is out! :tada:

      <Short summary of major features pulled from Blog, eg:>
      *Amazing Technology*: Just some of the great work the community has
      been working on over the past few months.

      For more information, see the blog post:
      https://cilium.io/blog/2020/02/18/cilium-17

#. Update ``SECURITY.md`` to represent the security support for the most recent
   three release series.

#. Set the branch for the oldest release (now EOL) as "Active" and "Hidden" in
   the readthedocs Admin page. (Replace ``v1.2`` with the right branch)
   ``https://readthedocs.org/dashboard/cilium/version/v1.2/``
