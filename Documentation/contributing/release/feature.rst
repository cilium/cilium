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

#. Fork a new release branch from master:

   .. code-block:: shell-session

       git checkout master; git pull origin master
       git checkout -b v1.2
       git push

#. Protect the branch using the GitHub UI to disallow direct push and require
   merging via PRs with proper reviews. `Direct link <https://github.com/cilium/cilium/settings/branches>`_

#. Replace the contents of the ``CODEOWNERS`` file with the following to reduce
   code reviews to essential approvals:

   ::

        * @cilium/janitors
        api/ @cilium/api
        pkg/apisocket/ @cilium/api
        pkg/monitor/payload @cilium/api
        pkg/policy/api/ @cilium/api
        pkg/proxy/accesslog @cilium/api

#. Create a new project named "X.Y.Z" to automatically track the backports
   for that particular release. `Direct Link: <https://github.com/cilium/cilium/projects/new>`_

#. Copy the ``.github/maintainers-little-helper.yaml`` from the previous release ``vX.Y-1``
   change the contents to be relevant for the release ``vX.Y`` and set the
   ``project:`` to be the generated link created by the previous step. The link
   should be something like: ``https://github.com/cilium/cilium/projects/NNN``

#. Set the right version for the ``CustomResourceDefinitionSchemaVersion`` in
   the ``pkg/k8s/...`` by following these instructions:

   Run ``./Documentation/check-crd-compat-table.sh vX.Y``

#. Commit changes, open a pull request against the new ``v1.2`` branch, and get
   the pull request merged

   .. code-block:: shell-session

       git checkout -b pr/prepare-v1.2
       git add [...]
       git commit
       git push

#. Create the following GitHub labels:

   #. ``backport-pending/1.2``
   #. ``backport-done/1.2``
   #. ``backport/1.2``
   #. ``needs-backport/1.2``


#. Checkout to master and update the ``.github/maintainers-little-helper.yaml`` to have
   all the necessary configurations for the backport of the new ``vX.Y`` branch.
   Specifically, ensure that:

   * The project at the top of the file points to the "next" release,
   * A new section is added for the upcoming release that is being prepared, and
   * The section for the oldest release is removed.

   .. code-block:: shell-session

       $ git checkout -b pr/master-cilium-actions-update origin/master
       $ # modify .github/maintainers-little-helper.yaml
       $ git add .github/maintainers-little-helper.yaml
       $ git commit
       $ git push

#. Continue with the next step only after the previous steps are merged into
   master.

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

#. Prepare the master branch for the next development cycle:

   .. code-block:: shell-session

       git checkout master; git pull

#. Update the ``VERSION`` file to contain ``v1.2.90``
#. Add the ``VERSION`` file using ``git add`` and create & merge a PR titled
   ``Prepare for 1.3.0 development``.
#. Update the release branch on
    `Jenkins <https://jenkins.cilium.io/>`_ to be
    tested on every change and Nightly.
#. (Only 1.0 minor releases) Tag newest 1.0.x Docker image as ``v1.0-stable``
   and push it to Docker Hub. This will ensure that Kops uses latest 1.0 release by default.
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
