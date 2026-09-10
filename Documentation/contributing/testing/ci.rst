.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _ci_gha:

CI  / GitHub Actions
--------------------

The main CI infrastructure is maintained on GitHub Actions (GHA).

This infrastructure is broadly comprised of smoke tests and platform tests.
Smoke tests are typically initiated by ``pull_request`` or
``pull_request_target`` triggers automatically when opening or updating a pull
request. Platform tests often require an organization member to manually
trigger the test when the pull request is ready to be tested.

Triggering Smoke Tests
~~~~~~~~~~~~~~~~~~~~~~

Several short-running tests are automatically triggered for all contributor
submissions, subject to GitHub's limitations around first-time contributors.
If no GitHub workflows are triggering on your PR, a committer for the project
should trigger these within a few days. Reach out in the ``#testing``
channel on `Cilium Slack`_ for assistance in running these tests.

.. _trigger_phrases:

Triggering Platform Tests
~~~~~~~~~~~~~~~~~~~~~~~~~

To ensure that build resources are used judiciously, some tests on GHA are
manually triggered via comments. These builds typically make use of cloud
infrastructure, such as allocating clusters or VMs in AKS, EKS or GKE. In
order to trigger these jobs, a member of the GitHub organization must post a
comment on the Pull Request with a "trigger phrase".

If you'd like to trigger these jobs, ask in `Cilium Slack`_ in the ``#testing``
channel. If you're regularly contributing to Cilium, you can also `become a
member <https://github.com/cilium/community/blob/main/CONTRIBUTOR-LADDER.md#organization-member>`__
of the Cilium organization.

Depending on the PR target branch, a specific set of jobs is marked as required,
as per the `Cilium CI matrix`_. They will be automatically featured in PR checks
directly on the PR page. The ``/test`` trigger phrase may be used to trigger
the full testsuite at once. Additional trigger phrases (such as ``/ci-e2e-upgrade``)
can be used to run individual or optional jobs where supported.

More triggers can be found in `ariane-config.yaml <https://github.com/cilium/cilium/blob/main/.github/ariane-config.yaml>`_

For a full list of GHA, see `GitHub Actions Page <https://github.com/cilium/cilium/actions>`_

Using GitHub Actions for testing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On GHA, running a specific set of Ginkgo tests (``conformance-ginkgo.yaml``)
can also be accomplished by modifying the files under
``.github/actions/ginkgo/`` by adding or removing entries.

``main-focus.yaml``:

    This file contains a list of tests to include and exclude. The ``cliFocus``
    defined for each element in the "include" section is expanded to the
    specific defined ``focus``. This mapping allows us to determine which regex
    should be used with ``ginkgo --focus`` for each element in the "focus" list.
    See :ref:`ginkgo-documentation` for more information about ``--focus`` flag.

    Additionally, there is a list of excluded tests along with justifications
    in the form of comments, explaining why each test is excluded based on
    constraints defined in the ginkgo tests.

    For more information, refer to
    `GitHub's documentation on expanding matrix configurations <https://docs.github.com/en/actions/using-jobs/using-a-matrix-for-your-jobs#expanding-or-adding-matrix-configurations>`__

``main-k8s-versions.yaml``:

    This file defines which kernel versions should be run with specific Kubernetes
    (k8s) versions. It contains an "include" section where each entry consists of
    a k8s version, IP family, Kubernetes image, and kernel version. These details
    determine the combinations of k8s versions and kernel versions to be tested.

``main-prs.yaml``:

    This file specifies the k8s versions to be executed for each pull request (PR).
    The list of k8s versions under the "k8s-version" section determines the matrix
    of jobs that should be executed for CI when triggered by PRs.

``main-scheduled.yaml``:

    This file specifies the k8s versions to be executed on a regular basis. The
    list of k8s versions under the "k8s-version" section determines the matrix of
    jobs that should be executed for CI as part of scheduled jobs.

Workflow interactions:

    - The ``main-focus.yaml`` file helps define the test focus for CI jobs based on
      specific criteria, expanding the ``cliFocus`` to determine the relevant
      ``focus`` regex for ``ginkgo --focus``.

    - The ``main-k8s-versions.yaml`` file defines the mapping between k8s versions
      and the associated kernel versions to be tested.

    - Both ``main-prs.yaml`` and ``main-scheduled.yaml`` files utilize the
      "k8s-version" section to specify the k8s versions that should be included
      in the job matrix for PRs and scheduled jobs respectively.

    - These files collectively contribute to the generation of the job matrix
      for GitHub Actions workflows, ensuring appropriate testing and validation
      of the defined k8s versions.

For example, to only run the test under ``f10-agent-hubble-bandwidth`` with Kubernetes
version 1.26, the following files can be modified to have the following content:

``main-focus.yaml``:

   .. code-block:: yaml

        ---
        focus:
        - "f10-agent-hubble-bandwidth"
        include:
          - focus: "f10-agent-hubble-bandwidth"
            cliFocus: "K8sAgentHubbleTest"

``main-prs.yaml``:

   .. code-block:: yaml

        ---
        k8s-version:
          - "1.26"

The ``main-k8s-versions.yaml`` and ``main-scheduled.yaml`` files can be left
unmodified and this will result in the execution on the tests under
``f10-agent-hubble-bandwidth`` for the ``k8s-version`` "``1.26``".


Bisect process
^^^^^^^^^^^^^^

Bisecting Ginkgo tests (``conformance-ginkgo.yaml``) can be performed by
modifying the workflow file, as well as modifying the files under
``.github/actions/ginkgo/`` as explained in the previous section. The sections
that need to be modified for the ``conformance-ginkgo.yaml`` can be found in
form of comments inside that file under the ``on`` section and enable the
event type of ``pull_request``. Additionally, the following section also needs
to be modified:

   .. code-block:: text

        jobs:
          check_changes:
            name: Deduce required tests from code changes
            [...]
            outputs:
              tested: ${{ steps.tested-tree.outputs.src }}
              matrix_sha: ${{ steps.sha.outputs.sha }}
              base_branch: ${{ steps.sha.outputs.base_branch }}
              sha: ${{ steps.sha.outputs.sha }}
              #
              # For bisect uncomment the base_branch and 'sha' lines below and comment
              # the two lines above this comment
              #
              #base_branch: <replace with the base branch name, should be 'main', not your branch name>
              #sha: <replace with the SHA of an existing docker image tag that you want to bisect>

As per the instructions, the ``base_branch`` needs to be uncommented and
should point to the base branch name that we are testing. The ``sha`` must to
point to the commit SHA that we want to bisect. **The SHA must point to an
existing image tag under the ``quay.io/cilium/cilium-ci`` docker image
repository**.

It is possible to find out whether or not a SHA exists by running either
``docker manifest inspect`` or ``docker buildx imagetools inspect``.
This is an example output for the non-existing SHA ``22fa4bbd9a03db162f08c74c6ef260c015ecf25e``
and existing SHA ``7b368923823e63c9824ea2b5ee4dc026bc4d5cd8``:


   .. code-block:: shell

        $ docker manifest inspect quay.io/cilium/cilium-ci:22fa4bbd9a03db162f08c74c6ef260c015ecf25e
        ERROR: quay.io/cilium/cilium-ci:22fa4bbd9a03db162f08c74c6ef260c015ecf25e: not found

        $ docker buildx imagetools inspect quay.io/cilium/cilium-ci:7b368923823e63c9824ea2b5ee4dc026bc4d5cd8
        Name:      quay.io/cilium/cilium-ci:7b368923823e63c9824ea2b5ee4dc026bc4d5cd8
        MediaType: application/vnd.docker.distribution.manifest.list.v2+json
        Digest:    sha256:0b7d1078570e6979c3a3b98896e4a3811bff483834771abc5969660df38463b5

        Manifests:
          Name:      quay.io/cilium/cilium-ci:7b368923823e63c9824ea2b5ee4dc026bc4d5cd8@sha256:63dbffea393df2c4cc96ff340280e92d2191b6961912f70ff3b44a0dd2b73c74
          MediaType: application/vnd.docker.distribution.manifest.v2+json
          Platform:  linux/amd64

          Name:      quay.io/cilium/cilium-ci:7b368923823e63c9824ea2b5ee4dc026bc4d5cd8@sha256:0c310ab0b7a14437abb5df46d62188f4b8b809f0a2091899b8151e5c0c578d09
          MediaType: application/vnd.docker.distribution.manifest.v2+json
          Platform:  linux/arm64

Once the changes are committed and pushed into a draft Pull Request, it is
possible to visualize the test results on the Pull Request's page.

GitHub Test Results
^^^^^^^^^^^^^^^^^^^

Once the test finishes, its result is sent to the respective Pull Request's
page.

In case of a failure, it is possible to check with test failed by going over the
summary of the test on the GitHub Workflow Run's page:


.. image:: /images/gha-summary.png
    :align: center


On this example, the test ``K8sAgentHubbleTest Hubble Observe Test L7 Flow``
failed. With the ``cilium-sysdumps`` artifact available for download we can
retrieve it and perform further inspection to identify the cause for the
failure. To investigate CI failures, see :ref:`ci_failure_triage`.

.. _test_matrix:

Testing matrix
^^^^^^^^^^^^^^

Up to date CI testing information regarding k8s - kernel version pairs can
always be found in the `Cilium CI matrix`_.

.. _Cilium CI matrix: https://docs.google.com/spreadsheets/d/1TThkqvVZxaqLR-Ela4ZrcJ0lrTJByCqrbdCjnI32_X0

.. _testing_ci_workflow_changes:

Testing CI workflow changes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There are six routes to running a CI change, from doing nothing to opening a
separate test pull request. The notice posted alongside the
``dont-merge/needs-ci-validation`` label works out the smallest set of actions
that covers the files it flags, and tags each one with the route it uses, so the
identifiers below are what a reviewer reads there.

.. list-table:: Validation routes
   :header-rows: 1
   :widths: 10 90

   * - Route
     - What to do
   * - M0
     - Nothing. GitHub loads the workflow from the merge ref, so this pull
       request already runs the version it proposes. These files are not
       flagged. On a fork, secrets are still withheld, so a step that needs one
       is not fully exercised.
   * - M1
     - Comment ``/test``, or the relevant ``/ci-*`` trigger. This exercises the
       code under test but not the CI configuration, because for a fork Ariane
       dispatches the base branch and points ``context-ref`` at the target
       branch.
   * - M2
     - Comment the specific ``/ci-*`` trigger for each changed workflow. From a
       branch in ``cilium/cilium`` Ariane dispatches that branch, so both the
       workflow definition and ``context-ref`` come from the pull request.
       Remember that ``/test`` does not cover every workflow.
   * - M3
     - Dispatch each consuming workflow by hand, keeping the definition trusted
       and overriding ``context-ref`` to the pull request's head SHA. See the
       command under step 2 below.
   * - M4
     - Mirror the branch to ``cilium/cilium`` and dispatch against it with
       ``gh workflow run <workflow> --ref <branch>``, so that the branch's own
       definition runs. No pull request is needed for this, only the branch:
       push it, dispatch, read the run and delete it again. Nothing else reacts
       to the push, because every ``push`` trigger in this repository is
       restricted to ``main``, ``ft/main/**``, ``renovate/main-**`` or tags.
   * - M5
     - Mirror the branch under ``ft/main/``, then open a test pull request whose
       *base* is that branch. A ``pull_request_target`` workflow is loaded from
       the base branch, so pointing the base at the mirror is what makes the
       proposed definition run, under the real trigger and with no temporary
       edit to revert. A ``push`` only workflow needs no pull request at all,
       just the push; a ``workflow_call`` only one runs when any workflow that
       calls it is dispatched against the mirror, since a local
       ``./.github/workflows/…`` reference resolves at the caller's commit. Only
       a ``schedule`` only workflow has no native route, and there a temporary
       trigger is the fallback; revert it before merge.
   * - M6
     - Add the workflow's own path to its ``pull_request`` ``paths`` filter, as
       ``tests-cifuzz.yaml`` does, or include a file the filter does match in a
       test pull request. Needed when a workflow is triggered on
       ``pull_request`` but its filter excludes the workflow file itself, so a
       change to it looks validated while nothing actually runs.

Which route applies depends on what changed and, just as much, on whether the
pull request comes from a fork:

.. list-table:: Which route applies
   :header-rows: 1
   :widths: 52 24 24

   * - What the pull request changes
     - From a fork
     - From a ``cilium/cilium`` branch
   * - A workflow triggered on ``pull_request`` (``lint-go.yaml``,
       ``tests-smoke.yaml``, …)
     - M0
     - M0
   * - The same, but its ``paths`` filter excludes the workflow file itself
     - M6
     - M6
   * - Product code (Go, bpf, ``cilium-cli``)
     - M1
     - M1
   * - A composite action or config under ``.github/actions/``
     - M3
     - M2
   * - A workflow body, where the workflow has ``workflow_dispatch``
     - M4
     - M2
   * - A workflow body, where it does not (``pull_request_target``,
       ``schedule``, ``push``)
     - M5
     - M5
   * - A workflow's ``on:`` block, or a whole new workflow
     - M5
     - M5
   * - ``.github/ariane-config.yaml``
     - review only
     - M2

A change to an ``on:`` block is only partly covered, because GitHub evaluates
triggers and the ``types``, ``branches`` and ``paths`` filters when the real
event fires, and no route reproduces a cron. A whole new workflow is a special
case of its own: it is not dispatchable until GitHub has a record for the file,
which the first run of it on any branch creates, so a push or a test pull request
has to register it before ``gh workflow run`` will accept it.

Two exceptions are worth knowing. ``common-post-jobs.yaml`` consumes
``cilium/cilium/.github/actions/merge-artifacts@main``, pinned to ``main``, so a
change to that action is never exercised before merge even from a branch here.
And for a pull request from a fork the ``/default`` workflows are not dispatched
automatically at all, so nothing runs until a reviewer triggers it.

When CI runs on a pull request, only workflows triggered on ``pull_request``
use the version of the workflow file proposed in that pull request: GitHub
loads them from the pull request's merge ref. This holds whether the pull
request is opened from a fork or from a branch in ``cilium/cilium``, so the
proposed workflow is exercised in both cases. The difference is that, for a
pull request opened from a fork, GitHub withholds repository secrets and only
grants a read-only token, and workflows may not run at all until a maintainer
approves the run for a first-time contributor. So a ``pull_request`` workflow
change is tested either way, but steps that depend on secrets behave
differently on a fork.

The other triggers used in this repository do not run the proposed version at
all, for different reasons:

- ``pull_request_target`` workflows are loaded by GitHub from the base branch,
  by design, so that untrusted pull request code cannot alter a workflow that
  runs with elevated permissions.
- ``workflow_dispatch`` workflows, the ones Ariane runs for ``/test`` and the
  ``/ci-*`` comments, are loaded from the ref Ariane dispatches against. For a
  pull request opened from a branch in ``cilium/cilium`` that is the pull
  request's own branch, so the proposed definition does run, but only for those
  workflows somebody actually dispatches. For a pull request from a fork the
  branch does not exist in this repository, so Ariane dispatches the base
  branch and the proposed definition never runs.
- ``schedule`` and ``push`` workflows do not run on the pull request at all:
  they run on ``main`` (on a schedule, or once the change is merged).

Composite actions and configuration under ``.github/actions/`` follow the same
split, because the consuming workflow checks them out from ``context-ref``,
which is the pull request's branch when it is not a fork and the target branch
when it is. ``.github/ariane-config.yaml`` follows the same split, because Ariane
reads its own configuration at the very ref it dispatches: commenting ``/test``
on a pull request from a branch here uses the configuration that pull request
proposes, while for a fork it uses the target branch's.

So whether the pull request comes from a fork matters a great deal here. From a
branch in ``cilium/cilium``, most changes are exercised as soon as the right
workflow is dispatched, and the gap is only in remembering to dispatch it. From
a fork, nothing under ``.github/`` other than a ``pull_request`` workflow is
exercised, and validating it takes the deliberate steps below.

To make this visible, the ``dont-merge/needs-ci-validation`` label is applied
automatically when a pull request is opened, reopened or pushed to with changes
to such files, together with a comment listing the affected paths. The label is
a manual merge gate that a reviewer clears once the changes are validated, and
clearing it sticks: each comment records the paths it reported, and the label is
only applied again when a push adds a CI file that has not been reported yet.
So a reviewer does not have to clear the label repeatedly, but CI changes added
later during review still re-arm the gate. Renovate and Dependabot are
excluded, as they open pull requests from trusted branches within
``cilium/cilium`` where the full CI already runs against their changes. The
check itself lives in ``tools/ci-validation``, run from the ``ci-validation``
workflow; it inspects the pull request through the API and never checks out or
executes its head.

When a pull request carries this label, the changes should be validated
manually before merge:

#. A reviewer confirms that the workflow changes are safe to run and will not
   compromise the repository or leak secrets.
#. The changes are mirrored to a branch in ``cilium/cilium``, rather than left
   on a fork, so that the CI has access to secrets and the branch can be
   dispatched against directly. If the contributor is a reviewer, they are
   responsible for this step; otherwise the reviewer performs it on the
   contributor's behalf, which is why the previous step comes first. How to
   exercise the change depends on what was modified:

   - For a change to a ``workflow_dispatch`` workflow, the kind Ariane runs for
     ``/test`` or a ``/ci-*`` comment, the mirrored branch is all that is
     needed: Ariane dispatches against the pull request's branch whenever that
     branch is in ``cilium/cilium``, so the proposed definition is what runs.
     What is easy to miss is that only the workflows actually dispatched are
     covered, and ``/test`` does not cover all of them, so comment the specific
     ``/ci-*`` trigger for each changed workflow. To dispatch by hand instead,
     use ``gh workflow run <workflow> --ref <branch>``, since
     ``workflow_dispatch`` loads the definition from the ref it is dispatched
     against, passing the inputs Ariane would provide, ``SHA`` and
     ``context-ref``, as full 40 character SHAs. Apply any additional tweaks the
     workflow documents (see, e.g., the :ref:`bisect process <ci_gha>` for
     ``conformance-ginkgo.yaml``).
   - For a change to a ``pull_request_target``, ``schedule`` or ``push``
     workflow, there is no dispatch to hijack. Temporarily add a
     ``pull_request`` trigger to the affected workflow's ``on`` section and open
     a test pull request from the mirrored branch, so that GitHub runs the
     branch's version.
   - For a change to a composite action or config under ``.github/actions/``,
     the consuming workflows read it from whatever ``context-ref`` points at.
     For a pull request from a fork Ariane sets that to the target branch, so
     commenting ``/test`` exercises the base version of the file and says
     nothing about the change. Mirroring is not needed here: dispatch each
     consuming workflow yourself, keeping ``--ref`` on the base branch so that a
     trusted definition runs, and pass ``context-ref`` as the pull request's
     head SHA so that its version of the file is used::

         gh workflow run tests-e2e-upgrade.yaml --ref main \
             -f PR-number=<number> \
             -f SHA=<head SHA> \
             -f base-SHA=<base SHA> \
             -f context-ref=<head SHA>

     Identify every workflow that consumes the changed file and dispatch each
     one: not all of them are in ``/test``, and one behind its own trigger is
     easy to forget. For example ``.github/actions/e2e/lb.yaml`` is consumed by
     ``tests-e2e-upgrade.yaml``, which only runs for ``/ci-e2e-upgrade``.

     Note that overriding ``context-ref`` deliberately crosses a security
     boundary: the files under ``.github/actions/`` become steps that run with
     the repository's secrets, which is exactly why Ariane does not do this for
     forks. Only do it once the diff has been reviewed, as the first step
     above requires.

#. If the test run does not pass, iterate on the change until it does,
   coordinating with the contributor as needed.
#. Once the test run passes, link the successful run on the original pull
   request as a record of the validation.
#. When the changes are validated, a reviewer removes the
   ``dont-merge/needs-ci-validation`` label so that the pull request can be
   merged. Any temporary ``pull_request`` trigger added for testing must be
   reverted, and a separate test pull request can then be closed.

.. _ci_failure_triage:

CI Failure Triage
~~~~~~~~~~~~~~~~~

This section describes the process to triage CI failures. We define 3 categories:

+----------------------+-----------------------------------------------------------------------------------+
| Keyword              | Description                                                                       |
+======================+===================================================================================+
| Flake                | Failure due to a temporary situation such as loss of connectivity to external     |
|                      | services or bug in system component, e.g. quay.io is down, VM race conditions,    |
|                      | kube-dns bug, ...                                                                 |
+----------------------+-----------------------------------------------------------------------------------+
| CI-Bug               | Bug in the test itself that renders the test unreliable, e.g. timing issue when   |
|                      | importing and missing to block until policy is being enforced before connectivity |
|                      | is verified.                                                                      |
+----------------------+-----------------------------------------------------------------------------------+
| Regression           | Failure is due to a regression, all failures in the CI that are not caused by     |
|                      | bugs in the test are considered regressions.                                      |
+----------------------+-----------------------------------------------------------------------------------+

Triage process
^^^^^^^^^^^^^^

#. Investigate the failure you are interested in and determine if it is a
   CI-Bug, Flake, or a Regression as defined in the table above.

   #. Search `GitHub issues <https://github.com/cilium/cilium/issues?utf8=%E2%9C%93&q=is%3Aissue+>`_
      to see if bug is already filed. Make sure to also include closed issues in
      your search as a CI issue can be considered solved and then re-appears.
      Good search terms are:

      - The test name, e.g.
        ::

            k8s-1.7.K8sValidatedKafkaPolicyTest Kafka Policy Tests KafkaPolicies (from (k8s-1.7.xml))

      - The line on which the test failed, e.g.
        ::

            github.com/cilium/cilium/test/k8s/kafka_policies.go:202

      - The error message, e.g.
        ::

            Failed to produce from empire-hq on topic deathstar-plan

#. If a corresponding GitHub issue exists, update it with:

   #. A link to the failing GHA build (note that the build information is
      eventually deleted).

#. If no existing GitHub issue was found, file a `new GitHub issue <https://github.com/cilium/cilium/issues/new>`_:

   #. Attach failure case and logs from failing test
   #. If the failure is a new regression or a real bug:

      #. Title: ``<Short bug description>``
      #. Labels ``kind/bug`` and ``needs/triage``.

   #. If failure is a new CI-Bug, Flake or if you are unsure:

      #. Title ``CI: <testname>: <cause>``, e.g. ``CI: K8sValidatedPolicyTest Namespaces: cannot curl service``
      #. Labels ``kind/bug/CI`` and ``needs/triage``
      #. Include the test name and whole Stacktrace section to help others find this issue.

   .. note::

      Be extra careful when you see a new flake on a PR, and want to open an
      issue. It's much more difficult to debug these without context around the
      PR and the changes it introduced. When creating an issue for a PR flake,
      include a description of the code change, the PR, or the diff. If it
      isn't related to the PR, then it should already happen in the ``main``
      branch, and a new issue isn't needed.

**Examples:**

* ``Flake, quay.io is down``
* ``Flake, DNS not ready, #3333``
* ``CI-Bug, K8sValidatedPolicyTest: Namespaces, pod not ready, #9939``
* ``Regression, k8s host policy, #1111``

Disabling Github Actions Workflows
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. warning::
    Do not use the `GitHub web UI <https://docs.github.com/en/actions/using-workflows/disabling-and-enabling-a-workflow?tool=webui>`_
    to disable GitHub Actions workflows. It makes it difficult to find out who
    disabled the workflows and why.

Alternatives to Disabling Github Actions Workflows
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Before proceeding, consider the following alternatives to disabling an entire
GitHub Actions workflow.

- Skip individual tests. If specific tests are causing the workflow to fail,
  disable those tests instead of disabling the workflow. When you disable a
  workflow, all the tests in the workflow stop running. This makes it easier
  to introduce new regressions that would have been caught by these tests
  otherwise.
- Remove the workflow from the list of required status checks. This way the
  workflow still runs on pull requests, but you can still merge them without
  the workflow succeeding. To remove the workflow from the required status check
  list, post a message in the `#testing Slack channel <https://cilium.slack.com/archives/C7PE7V806>`_
  and @mention people in the `cilium-maintainers team <https://github.com/orgs/cilium/teams/cilium-maintainers>`__.

Step 1: Open a GitHub Issue
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Open a GitHub issue to track activities related to fixing the workflow. If there
are existing test flake GitHub issues, list them in the tracking issue. Find an
assignee for the tracking issue to avoid the situation where the workflow remains
disabled indefinitely because nobody is assigned to actually fix the workflow.

Step 2: Update the required status check list
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If the workflow is in the required status check list, it needs to be removed
from the list. Notify the `cilium-maintainers team <https://github.com/orgs/cilium/teams/cilium-maintainers>`__
by mentioning ``@cilium/cilium-maintainers`` in the tracking issue and ask them
to remove the workflow from the required status check list.

Step 3: Update the workflow configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Update the workflow configuration as described in the following sub-steps
depending on whether the workflow is triggered by the ``/test`` comment
or by the ``pull_request`` or ``pull_request_target`` trigger. Open a pull
request with your changes, have it reviewed, then merged.

.. tabs::
  .. group-tab:: ``/test`` comment trigger

    For those workflows that get triggered by the ``/test`` comment, update
    ariane-config.yaml and remove the workflow from ``triggers:/test:workflows``
    section (`an example <https://github.com/cilium/cilium/pull/29488>`_). Do not
    remove the targeted trigger (``triggers:/ci-e2e`` for example) so that you can
    still use the targeted trigger to run the workflow when needed.

  .. group-tab:: ``pull_request`` or ``pull_request_target`` trigger

    For those workflows that get triggered by the ``pull_request`` or
    ``pull_request_target`` trigger, remove the trigger from the workflow file.
    Do not remove the ``schedule`` trigger if the workflow has it. It is useful
    to be able to see if the workflow has stabilized enough over time when making
    the decision to re-enable the workflow.
