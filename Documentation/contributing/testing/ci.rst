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

.. _ci_junit_opensearch:

JUnit reports and OpenSearch
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Most workflows that run ``cilium connectivity test`` (and the Ginkgo suite)
write a JUnit XML report per step via ``--junit-file`` into the
``cilium-junits`` directory. At the end of the run ``common-post-jobs.yaml``
merges every ``cilium-junits-*`` artifact into a single ``cilium-junits``
artifact, always, regardless of whether the run passed. Each report contains a
test case per test with its pass or fail status.

A scraper (``corgi``) periodically ingests these reports into OpenSearch, where
historical test results can be queried. Two properties are worth knowing when
reasoning about what is and is not visible there:

- The scraper parses the JUnit report of every run it enumerates, regardless of
  the run's conclusion, and records each test case with its own pass or fail
  status. So a test failure is captured as long as its JUnit report was
  uploaded, even when the GitHub run is green. This is what makes the tolerated
  quarantine (see :ref:`ci_quarantine`) safe: a quarantined test that fails in a
  ``continue-on-error`` step still runs, still uploads its report, and its
  failure is still recorded in OpenSearch.
- The derived workflow, job and step failure-rate metrics are computed from the
  GitHub run conclusion, not from the individual test cases. A quarantined
  failure therefore does not move those failure-rate metrics; to see it, query
  the test cases directly rather than the rate.

The corollary is that a test that does not run at all produces no JUnit report,
so its failure is captured nowhere, not in the run summary and not in
OpenSearch. Prefer running a test and tolerating its failure over skipping it.

.. _test_matrix:

Testing matrix
^^^^^^^^^^^^^^

Up to date CI testing information regarding k8s - kernel version pairs can
always be found in the `Cilium CI matrix`_.

.. _Cilium CI matrix: https://docs.google.com/spreadsheets/d/1TThkqvVZxaqLR-Ela4ZrcJ0lrTJByCqrbdCjnI32_X0

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

.. _ci_quarantine:

Quarantining Failing Tests and Jobs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When a test or a whole job fails consistently for a known reason that is still
under investigation, such as a real bug or a persistent flake that is not yet
fixed, you can *quarantine* it. Quarantining stops that failure from turning CI
red while keeping the configuration running, so the signal is preserved and the
failure stays visible instead of being silently dropped. Prefer quarantining a
single test or job over :ref:`disabling an entire workflow
<ci_disabling_workflows>`, which stops every test in the workflow from running.

Two mechanisms are in use, depending on the granularity of the failure:

- Quarantine a single test within an otherwise-passing job.
- Quarantine an entire job, for example an experimental configuration that is
  not yet expected to pass.

In every case a ``::warning::`` annotation is emitted so the tolerated failure
is not hidden, and artifacts are still uploaded (except where a test is skipped
outright, which collects no result for that test).

When to quarantine
^^^^^^^^^^^^^^^^^^

Quarantine when all of the following hold:

- The failure is understood well enough to be attributed to a specific test or
  configuration, and it is not caused by the pull request under test.
- A fix is not yet available, but the failure is expected to be fixed: it is a
  bug or a flake, not intended behaviour.
- You want to keep running the test or job to preserve the signal, rather than
  deleting it.

If an entire workflow needs to stop, see :ref:`ci_disabling_workflows`
instead. If a test is being removed permanently, delete it rather than
quarantining it.

Label and track the quarantine
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Every quarantine must be tracked so it is not forgotten and gets fixed before
the next release:

#. Open (or find) a GitHub issue describing the failure. Add the
   ``ci/quarantine`` label and a ``release-blocker/<version>`` label for every
   affected release (for example ``release-blocker/1.20``). The
   ``release-blocker`` label ensures the failure must be resolved before that
   release ships; the ``ci/quarantine`` label keeps the set of quarantined
   failures easy to find.
#. Label the pull request that adds the quarantine with ``ci/quarantine`` (and
   ``release-note/ci``), and link it to the tracking issue.
#. Add a comment in the workflow next to the quarantine explaining why it is
   quarantined and how to re-arm it, referencing the tracking issue.

For example, the test quarantine in `PR #47534
<https://github.com/cilium/cilium/pull/47534>`__ is tracked by `issue #47391
<https://github.com/cilium/cilium/issues/47391>`__, and the job quarantine in
`PR #46621 <https://github.com/cilium/cilium/pull/46621>`__ is tracked by
`issue #46553 <https://github.com/cilium/cilium/issues/46553>`__; both issues
carry the ``ci/quarantine`` label.

Quarantine a single test
^^^^^^^^^^^^^^^^^^^^^^^^

Quarantine a single connectivity test by removing it from the gating run with a
``--test '!<test-name>'`` selector, then re-running it in a separate step marked
``continue-on-error: true`` with its own ``--junit-file``, so it still executes
and uploads a report while its failure does not fail the workflow. A following
step keyed on the tolerated step's ``outcome`` emits a warning annotation to
keep the failure visible. This mirrors the job quarantine below at single-test
granularity.

Every other test keeps gating. When the failure only happens on some matrix
legs, deselect the test only on the affected legs so it keeps gating on the
legs where it passes and coverage is reduced as narrowly as possible.

Do not just skip the test outright (deselect it without the tolerated re-run):
that collects no result on the affected legs, so nothing is uploaded and the
failure is captured nowhere, not even in OpenSearch (see :ref:`ci_junit_opensearch`).

The following example (from `PR #47534
<https://github.com/cilium/cilium/pull/47534>`__, in
``.github/workflows/conformance-eks.yaml``) quarantines
``north-south-loadbalancing-with-l7-policy`` and
``egress-gateway-excluded-cidrs`` on the EKS legs without prefix delegation,
where pod IPs spread across secondary ENIs in ways these tests do not cope
with, while the prefix-delegation legs keep running them inline and gating on
them. A list holds the quarantined tests; deselect each from the gating run and
record which were deselected as a step output:

.. code-block:: shell

    QUARANTINED_TESTS=(
      north-south-loadbalancing-with-l7-policy
      egress-gateway-excluded-cidrs
    )

    QUARANTINED=""
    if [[ "${{ matrix.aws-eni-pd }}" != "true" ]]; then
      for test in "${QUARANTINED_TESTS[@]}"; do
        CONNECTIVITY_TEST_DEFAULTS+=" --test '!${test}'"
        QUARANTINED+="${QUARANTINED:+,}${test}"
      done
    fi

    echo connectivity_test_defaults=${CONNECTIVITY_TEST_DEFAULTS} >> $GITHUB_OUTPUT
    echo "quarantined_tests=${QUARANTINED}" >> $GITHUB_OUTPUT

then, only when the list is non-empty, re-run those tests in one tolerated step
and warn on failure:

.. code-block:: yaml

    - name: Run quarantined tests
      id: run-tests-quarantined
      if: ${{ steps.vars-conn.outputs.quarantined_tests != '' }}
      continue-on-error: true
      env:
        QUARANTINED_TESTS: ${{ steps.vars-conn.outputs.quarantined_tests }}
      run: |
        TEST_FLAGS=""
        for test in ${QUARANTINED_TESTS//,/ }; do
          TEST_FLAGS+=" --test ${test}"
        done

        # shellcheck disable=SC2086
        cilium connectivity test ${{ steps.e2e_config.outputs.test_flags }} ${TEST_FLAGS} \
        --test-concurrency=${{ env.test_concurrency }} \
        --junit-file "cilium-junits/${{ env.job_name }} (${{ join(matrix.*, ', ') }}) - quarantined.xml"

    - name: Warn on quarantined test failure
      if: ${{ always() && steps.run-tests-quarantined.outcome == 'failure' }}
      env:
        QUARANTINED_TESTS: ${{ steps.vars-conn.outputs.quarantined_tests }}
      run: |
        echo "::warning title=Test quarantined::One of the quarantined tests (${QUARANTINED_TESTS}) failed on this leg but is quarantined, so it did not fail the workflow. Investigate the failure above; remove a test from the quarantine list once its issue is fixed."

To quarantine another test, add it to the ``QUARANTINED_TESTS`` list; to re-arm
one, drop it from the list.

Because the test still runs and its JUnit report is still uploaded, the failure
is still captured in OpenSearch even though the run is green; see
:ref:`ci_junit_opensearch`.

.. note::

    The legacy Ginkgo suite has an analogous per-``k8s-version`` deselection
    list under the ``exclude:`` key in
    ``.github/actions/ginkgo/main-focus.yaml``, and the Gateway API workflow
    deselects tests through its ``--skip-tests`` flag; each entry carries a
    justifying comment. Follow the same labeling and tracking steps above when
    an entry is a quarantine rather than a permanent constraint.

Quarantine an entire job
^^^^^^^^^^^^^^^^^^^^^^^^

To let an entire job fail without failing the workflow, for example an
experimental configuration that is not yet expected to pass, apply
``continue-on-error`` to the job, gated on a quarantine flag, and re-surface
the failure with a warning annotation. The reusable
``.github/workflows/conformance-eks.yaml`` implements this with a
``quarantine`` boolean input:

.. code-block:: yaml

    quarantine:
      description: "If true, a failure of the installation and connectivity test does not fail the workflow (the job is quarantined). A warning annotation is emitted instead, and all artifacts are still collected so the failure remains visible."
      required: false
      type: boolean
      default: false

that gates ``continue-on-error`` on the connectivity-test job, plus a step that
emits a ``::warning::`` when a quarantined job actually failed:

.. code-block:: yaml

    continue-on-error: ${{ inputs.quarantine == true }}

The caller (`PR #46621 <https://github.com/cilium/cilium/pull/46621>`__, in
``.github/workflows/conformance-kpr-eks.yaml``) drives this from a single
workflow-level environment flag and wires it through four pieces:

- A workflow-level ``env`` value (``QUARANTINE_NETKIT: "true"``) is the single
  in-file source of truth. Setting it to ``"false"`` re-arms the jobs, and
  forks inherit the quarantine automatically.
- The ``env`` context is not available in a job's ``with:`` input or in the
  status gate, so a small ``config`` job re-exports it as a job output that
  ``needs.config.outputs.quarantine_netkit`` can read in those positions.
- Each quarantined job passes ``quarantine: ${{
  needs.config.outputs.quarantine_netkit == 'true' }}`` into the reusable
  workflow.
- The ``merge-upload-and-status`` status gate tolerates the quarantined result
  by combining it with the flag through a logical OR (and with ``'skipped'`` for
  triggers where the job does not run), so a quarantined failure does not flip
  the commit status while the job stays listed in ``needs`` and still guards
  against being cancelled. A ``quarantine-warning`` job re-emits the warning at
  the parent workflow level, because the annotation from the reusable workflow
  is attached to the called job and does not surface on the caller's summary.

.. code-block:: yaml

    success: >-
      ${{
        needs.conformance-eks-kpr.result == 'success' &&
        needs.conformance-eks-kpr-ipsec.result == 'success' &&
        needs.conformance-eks-kpr-wireguard.result == 'success' &&
        (needs.conformance-eks-kpr-netkit.result == 'success' || needs.conformance-eks-kpr-netkit.result == 'skipped' || needs.config.outputs.quarantine_netkit == 'true') &&
        (needs.conformance-eks-kpr-netkit-l2.result == 'success' || needs.conformance-eks-kpr-netkit-l2.result == 'skipped' || needs.config.outputs.quarantine_netkit == 'true')
      }}

.. warning::

    Gate on the quarantine flag explicitly, as above. Do not loosen the whole
    check to ``result != 'failure'`` to tolerate a quarantined job: that also
    treats ``cancelled`` as success and would silently hide unrelated
    breakage.

Remove the quarantine
^^^^^^^^^^^^^^^^^^^^^

Once the underlying failure is fixed, remove the quarantine so the test or job
gates again: drop the test from the ``QUARANTINED_TESTS`` list (or delete the
``--test '!...'`` selector where a test is skipped outright), or set the
``QUARANTINE_*`` flag to ``"false"`` (and remove the plumbing) for a whole job.
Then close the tracking issue and drop its ``release-blocker`` label. Leaving a
quarantine in place after the fix silently reduces coverage.

.. _ci_disabling_workflows:

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
  otherwise. See :ref:`ci_quarantine` for how to quarantine a single test or
  job while keeping it running.
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
