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
directly on the PR page. The following trigger phrases may be used to trigger
them all at once:

+------------------+--------------------------+
| PR target branch | Trigger required PR jobs |
+==================+==========================+
| main             | /test                    |
+------------------+--------------------------+
| v1.14            | /test-backport-1.14      |
+------------------+--------------------------+
| v1.13            | /test-backport-1.13      |
+------------------+--------------------------+
| v1.12            | /test-backport-1.12      |
+------------------+--------------------------+

Pull requests submitted against older stable branches such as v1.13 may also be
subject to Jenkins CI jobs. For more information, see
`v1.13 CI <https://docs.cilium.io/en/v1.13/contributing/testing/ci/#ci-jenkins>`__.

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

For example, to only run the test under ``f09-datapath-misc-2`` with Kubernetes
version 1.26, the following files can be modified to have the following content:

``main-focus.yaml``:

   .. code-block:: yaml

        ---
        focus:
        - "f09-datapath-misc-2"
        include:
          - focus: "f09-datapath-misc-2"
            cliFocus: "K8sDatapathConfig Check|K8sDatapathConfig IPv4Only|K8sDatapathConfig High-scale|K8sDatapathConfig Iptables|K8sDatapathConfig IPv4Only|K8sDatapathConfig IPv6|K8sDatapathConfig Transparent"

``main-prs.yaml``:

   .. code-block:: yaml

        ---
        k8s-version:
          - "1.26"

The ``main-k8s-versions.yaml`` and ``main-scheduled.yaml`` files can be left
unmodified and this will result in the execution on the tests under
``f09-datapath-misc-2`` for the ``k8s-version`` "``1.26``".


Bisect process
^^^^^^^^^^^^^^

Bisecting Ginkgo tests (``conformance-ginkgo.yaml``) can be performed by
modifying the workflow file, as well as modifying the files under
``.github/actions/ginkgo/`` as explained in the previous section. The sections
that need to be modified for the ``conformance-ginkgo.yaml`` can be found in
form of comments inside that file under the ``on`` section and enable the
event type of ``pull_request``. Additionally, the following section also needs
to be modified:

   .. code-block:: yaml

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


On this example, the test ``K8sDatapathConfig Transparent encryption DirectRouting Check connectivity with transparent encryption and direct routing with bpf_host``
failed. With the ``cilium-sysdumps`` artifact available for download we can
retrieve it and perform further inspection to identify the cause for the
failure. To investigate CI failures, see :ref:`ci_failure_triage`.

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
