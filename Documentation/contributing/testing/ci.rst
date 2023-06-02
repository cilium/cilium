.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _ci_jenkins:

CI / Jenkins
------------

The main CI infrastructure is maintained at https://jenkins.cilium.io/

Triggering Pull-Request Builds With Jenkins
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To ensure that build resources are used judiciously, builds on Jenkins
are manually triggered via comments on each pull-request that contain
"trigger-phrases". Only members of the Cilium GitHub organization are
allowed to trigger these jobs.

Depending on the PR target branch, a specific set of jobs is marked as required,
as per the `Cilium CI matrix`_. They will be automatically featured in PR checks
directly on the PR page. The following trigger phrases may be used to trigger
them all at once:

+------------------+--------------------------+
| PR target branch | Trigger required PR jobs |
+==================+==========================+
| main             | /test                    |
+------------------+--------------------------+
| v1.13            | /test-backport-1.13      |
+------------------+--------------------------+
| v1.12            | /test-backport-1.12      |
+------------------+--------------------------+
| v1.11            | /test-backport-1.11      |
+------------------+--------------------------+

For ``main`` PRs: on top of ``/test``, one may use ``/test-missed-k8s`` to
trigger all non-required K8s versions on Kernel 4.9 as per the `Cilium CI
matrix`_.

For a full list of Jenkins PR jobs, see `Jenkins (PR tab)
<https://jenkins.cilium.io/view/PR/>`_. Trigger phrases are configured within
each job's build triggers advanced options.

There are some feature flags based on Pull Requests labels, the list of labels
are the following:

- ``area/containerd``: Enable containerd runtime on all Kubernetes test.
- ``ci/net-next``: Run tests on net-next kernel. This causes the  ``/test``
  target to only run on the net-next kernel. It is purely for testing on a
  different kernel, to merge a PR it must pass the CI without this flag.

Retrigger specific jobs
^^^^^^^^^^^^^^^^^^^^^^^^^^

For all PRs: one may manually retrigger a specific job (e.g. in case of a flake)
with the individual trigger featured directly in the PR check's name (e.g. for
``K8s-1.20-kernel-4.9 (test-1.20-4.9)``, use ``/test-1.20-4.9``).

This works for all displayed Jenkins tests.

Testing with race condition detection enabled
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Optional non-required Jenkins are available for running the test suite with race
condition detection enabled, and may be triggered using the trigger phrase
``/test-race``.

For a full list of Jenkins PR jobs with race detection enabled, see `Jenkins
(Race Detection tab) <https://jenkins.cilium.io/view/Race%20Detection/>`_.
Trigger phrases are configured within each job's build triggers advanced
options.

Using Jenkins for testing
~~~~~~~~~~~~~~~~~~~~~~~~~

Typically when running Jenkins tests via one of the above trigger phases, it
will run all of the tests in that particular category. However, there may be
cases where you just want to run a single test quickly on Jenkins and observe
the test result. To do so, you need to update the relevant test to have a
custom name, and to update the Jenkins file to focus that test. Below is an
example patch that shows how this can be achieved.

.. code-block:: diff

    diff --git a/ginkgo.Jenkinsfile b/ginkgo.Jenkinsfile
    index ee17808748a6..637f99269a41 100644
    --- a/ginkgo.Jenkinsfile
    +++ b/ginkgo.Jenkinsfile
    @@ -62,10 +62,10 @@ pipeline {
                 steps {
                     parallel(
                         "Runtime":{
    -                        sh 'cd ${TESTDIR}; ginkgo --focus="RuntimeValidated"'
    +                        sh 'cd ${TESTDIR}; ginkgo --focus="XFoooo"'
                         },
                         "K8s-1.9":{
    -                        sh 'cd ${TESTDIR}; K8S_VERSION=1.9 ginkgo --focus="K8sValidated" ${FAILFAST}'
    +                        sh 'cd ${TESTDIR}; K8S_VERSION=1.9 ginkgo --focus="K8sFooooo" ${FAILFAST}'
                         },
                         failFast: true
                     )
    diff --git a/test/k8s/nightly.go b/test/k8s/nightly.go
    index 62b324619797..3f955c73a818 100644
    --- a/test/k8s/nightly.go
    +++ b/test/k8s/nightly.go
    @@ -466,7 +466,7 @@ var _ = Describe("NightlyExamples", func() {

                    })

    -               It("K8sValidated Updating Cilium stable to main", func() {
    +               FIt("K8sFooooo K8sValidated Updating Cilium stable to main", func() {
                            podFilter := "k8s:zgroup=testapp"

                            //This test should run in each PR for now.

Jobs Overview
~~~~~~~~~~~~~

Cilium-PR-Ginkgo-Tests-Validated
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Runs validated Ginkgo tests which are confirmed to be stable and have been
verified. These tests must always pass.

The configuration for this job is contained within ``ginkgo.Jenkinsfile``.

The job runs the following steps in parallel:

    - Runs the single-node e2e tests using the Docker runtime.
    - Runs the multi-node Kubernetes e2e tests against the latest default
      version of Kubernetes specified above.

This job can be used to run tests on custom branches. To do so, log into Jenkins and go to https://jenkins.cilium.io/job/cilium-ginkgo/configure .
Then add your branch name to ``GitHub Organization -> cilium -> Filter by name (with wildcards) -> Include`` field and save changes.
After you don't need to run tests on your branch, please remove the branch from this field.

.. note::

   It is also possible to run specific tests from this suite via ``test-only``.
   The comment can contain 3 arguments: ``--focus`` which specifies which tests
   should be run, ``--kernel_version`` for supported kernel version
   (net-next, 49, 419 are possible values right now), ``--k8s_version`` for k8s
   version. If you want to run only one ``It`` block, you need to prepend it
   with a test suite and create a regex, e.g
   ``/test-only --focus="K8sDatapathConfig.*Check connectivity with automatic direct nodes routes" --k8s_version=1.18 --kernel_version=net-next``
   will run specified test in 1.18 Kubernetes cluster running on net-next nodes.
   Kubernetes version defaults to 1.21, kernel version defaults to 4.19.

   +-------------------------------------------------+-------------------------------------------+
   | ``/test-only --focus="K8s"``                    | Runs all kubernetes tests                 |
   +-------------------------------------------------+-------------------------------------------+
   | ``/test-only --focus="K8sChaos"``               | Runs all k8s chaos tests                  |
   +-------------------------------------------------+-------------------------------------------+
   | ``/test-only --focus="K8sDatapathConfig"``      | Runs all k8s datapath configuration tests |
   +-------------------------------------------------+-------------------------------------------+
   | ``/test-only --focus="K8sDemos"``               | Runs all k8s demo tests                   |
   +-------------------------------------------------+-------------------------------------------+
   | ``/test-only --focus="K8sKubeProxyFreeMatrix"`` | Runs all k8s kube-proxy free matrix tests |
   +-------------------------------------------------+-------------------------------------------+
   | ``/test-only --focus="K8sFQDNTest"``            | Runs all k8s fqdn tests                   |
   +-------------------------------------------------+-------------------------------------------+
   | ``/test-only --focus="K8sHealthTest"``          | Runs all k8s health tests                 |
   +-------------------------------------------------+-------------------------------------------+
   | ``/test-only --focus="K8sHubbleTest"``          | Runs all k8s Hubble tests                 |
   +-------------------------------------------------+-------------------------------------------+
   | ``/test-only --focus="K8sIdentity"``            | Runs all k8s identity tests               |
   +-------------------------------------------------+-------------------------------------------+
   | ``/test-only --focus="K8sIstioTest"``           | Runs all k8s Istio tests                  |
   +-------------------------------------------------+-------------------------------------------+
   | ``/test-only --focus="K8sKafkaPolicyTest"``     | Runs all k8s Kafka tests                  |
   +-------------------------------------------------+-------------------------------------------+
   | ``/test-only --focus="K8sPolicyTest"``          | Runs all k8s policy tests                 |
   +-------------------------------------------------+-------------------------------------------+
   | ``/test-only --focus="K8sServicesTest"``        | Runs all k8s services tests               |
   +-------------------------------------------------+-------------------------------------------+
   | ``/test-only --focus="K8sUpdates"``             | Runs k8s update tests                     |
   +-------------------------------------------------+-------------------------------------------+


Cilium-PR-Ginkgo-Tests-Kernel
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Runs the Kubernetes e2e tests with a 4.19 kernel. The configuration for this
job is contained within ``ginkgo-kernel.Jenkinsfile``.


Cilium-PR-Ginkgo-Tests-k8s
^^^^^^^^^^^^^^^^^^^^^^^^^^

Runs the Kubernetes e2e tests against all Kubernetes versions that are not
currently not tested as part of each pull-request, but which Cilium still
supports, as well as the most-recently-released versions of Kubernetes that
might not be declared stable by Kubernetes upstream. Check the contents of
``ginkgo-kubernetes-all.Jenkinsfile`` in the branch of Cilium for which you are
running tests to see which Kubernetes versions will be tested against.

Ginkgo-CI-Tests-Pipeline
^^^^^^^^^^^^^^^^^^^^^^^^

`Ginkgo-CI-Tests-Pipeline`_

.. _packer_ci:

Packer-CI-Build
^^^^^^^^^^^^^^^

As part of Cilium development, we use a custom base box with a bunch of
pre-installed libraries and tools that we need to enhance our daily workflow.
That base box is built with `Packer <https://www.packer.io/>`_ and it is hosted
in the `packer-ci-build`_ GitHub repository.

New versions of this box can be created via `Jenkins Packer Build`_, where
new builds of the image will be pushed to  `Vagrant Cloud
<https://app.vagrantup.com/cilium>`_ . The version of the image corresponds to
the `BUILD_ID <https://wiki.jenkins.io/display/JENKINS/Building+a+software+project#Buildingasoftwareproject-below>`_
environment variable in the Jenkins job. That version ID will be used in Cilium
`Vagrantfiles
<https://github.com/cilium/cilium/blob/main/test/Vagrantfile#L10>`_.

Changes to this image are made via contributions to the packer-ci-build
repository. Authorized GitHub users can trigger builds with a GitHub comment on
the PR containing the trigger phrase ``/build``. In case that a new box needs to
be rebased with a different branch than main, authorized developers can run
the build with custom parameters. To use a different Cilium branch in the `job`_
go to *Build with parameters* and a base branch can be set as the user needs.

This box will need to be updated when a new developer needs a new dependency
that is not installed in the current version of the box, or if a dependency that
is cached within the box becomes stale.

After the pull request to packer-ci-build is merged, builds for master boxes
have to be triggered `here <https://jenkins.cilium.io/view/Packer%20builds/>`_.

Make sure that you update vagrant box versions in `vagrant_box_defaults.rb
<https://github.com/cilium/cilium/blob/main/vagrant_box_defaults.rb>`__ after
new boxes are built and tested.

Once you change the image versions locally, create a branch named
``pr/update-packer-ci-build`` and open a PR ``github.com/cilium/cilium``.
It is important that you use that branch name so the VM images are cached into
packet.net before the branch is merged.

Once this PR is merged, ask `Cilium's CI team
<https://github.com/orgs/cilium/teams/vagrant>`_ to ensure:

1. The autoscaler provisioning code is up to date.

2. That all Jenkins nodes are scaled down and then back up.

.. _Jenkins Packer Build: Vagrant-Master-Boxes-Packer-Build_
.. _job: Vagrant-Master-Boxes-Packer-Build_

.. _test_matrix:

Testing matrix
^^^^^^^^^^^^^^

Up to date CI testing information regarding k8s - kernel version pairs can
always be found in the `Cilium CI matrix`_.

.. _Cilium CI matrix: https://docs.google.com/spreadsheets/d/1TThkqvVZxaqLR-Ela4ZrcJ0lrTJByCqrbdCjnI32_X0

.. _trigger_phrases:

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

Pipelines subject to triage
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Build/test failures for the following Jenkins pipelines must be reported as
GitHub issues using the process below:

+---------------------------------------+------------------------------------------------------------------+
| Pipeline                              | Description                                                      |
+=======================================+==================================================================+
| `Ginkgo-Tests-Validated-master`_      | Runs whenever a PR is merged into main                           |
+---------------------------------------+------------------------------------------------------------------+
| `Ginkgo-CI-Tests-Pipeline`_           | Runs every two hours on the main branch                          |
+---------------------------------------+------------------------------------------------------------------+
| `Vagrant-Master-Boxes-Packer-Build`_  | Runs on merge into `packer-ci-build`_ repository.                |
+---------------------------------------+------------------------------------------------------------------+
| :jenkins-branch:`Release-branch <>`   | Runs various Ginkgo tests on merge into branch "\ |SCM_BRANCH|"  |
+---------------------------------------+------------------------------------------------------------------+

.. _Ginkgo-Tests-Validated-master: https://jenkins.cilium.io/job/cilium-ginkgo/job/cilium/job/master/
.. _Ginkgo-CI-Tests-Pipeline: https://jenkins.cilium.io/job/Ginkgo-CI-Tests-Pipeline/
.. _Vagrant-Master-Boxes-Packer-Build: https://jenkins.cilium.io/job/Vagrant-Master-Boxes-Packer-Build/
.. _packer-ci-build: https://github.com/cilium/packer-ci-build/

Triage process
^^^^^^^^^^^^^^

#. Discover untriaged Jenkins failures via the jenkins-failures.sh script. It
   defaults to checking the previous 24 hours but this can be modified by
   setting the SINCE environment variable (it is a unix timestamp). The script
   checks the various test pipelines that need triage.

   .. code-block:: shell-session

       $ contrib/scripts/jenkins-failures.sh

   .. note::

     You can quickly assign SINCE with statements like ``SINCE=`date -d -3days```

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

   #. A link to the failing Jenkins build (note that the build information is
      eventually deleted).
   #. Attach the zipfile downloaded from Jenkins with logs from the failing
      tests. A zipfile for all tests is also available.

#. If no existing GitHub issue was found, file a `new GitHub issue <https://github.com/cilium/cilium/issues/new>`_:

   #. Attach zipfile downloaded from Jenkins with logs from failing test
   #. If the failure is a new regression or a real bug:

      #. Title: ``<Short bug description>``
      #. Labels ``kind/bug`` and ``needs/triage``.

   #. If failure is a new CI-Bug, Flake or if you are unsure:

      #. Title ``CI: <testname>: <cause>``, e.g. ``CI: K8sValidatedPolicyTest Namespaces: cannot curl service``
      #. Labels ``kind/bug/CI`` and ``needs/triage``
      #. Include a link to the failing Jenkins build (note that the build information is
         eventually deleted).
      #. Attach zipfile downloaded from Jenkins with logs from failing test
      #. Include the test name and whole Stacktrace section to help others find this issue.

   .. note::

      Be extra careful when you see a new flake on a PR, and want to open an
      issue. It's much more difficult to debug these without context around the
      PR and the changes it introduced. When creating an issue for a PR flake,
      include a description of the code change, the PR, or the diff. If it
      isn't related to the PR, then it should already happen in the ``main``
      branch, and a new issue isn't needed.

#. Edit the description of the Jenkins build to mark it as triaged. This will
   exclude it from future jenkins-failures.sh output.

   #. Login -> Click on build -> Edit Build Information
   #. Add the failure type and GH issue number. Use the table describing the
      failure categories, at the beginning of this section, to help
      categorize them.

   .. note::

      This step can only be performed with an account on Jenkins. If you are
      interested in CI failure reviews and do not have an account yet, ping us
      on Slack in the ``#testing`` channel.

**Examples:**

* ``Flake, quay.io is down``
* ``Flake, DNS not ready, #3333``
* ``CI-Bug, K8sValidatedPolicyTest: Namespaces, pod not ready, #9939``
* ``Regression, k8s host policy, #1111``

Bisect process
^^^^^^^^^^^^^^

If you are unable to triage the issue, you may try to use bisect job to find when things went awry in Jenkins.

#. Log in to Jenkins

#. Go to https://jenkins.cilium.io/job/bisect-cilium/configure .

#. Under ``Git Bisect`` build step fill in ``Good start revision`` and ``Bad end revision``.

#. Write description of what you are looking for under ``Search Identifier``.

#. Adjust ``Retry number`` and ``Min Successful Runs`` to account for current CI flakiness.

#. Save the configuration.

#. Click "Build Now" in https://jenkins.cilium.io/job/bisect-cilium/ .

#. This may take over a day depending on how many underlying builds will be created. The result will be in ``bisect-cilium`` console output, actual builds will be happening in https://jenkins.cilium.io/job/cilium-revision/ job.

Infrastructure details
~~~~~~~~~~~~~~~~~~~~~~

Logging into VM running tests
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. If you have access to credentials for Jenkins, log into the Jenkins slave running the test workload
2. Identify the vagrant box running the specific test

   .. code-block:: shell-session

       $ vagrant global-status
       id       name                          provider   state   directory
       -------------------------------------------------------------------------------------------------------------------------------------------------------------------------
       6e68c6c  k8s1-build-PR-1588-6          virtualbox running /root/jenkins/workspace/cilium_cilium_PR-1588-CWL743UTZEF6CPEZCNXQVSZVEW32FR3CMGKGY6667CU7X43AAZ4Q/tests/k8s
       ec5962a  cilium-master-build-PR-1588-6 virtualbox running /root/jenkins/workspace/cilium_cilium_PR-1588-CWL743UTZEF6CPEZCNXQVSZVEW32FR3CMGKGY6667CU7X43AAZ4Q
       bfaffaa  k8s2-build-PR-1588-6          virtualbox running /root/jenkins/workspace/cilium_cilium_PR-1588-CWL743UTZEF6CPEZCNXQVSZVEW32FR3CMGKGY6667CU7X43AAZ4Q/tests/k8s
       3fa346c  k8s1-build-PR-1588-7          virtualbox running /root/jenkins/workspace/cilium_cilium_PR-1588-CWL743UTZEF6CPEZCNXQVSZVEW32FR3CMGKGY6667CU7X43AAZ4Q@2/tests/k8s
       b7ded3c  cilium-master-build-PR-1588-7 virtualbox running /root/jenkins/workspace/cilium_cilium_PR-1588-CWL743UTZEF6CPEZCNXQVSZVEW32FR3CMGKGY6667CU7X43AAZ4Q@2

3. Log into the specific VM

.. code-block:: shell-session

    $ JOB_BASE_NAME=PR-1588 BUILD_NUMBER=6 vagrant ssh 6e68c6c


Jenkinsfiles Extensions
^^^^^^^^^^^^^^^^^^^^^^^

Cilium uses a custom `Jenkins helper library
<https://github.com/cilium/Jenkins-library>`_ to gather metadata from PRs and
simplify our Jenkinsfiles. The exported methods are:

- **ispr()**: return true if the current build is a PR.
- **setIfPr(string, string)**: return the first argument in case of a PR, if not
  a PR return the second one.
- **BuildIfLabel(String label, String Job)**: trigger a new Job if the PR has
  that specific Label.
- **Status(String status, String context)**: set pull request check status on
  the given context, example ``Status("SUCCESS", "$JOB_BASE_NAME")``



