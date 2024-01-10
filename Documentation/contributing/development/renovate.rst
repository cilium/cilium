.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

Updating dependencies with Renovate
===================================

The Cilium project uses `Renovate Bot <https://github.com/renovatebot/renovate>`__
to maintain and update dependencies on a regular basis. This guide describes
how to contribute a PR which modifies the Renovate configuration. There are two
complementary methods for validating Renovate changes: Linting with the "local"
platform, and testing the updates in your own fork.

Linting locally
~~~~~~~~~~~~~~~

Use the ``renovate/renovate`` docker image to perform a dry run of Renovate.
This step should complete in less than ten minutes, and it will report syntax
errors in the configuration.

#. Make some changes to the Renovate configuration in ``.github/renovate.json5``.
#. Run the renovate image against the new configuration.

   .. code-block:: shell-session

      docker run -ti -e LOG_LEVEL=debug \
                 -e GITHUB_COM_TOKEN="$(gh auth token)" \
                 -v /tmp:/tmp \
                 -v $(pwd):/usr/src/app \
                 docker.io/renovate/renovate:full \
                 renovate --platform=local \
      | tee renovate.log

This approach is based on the `Local platform guide <https://docs.renovatebot.com/modules/platform/local/>`__
provided by Renovate. See that guide for more details about usage and
limitations.

Testing on a fork
~~~~~~~~~~~~~~~~~

For most changes to the Renovate configuration, you will likely need to test
the changes on your own fork of Cilium.

#. Make some changes to the Renovate configuration. Renovate is configured in
   ``.github/renovate.json5``.
#. (Optional) Disable unrelated configuration. For an example, see
   `this commit <https://github.com/joestringer/cilium/commit/4a80859a882c92973dd5b25f5c31de614abcf5de>`__.
#. Push the branch to the default branch of your own fork.
#. `Enable the Renovate GitHub app <https://github.com/apps/renovate>`__ in
   your GitHub account.
#. Ensure that Renovate is enabled in the repository settings in the
   `Renovate Dashboard <https://app.renovatebot.com/dashboard>`__.
#. Trigger the Renovate app from the dashboard or push a fresh commit to your
   fork's default branch to trigger Renovate again.
#. Use the dashboard to trigger Renovate to create a PR on your fork and
   validate that the proposed PRs are updating the correct parts of the codebase.

Once you have tested that the Renovate configuration works in your own fork,
create a PR against Cilium and provide links in the description to inform
reviewers about the testing you have performed on the changes.
