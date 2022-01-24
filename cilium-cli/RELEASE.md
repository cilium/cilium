# RELEASE

Release process and checklist for `cilium-cli`.

This repository doesn't use release branches. All releases currently stem from
the master branch.

## Prepare the variables

These variables will be used in the commands throughout the document to allow
copy-pasting.

### Version

If releasing a new version v5.4.0 with the latest release being v5.3.8, for
example, they will look as follows:

    export RELEASE=v5.4.0
    export LAST_RELEASE=v5.3.8

### Commit SHA to release

    export COMMIT_SHA=<commit-sha-to-release>

## Tag a release

    git tag -a $RELEASE -m "$RELEASE release" $COMMIT_SHA && git push origin $RELEASE

## Update the GitHub release notes

When a tag is pushed, a GitHub Action job takes care of creating a new GitHub
draft release, building artifacts and attaching them to the draft release. Once
the draft is ready, use the "Auto-generate release notes" button to generate
the release notes from PR titles, review them and publish the release.

## (OPTIONAL) Update the Homebrew formula

The `cilium-cli` Homebrew formula can be updated using the command:

    brew bump-formula-pr --version=${RELEASE#v} cilium-cli

This will automatically create a PR against https://github.com/Homebrew/homebrew-core
bumping the version. This assumes a GitHub access token exported in
`$HOMEBREW_GITHUB_API_TOKEN`, see `brew bump-formula-pr --help` for details.
