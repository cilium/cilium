# RELEASE

Release process and checklist for `cilium-cli`.

This repository doesn't use release branches. All releases currently stem from
the master branch.

## Prepare the variables

These variables will be used in the commands throughout the document to allow
copy-pasting.

### Version

Set `RELEASE` environment variable to the new version. For example, if you are
releasing `v5.4.0`:

    export RELEASE=v5.4.0

### Commit SHA to release

    export COMMIT_SHA=<commit-sha-to-release>

## Tag a release

    git tag -a $RELEASE -m "$RELEASE release" $COMMIT_SHA && git push origin $RELEASE

## Update the GitHub release notes

When a tag is pushed, a GitHub Action job takes care of creating a new GitHub
draft release, building artifacts and attaching them to the draft release. Once
the draft is ready, use the "Auto-generate release notes" button to generate
the release notes from PR titles, review them and publish the release.

## Update the README.md

Update the *Releases* section of the `README.md` to point to the latest GitHub
release. This section lists all currently supported releases in a table. The
version in this table needs to be updated to match the new release.

## (OPTIONAL) Update stable.txt

The CLI installation instructions in the Cilium documentation use the version
specified in `stable.txt` in the `master` branch. Update `stable.txt` whenever
Cilium users should pick up this new release for installation.

To update `stable.txt`:

    git checkout -b pr/update-stable-to-$RELEASE
    echo $RELEASE > stable.txt
    git add stable.txt
    git commit -s -m "stable.txt: update to $RELEASE"

Then open a pull request against `master` branch.

## (OPTIONAL) Update the Homebrew formula

The `cilium-cli` Homebrew formula can be updated using the command:

    brew bump-formula-pr --version=${RELEASE#v} cilium-cli

This will automatically create a PR against https://github.com/Homebrew/homebrew-core
bumping the version. This assumes a GitHub access token exported in
`$HOMEBREW_GITHUB_API_TOKEN`, see `brew bump-formula-pr --help` for details.
