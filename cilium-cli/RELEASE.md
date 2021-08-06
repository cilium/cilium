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

    git tag -a $RELEASE -m '$RELEASE release' $COMMIT_SHA && git push origin $RELEASE

## Prepare the release notes

Using https://github.com/cilium/release, prepare the release notes between the
last minor version (latest patch) and current.

    ./release --repo cilium/cilium-cli --base $LAST_RELEASE --head $COMMIT_SHA
    **Other Changes:**
    * install: Add a hidden --base-version flag (#418, @michi-covalent)
    * Makefile: introduce GO_BUILD variable (#432, @tklauser)
    * Prepare for release v0.8.5 (#428, @michi-covalent)
    * Run "Post-test information gathering" step on cancellation (#426, @michi-covalent)
    * skip Succeeded pods (#431, @xyz-li)
    ... etc ...

## Update the GitHub release notes

When a tag is pushed, a GitHub Action job takes care of creating a new GitHub
draft release, building artifacts and attaching them to the draft release. Once
the draft is ready, copy & paste the generated release notes manually and publish
the release.

## Update stable.txt

The Cilium repository uses the version specified in `stable.txt` in the master branch
for its CI workflows. Update `stable.txt` when Cilium needs to pick up this new release
for its CI workflows:

    git checkout -b pr/update-stable-to-$RELEASE
    echo $RELEASE > stable.txt
    git add stable.txt
    git commit -s -m "Update the stable version to $RELEASE"

Then open a pull request against `master` branch.
