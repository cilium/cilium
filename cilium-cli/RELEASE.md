# cilium-cli Release Process

Release process and checklist for `cilium-cli`.

This repository currently uses release branches `v0.10` and `master`. All releases stem from
the on of these branches. Refer to the [Release
table](https://github.com/cilium/cilium-cli#releases) for the most recent supported versions.

## Prepare environment variables

Set `RELEASE` environment variable to the new version. This variable will be
used in the commands throughout the documenat to allow copy-pasting.

For example, if you are releasing `v5.4.0`:

    export RELEASE=v5.4.0

## Prepare the release

### Update the README.md

Update the *Releases* section of the `README.md` which lists all currently
supported releases in a table. The version in this table needs to be updated to
match the new release `$RELEASE`.

### (Optional) Update stable.txt

The CLI installation instructions in the Cilium documentation use the version
specified in `stable.txt` in the `master` branch. Update `stable.txt` whenever
Cilium users should pick up this new release for installation:

    echo $RELEASE > stable.txt

### Create release preparation branch and open PR

    git checkout -b pr/prepare-$RELEASE
    git add README.md stable.txt
    git commit -s -m "Prepare for $RELEASE release"

Then open a pull request against `master` branch. Wait for the PR to be reviewed and merged.

## Tag a release

Update your local checkout:

    git checkout master
    git pull origin master

Set the commit you want to tag:

    export COMMIT_SHA=<commit-sha-to-release>

Usually this is the most recent commit on `master`, i.e.

    export COMMIT_SHA=$(git rev-parse origin/master)

Then tag and push the release:

    git tag -a $RELEASE -m "$RELEASE release" $COMMIT_SHA && git push origin $RELEASE

## Update the GitHub release notes

When a tag is pushed, a GitHub Action job takes care of creating a new GitHub
draft release, building artifacts and attaching them to the draft release. Once
the draft is ready, use the "Auto-generate release notes" button to generate
the release notes from PR titles, review them and publish the release.
