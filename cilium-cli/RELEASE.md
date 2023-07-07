# cilium-cli Release Process

Release process and checklist for `cilium-cli`.

This repository currently uses release branches `v0.10` and `main`. All releases stem from
one of these branches. Refer to the [Release
table](https://github.com/cilium/cilium-cli#releases) for the most recent supported versions.

## Check issues and PRs

- Merge all [PRs marked as ready to
  merge](https://github.com/cilium/cilium-cli/labels/ready-to-merge)
- Make sure there are no [open issues or PRs labeled as release
  blocker](https://github.com/cilium/cilium-cli/labels/priority%2Frelease-blocker)
- Make sure there are no [Dependabot alerts](https://github.com/cilium/cilium-cli/security/dependabot)

## Prepare environment variables

Set `RELEASE` environment variable to the new version. This variable will be
used in the commands throughout the documenat to allow copy-pasting.

    export RELEASE=v0.15.2

## Prepare the release

### Update the README.md

Update the *Releases* section of the `README.md` which lists all currently
supported releases in a table. The version in this table needs to be updated to
match the new release `$RELEASE`. Also bump `$RELEASE` in the section above, so
it can be copy-pasted when preparing the next release.

### Create release preparation branch and open PR

    git checkout -b pr/prepare-$RELEASE
    git add README.md RELEASE.md
    git commit -s -m "Prepare for $RELEASE release"
    git push origin HEAD

Then open a pull request against `main` branch. Wait for the PR to be reviewed and merged.

## Tag a release

Update your local checkout:

    git checkout main
    git pull origin main

Set the commit you want to tag:

    export COMMIT_SHA=<commit-sha-to-release>

Usually this is the most recent commit on `main`, i.e.

    export COMMIT_SHA=$(git rev-parse origin/main)

Then tag and push the release:

    git tag -a $RELEASE -m "$RELEASE release" $COMMIT_SHA && git push origin $RELEASE

## Update the GitHub release notes

When a tag is pushed, a GitHub Action job takes care of creating a new GitHub
draft release, building artifacts and attaching them to the draft release. Once
the draft is ready, review the release notes and publish the release.

### Update stable.txt

The CLI installation instructions in the Cilium documentation use the version
specified in `stable.txt` in the `main` branch. Update `stable.txt` after the
release, whenever Cilium users should pick up this new release for
installation:

    echo $RELEASE > stable.txt
    git checkout -b pr/update-stable-$RELEASE
    git add stable.txt
    git commit -s -m "Update stable release to $RELEASE"
    git push origin HEAD

Then open a pull request against `main` branch.
