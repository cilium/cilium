# RELEASE

Release process and checklist for `cilium-cli`.

This repository doesn't use release branches. All releases currently stem from
the master branch.

## Prepare the variables

These variables will be used in the commands throughout the document to allow
copy-pasting.

### Version

If releasing a new version 5.4.0 with the latest release being 5.3.8, for
example, they will look as follows:

    export MAJOR=5
    export MINOR=4
    export PATCH=0
    export LAST_RELEASE=5.3.8
    export NEXT_PATCH=$((PATCH+1))

## Create release prep branch

This branch will be used to prepare all the necessary things to get ready for
release.

    git checkout -b pr/v$MAJOR.$MINOR.$PATCH-prep

## Prepare the release notes

Using https://github.com/cilium/release, prepare the release notes between the
last minor version (latest patch) and current.

    ./release --repo cilium/cilium-cli --base v$LAST_RELEASE --head master
    **Other Changes:**
    * install: Add a hidden --base-version flag (#418, @michi-covalent)
    * Makefile: introduce GO_BUILD variable (#432, @tklauser)
    * Prepare for release v0.8.5 (#428, @michi-covalent)
    * Run "Post-test information gathering" step on cancellation (#426, @michi-covalent)
    * skip Succeeded pods (#431, @xyz-li)
    ... etc ...

## Update files for the new release

Update the version in `VERSION` and `stable.txt`, then commit the changes to
the prep branch:

    echo $MAJOR.$MINOR.$PATCH > VERSION
    echo v$MAJOR.$MINOR.$PATCH > stable.txt
    git add VERSION stable.txt
    git commit -s -m "Prepare for release v$MAJOR.$MINOR.$PATCH"

Consider that the Cilium repository uses the version specified in `stable.txt`
in the master branch for its CI workflows. In certain cases (e.g. for breaking
changes which require changes in the Cilium repo first), the version in
`stable.txt` might need to be updated in a separate PR.

## Update the `VERSION` file for next development cycle

Usually this only consists of bumping the patch version and adding the `-dev`
suffix, e.g.

    echo $MAJOR.$MINOR.${NEXT_PATCH}-dev > VERSION

Then commit the changes to the release prep branch:

    git add VERSION
    git commit -s -m "Prepare for v$MAJOR.$MINOR.$NEXT_PATCH development"

## Push the prep branch and open a Pull Request

The pull request has to be `pr/v$MAJOR.$MINOR.$PATCH-prep -> master`

Once the pull request is approved and merged, a tag can be created.

## Tag a release

Identify the right commit and tag the release. Usually, the commit modifying
the version in the `VERSION` file is tagged.

Example:

    git tag -a v0.8.5 -m 'v0.8.5 release' <commit-sha>

Then push the tag.

Example:

    git push origin v0.8.5

## Update the GitHub release notes

When a tag is pushed, a GitHub Action job takes care of creating a new GitHub
draft release, building artifacts and attaching them to the draft release.

The release notes need to be manually added before manually publishing the
release.
