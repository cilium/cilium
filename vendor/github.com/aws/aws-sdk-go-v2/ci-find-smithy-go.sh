#!/bin/bash

# looks for (and modreplaces if existing) a smithy-go branch matching the
# current branch name
#
# the loop will unfurl -*s off of the branch, e.g. sdk branch
# 'feat-foo-bar-baz' will match any of the following (in order):
#  - feat-foo-bar-baz
#  - feat-foo-bar
#  - feat-foo

if [ -z "$SMITHY_GO_REPOSITORY" ]; then
    SMITHY_GO_REPOSITORY=aws/smithy-go
fi

if [ -z "$RUNNER_TMPDIR" ]; then
    echo env RUNNER_TMPDIR is required
    exit 1
fi

branch=`git branch --show-current`
if [ "$branch" == main ]; then
    echo aws-sdk-go-v2 is on branch main, stop
    exit 0
fi

# For PR workflows, only the triggering ref is checked out, which in isolation
# is not recognized as a branch by git. Use the specific workflow env instead.
if [ -z "$branch" ]; then
    branch=$GITHUB_HEAD_REF
fi

if [ -n "$GIT_PAT" ]; then
    repository=https://$GIT_PAT@github.com/$SMITHY_GO_REPOSITORY
else
    repository=https://github.com/$SMITHY_GO_REPOSITORY
fi

echo on branch \"$branch\"
while [ -n "$branch" ] && [[ "$branch" == *-* ]]; do
    echo looking for $branch...
    git ls-remote --exit-code --heads $repository refs/heads/$branch
    if [ "$?" == 0 ]; then
        echo found $branch
        matched_branch=$branch
        break
    fi

    branch=${branch%-*}
done

if [ -z "$matched_branch" ]; then
    echo found no matching smithy-go branch, stop
    exit 0
fi

git clone -b $matched_branch $repository $RUNNER_TMPDIR/smithy-go
SMITHY_GO_SRC=$RUNNER_TMPDIR/smithy-go make gen-mod-replace-smithy-.
