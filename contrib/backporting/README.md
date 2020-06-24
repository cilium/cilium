Cilium Backporting Scripts
==========================

# check-stable - List commits that need backporting

`GITHUB_TOKEN=xxx check-stable X.Y`

The `check-stable` script scans for PRs which have been merged and marked with
the label `needs-backport/X.Y`. The script will list those PRs and all non-merge
commit ids that were part of the merge. There are three columns: first one is
the correlated sha of the commit from the master branch, second one is the sha
of the commit from the pull request, and third column is the commit subject.
The sha from the master branch is then needed for backporting into downstream
with the help of the `cherry-pick` script.

## Example

1. Generate a GitHub developer access token.
   You can do this directly from https://github.com/settings/tokens or
   by opening GitHub and then navigating to: User Profile -> Settings ->
   Developer Settings -> Personal access token -> Generate new token

   The access token requires access to the `public_repo` scope.

   If not already done, install `jq` on your system.

2. Run the script to generate the list of current backporting TODOs:

   `GITHUB_TOKEN=xxx `./check-stable 1.0`

   The list will be dumped to stdout.

# cherry-pick - Cherry-pick individual commits

`cherry-pick <commit-sha>`

After having run `check-stable`, the `cherry-pick` script takes an individual
commit sha as argument and adds the upstream commit into the downstream branch.
It will also add a note about the upstream commit id into the commit message
and the signed-off-by from the backporter.

## Example

1. Checkout one of the stable branches. Run `./check-stable` to get a TODO
   list of commits to backport.

2. Work through the list of commits dumped and pass a non-merge commit sha
   to `cherry-pick`:

   `./cherry-pick 479dd2d5a92a7035267bcdb91186c512ddd4379e`

3. Resolve conflicts whenever necessary, and continue with the next commit.

# set-labels.py - Set PR labels

`set-labels.py <PR number> <action> <backport version>`

The `set-labels.py` script is meant to keep the status of backporting changes
up-to-date. The script takes the PR number to update, the action to take which
can be "done" or "pending", and the backport version. This script needs the
`GITHUB_TOKEN` environment variable set. Please provide a developer access
token that has the `public_repo` scope as described in the steps above.

## Example invocation

The following invocation will set the "backport-done/1.7" label on the PRs
10505 and 10651.

```
for pr in 10505 10651; do contrib/backporting/set-labels.py $pr done 1.7; done
```
