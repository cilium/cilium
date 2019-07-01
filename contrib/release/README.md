Cilium Release Scripts
======================

## relnotes - Release Notes generation

`GITHUB_TOKEN=xxx relnotes <git revision range>`

The `relnotes` script is derived from Kubernetes and scans for PRs which have
been merged in the specified git revision range and extracts all PRs which have
one of the following labels set:

* release-note/major
* release-note/minor
* release-note/bug

Every PR with one of the above mentioned labels set will be included in the
release notes. The release notes will be sorted according to category defined
by label.

See [Write Release Notes if Needed][1] for details on how to format the body of
a PR to specify the release note text.

### System dependencies

* `lsb_release` tool (Fedora package: `redhat-lsb`)

### Example

1. Generate a GitHub developer access token. (User Profile -> Settings ->
   Developer Settings -> Personal access token -> Generate new token)

   The access token requires access to `public_repo`.

2. Run the script to generate the NEWS.rst file:

   `Usage: relnotes [OPTIONS] RELEASE-TAG RANGE`

   `GITHUB_TOKEN=xxx ./relnotes --markdown-file=NEWS.rst v1.0.0-rc4 v1.0.0-rc3..`

   In case the generated `NEWS.rst` file is not as expected, you can run
   `relnotes` with the `--verbose` flag to see individual decision taken for
   each PR.

## uploadrev

The `uploadrev` script takes a git revision as the only argument and uploads
all relevant files to releases.cilium.io. For the script to work AWS
credentials are required.  Please see the [AWS CLI documentation][2] for
configuration.

The below commands should work when run from a Cilium tree. Note that the
script will stash away any uncommitted staged changes and attempts to checkout
the revision. The files uploaded to the AWS bucket are in \_build/<revision>.

This includes the source code in zip and tar.gz format, binaries for Cilium
CLI, agent, health, bugtool, monitor and seperate sha256 files. Using
`v1.0.0-rc2` the following files would be uploaded:

	cilium-agent-x86_64
	cilium-agent-x86_64.sha256sum
	cilium-bugtool-x86_64
	cilium-bugtool-x86_64.sha256sum
	cilium-health-x86_64
	cilium-health-x86_64.sha256sum
	cilium-health-responder-x86_64
	cilium-health-responder-x86_64.sha256sum
	cilium-node-monitor-x86_64
	cilium-node-monitor-x86_64.sha256sum
	cilium-x86_64
	cilium-x86_64.sha256sum
	v1.0.0-rc2.tar.gz
	v1.0.0-rc2.tar.gz.sha256sum
	v1.0.0-rc2.zip
	v1.0.0-rc2.zip.sha256sum

If no arguments are supplied the usage is printed

```
$ ./contrib/release/uploadrev
Usage: ./contrib/release/uploadrev <tag>
Example: ./contrib/release/uploadrev v1.0.0-rc2
Environment:
  ARCH=${ARCH:-"`uname -m`"}
  DOMAIN=${DOMAIN:-"releases.cilium.io"}
  REMOTE_DIR=${REMOTE_DIR:-"$VER"}
  PREPEND=${PREPEND:-"cilium-$VER/"}
  ZIP_FILE=${ZIP_FILE:-"$VER.zip"}
  TARBALL=${TARBALL:-"$VER.tar.gz"}
  DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
  TARGET_DIR=${TARGET_DIR:-"$DIR/../../_build/`basename $REMOTE_DIR`"}
  CILIUM_SOURCE=${CILIUM_SOURCE:-"$DIR/../../"}
  SKIP_UPLOAD=${SKIP_UPLOAD:-0}
```

### Uploading


Uploading a tag

	$ ./contrib/release/uploadrev v1.0.0-rc2

Uploading a branch

	$ ./contrib/release/uploadrev master

### Staging

If you'd like todo a test upload to a private bucket before releasing, the
`DOMAIN` variable can be overriden.

	$ DOMAIN=releases.example.io ./uploadrev v1.0.0-rc2

[1]: https://github.com/kubernetes/community/blob/master/contributors/devel/pull-requests.md#write-release-notes-if-needed
[2]: https://docs.aws.amazon.com/cli/latest/userguide/installing.html
