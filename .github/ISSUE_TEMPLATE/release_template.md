---
name: Release a new version of Cilium
about: Create a checklist for an upcoming release
title: 'vX.Y.Z release'
labels: kind/release
assignees: ''

---

## Pre-release

- [ ] Check that there are no [release blockers] for the targeted release version
- [ ] Ensure that outstanding [backport PRs] are merged
- [ ] Consider building new [cilium-runtime images] and bumping the base image
      versions on this branch:
  - Cilium v1.10 or later:
     Modify the `FORCE_BUILD` environment value in the `images/runtime/Dockerfile` to force a rebuild.
     [Instructions](https://docs.cilium.io/en/latest/contributing/development/images/#update-cilium-builder-and-cilium-runtime-images)
  - Cilium v1.7 to v1.9:
     [Re-trigger a build in quay.io](https://docs.cilium.io/en/v1.9/contributing/development/images/#update-cilium-builder-and-cilium-runtime-images)
- [ ] Execute `release --current-version X.Y.Z --next-dev-version X.Y.W` to automatically
  move any unresolved issues/PRs from old release project into the new
  project. (`W` should be calculation of `Z+1`)
- [ ] Push a PR including the changes necessary for the new release:
  - [ ] Pull latest changes from the branch being released
  - [ ] Run `contrib/release/start-release.sh`
        **Note**: For `RCs` that are not in a stable branch, you need to follow
                  the RC release guide manually.
  - [ ] Run `Documentation/check-crd-compat-table.sh vX.Y` and if needed, follow the
        instructions.
  - [ ] Commit all changes with title `Prepare for release vX.Y.Z`
  - [ ] Submit PR (`contrib/release/submit-release.sh`)
  - [ ] For a new minor version:
    - [ ] Add the 'stable' tag as part of the GitHub workflow and remove the
          'stable' tag from the last stable branch.
    - [ ] Create the specific GH workflow that are only triggered via comment in
          the master branch for the stable version going to be released.
    - [ ] Remove all GH workflow that are only triggered via comment from the
          stable branch that is going to be released.
- [ ] Merge PR
- [ ] Create and push *both* tags to GitHub (`vX.Y.Z`, `X.Y.Z`)
  - Pull latest branch locally and run `contrib/release/tag-release.sh`
- [ ] Ask a maintainer to approve the build in the following links (keep the URL
      of the GitHub run to be used later):
  - [Cilium Image Release builds](https://github.com/cilium/cilium/actions?query=workflow:%22Image+Release+Build%22)
  - Check if all docker images are available before announcing the release
    `make -C install/kubernetes/ check-docker-images`
- [ ] Get the image digests from the build process and make a commit and PR with
      these digests.
  - [ ] Run `contrib/release/post-release.sh` to fetch the image
        digests and submit a PR to update these, use the URL of the GitHub run here.
  - [ ] Merge PR
- [ ] Update helm charts
  - [ ] Pull latest branch locally into the cilium repository.
  - [ ] Create helm charts artifacts in [Cilium charts] repository using
        [cilium helm release tool] for both the `vX.Y.Z` release and `vX.Y`
        branch and push these changes into the helm repository. Make sure the
        generated helm charts point to the commit that contains the image
        digests.
  - [ ] Check the output of the [chart workflow] and see if the test was
        successful.
- [ ] Check [read the docs] configuration:
    - [ ] For a RC, set a new build as active and hidden in [active versions].
    - [ ] For a new minor version set it as the [default version] and mark the
          EOL version as active and hidden and configure the new minor version
          as active and **not** hidden in [active versions].
    - [ ] For new minor version and RC update algolia configuration search in
          [docsearch-scraper-webhook].
- [ ] Check draft release from [releases] page
  - [ ] Update the text at the top with 2-3 highlights of the release
  - [ ] Copy the text from `digest-vX.Y.Z.txt` (previously generated with
        `contrib/release/post-release.sh`) to the end of the release.
  - [ ] Publish the release
- [ ] Announce the release in #general on Slack (only [@]channel for vX.Y.0)
- [ ] Update Grafana dashboards (only for vX.Y.0)
  - Install the dashboards available in ``./examples/kubernetes/addons/prometheus``
    and use them to upload them to Grafana.com.

## Post-release

- [ ] For new minor version update [security policy]
- [ ] Prepare post-release changes to master branch using `contrib/release/bump-readme.sh`
- [ ] Update external tools and guides to point to the new Cilium version:
  - [ ] [kops]
  - [ ] [kubespray]
  - [ ] [network policy]
  - [ ] [cluster administration networking]
  - [ ] [cluster administration addons]


[release blockers]: https://github.com/cilium/cilium/labels/release-blocker%2F1.X
[backport PRs]: https://github.com/cilium/cilium/pulls?utf8=%E2%9C%93&q=is%3Aopen+is%3Apr+backports
[Cilium release-notes tool]: https://github.com/cilium/release
[Docker Hub]: https://hub.docker.com/orgs/cilium/repositories
[Cilium charts]: https://github.com/cilium/charts
[releases]: https://github.com/cilium/cilium/releases
[Stable releases]: https://github.com/cilium/cilium#stable-releases
[kops]: https://github.com/kubernetes/kops/
[kubespray]: https://github.com/kubernetes-sigs/kubespray/
[cilium helm release tool]: https://github.com/cilium/charts/blob/master/prepare_artifacts.sh
[Quick Install]: https://docs.cilium.io/en/stable/gettingstarted/k8s-install-default.html
[cilium-runtime images]: https://quay.io/repository/cilium/cilium-runtime
[read the docs]: https://readthedocs.org/projects/cilium/
[active versions]: https://readthedocs.org/projects/cilium/versions/
[default version]: https://readthedocs.org/dashboard/cilium/advanced/
[docsearch-scraper-webhook]: https://github.com/cilium/docsearch-scraper-webhook
[security policy]: https://github.com/cilium/cilium/security/policy
[network policy]: https://kubernetes.io/docs/tasks/administer-cluster/network-policy-provider/cilium-network-policy/
[cluster administration networking]: https://kubernetes.io/docs/concepts/cluster-administration/networking/
[cluster administration addons]: https://kubernetes.io/docs/concepts/cluster-administration/addons/
[chart workflow]: https://github.com/cilium/charts/actions/workflows/conformance-gke.yaml
