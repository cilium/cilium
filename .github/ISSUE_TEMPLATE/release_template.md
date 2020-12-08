---
name: Release a new version of Cilium
about: Create a checklist for an upcoming release
title: 'vX.Y.Z release'
labels: kind/release
assignees: ''

---

## Pre-release

- [ ] Create a [new project] for the next release version
- [ ] Add build targets for the new release on [Docker Hub]
  - All versions:
    - [cilium](https://hub.docker.com/repository/docker/cilium/cilium/builds/edit)
    - [operator](https://hub.docker.com/repository/docker/cilium/operator/builds/edit)
    - [docker-plugin](https://hub.docker.com/repository/docker/cilium/docker-plugin/builds/edit)
  - Cilium v1.8 or later:
    - [operator-generic](https://hub.docker.com/repository/docker/cilium/operator-generic/builds/edit)
    - [operator-aws](https://hub.docker.com/repository/docker/cilium/operator-aws/builds/edit)
    - [operator-azure](https://hub.docker.com/repository/docker/cilium/operator-azure/builds/edit)
    - [hubble-relay](https://hub.docker.com/repository/docker/cilium/hubble-relay/builds/edit)
  - Cilium v1.9 or later:
    - [clustermesh-apiserver](https://hub.docker.com/repository/docker/cilium/clustermesh-apiserver/builds/edit)
- [ ] Check that there are no [release blockers] for the targeted release version
- [ ] Ensure that outstanding [backport PRs] are merged
- [ ] Consider building new [cilium-runtime images] and bumping the base image
      versions on this branch
- [ ] Move any unresolved issues/PRs from old release project into the newly
      created release project
- [ ] Push a PR including the changes necessary for the new release:
  - [ ] Pull latest branch
  - [ ] Run `contrib/release/start-release.sh'
  - [ ] (If applicable) Update the `cilium_version` and `cilium_tag` in
        `examples/getting-started/Vagrantfile`
  - [ ] Run `Documentation/check-crd-compat-table.sh vX.Y` and if needed, follow the
        instructions.
  - [ ] Commit all changes with title `Prepare for release vX.Y.Z`
  - [ ] Submit PR (`contrib/release/submit-release.sh`)
- [ ] Merge PR
- [ ] Create and push *both* tags to GitHub (`vX.Y.Z`, `X.Y.Z`)
  - Pull latest branch locally and run `contrib/release/tag-release.sh`
- [ ] Wait for docker builds to complete
  - [cilium](https://hub.docker.com/repository/docker/cilium/cilium/builds)
  - [operator](https://hub.docker.com/repository/docker/cilium/operator/builds)
  - [docker-plugin](https://hub.docker.com/repository/docker/cilium/docker-plugin/builds)
  - [operator-generic](https://hub.docker.com/repository/docker/cilium/operator-generic/builds)
  - [operator-aws](https://hub.docker.com/repository/docker/cilium/operator-aws/builds)
  - [operator-azure](https://hub.docker.com/repository/docker/cilium/operator-azure/builds)
  - [hubble-relay](https://hub.docker.com/repository/docker/cilium/hubble-relay/builds)
  - [clustermesh-apiserver](https://hub.docker.com/repository/docker/cilium/clustermesh-apiserver/builds)
  - Check if all docker images are available before announcing the release
    `make -C install/kubernetes/ check-docker-images`
- [ ] Create helm charts artifacts in [Cilium charts] repository using
      [cilium helm release tool] for both the `vX.Y.Z` release and `vX.Y` branch
      & push to repository
- [ ] Run sanity check of Helm install using connectivity-check script.
      Suggested approach: Follow the full [GKE getting started guide].
- [ ] Check draft release from [releases] page and publish the release
- [ ] Announce the release in #general on Slack (only [@]channel for vX.Y.0)
- [ ] Update Grafana dashboards (only for vX.Y.0)
  - Install the dashboards available in ``./examples/kubernetes/addons/prometheus``
    and use them to upload them to Grafana.com.

## Post-release

- [ ] Prepare post-release changes to master branch using `contrib/release/bump-readme.sh`
- [ ] Update the `stable` tags for each Cilium image (`contrib/release/bump-docker-stable.sh`)
- [ ] Update external tools and guides to point to the new Cilium version:
  - [ ] [kops]
  - [ ] [kubespray]


[release blockers]: https://github.com/cilium/cilium/labels/priority%2Frelease-blocker
[backport PRs]: https://github.com/cilium/cilium/pulls?utf8=%E2%9C%93&q=is%3Aopen+is%3Apr+backports
[new project]: https://github.com/cilium/cilium/projects/new
[Cilium release-notes tool]: https://github.com/cilium/release
[Docker Hub]: https://hub.docker.com/orgs/cilium/repositories
[Cilium charts]: https://github.com/cilium/charts
[releases]: https://github.com/cilium/cilium/releases
[Stable releases]: https://github.com/cilium/cilium#stable-releases
[kops]: https://github.com/kubernetes/kops/
[kubespray]: https://github.com/kubernetes-sigs/kubespray/
[cilium helm release tool]: https://github.com/cilium/charts/blob/master/prepare_artifacts.sh
[GKE getting started guide]: https://docs.cilium.io/en/stable/gettingstarted/k8s-install-gke/
[cilium-runtime images]: https://quay.io/repository/cilium/cilium-runtime
