To update the development version of a helm chart, go to the branch
that you want to update in the cilium/cilium repo.

```
$ git checkout v1.8
```

Generate helm charts

```
$ echo "$(git branch --show-current | sed 's/v//')-dev" > VERSION && \
  make -C install/kubernetes
```

Run the `prepare_artifacts.sh` script from this repository.
