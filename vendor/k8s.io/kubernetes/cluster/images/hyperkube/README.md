### hyperkube

`hyperkube` is an all-in-one binary for the Kubernetes server components
`hyperkube` is built for multiple architectures and _the image is pushed automatically on every release._

#### How to release by hand

```console
# First, build the binaries
$ build/run.sh make cross

# Build for linux/amd64 (default)
# export REGISTRY=$HOST/$ORG to switch from gcr.io/google_containers

$ make push VERSION={target_version} ARCH=amd64
# ---> gcr.io/google_containers/hyperkube-amd64:VERSION
# ---> gcr.io/google_containers/hyperkube:VERSION (image with backwards-compatible naming)

$ make push VERSION={target_version} ARCH=arm
# ---> gcr.io/google_containers/hyperkube-arm:VERSION

$ make push VERSION={target_version} ARCH=arm64
# ---> gcr.io/google_containers/hyperkube-arm64:VERSION

$ make push VERSION={target_version} ARCH=ppc64le
# ---> gcr.io/google_containers/hyperkube-ppc64le:VERSION

$ make push VERSION={target_version} ARCH=s390x
# ---> gcr.io/google_containers/hyperkube-s390x:VERSION
```

If you don't want to push the images, run `make` or `make build` instead


[![Analytics](https://kubernetes-site.appspot.com/UA-36037335-10/GitHub/cluster/images/hyperkube/README.md?pixel)]()
