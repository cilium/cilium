# Cilium + Kubernetes The Hard Way from Kelsey Hightower

We thought the best way on how we could provide a tutorial to deploy cilium on gce with
Kubernetes. Giving the fact that [Kelsey's tutorial](https://github.com/kelseyhightower/kubernetes-the-hard-way)
is super dope, we decided to modify it a little bit to accomudate cilium. Most of the
steps will be the same as that tutorial but we will highlight the different parts on each
section. (Spoiler alert: kube-proxy won't be used)

# TODO write some cilium internal bits and configurations need to make to run cilium everywhere

## Cluster Details

* Kubernetes v1.5.2 (Tested with v1.5.1)
* Docker 1.13.0 (Tested with 1.12.5)
* etcd v3.1.0 (cilium minimum requirement)
* [CNI Based Networking](https://github.com/containernetworking/cni)
* CNI Plugin: cilium (+ loopback)
* Network Policy Enforcer: cilium
* Secure communication between all components (etcd, control plane, workers)
* Default Service Account and Secrets

## Platforms

This tutorial assumes you have access to one of the following:

* [Google Cloud Platform](https://cloud.google.com) and the [Google Cloud SDK](https://cloud.google.com/sdk/) (125.0.0+)

## Labs

While GCP will be used for basic infrastructure needs, the things learned in this tutorial apply to every platform.

* [Cloud Infrastructure Provisioning](docs/01-infrastructure.md)
* [Setting up a CA and TLS Cert Generation](docs/02-certificate-authority.md)
* [Bootstrapping an H/A etcd cluster](docs/03-etcd.md)
* [Bootstrapping an H/A Kubernetes Control Plane](docs/04-kubernetes-controller.md)
* [Bootstrapping Kubernetes Workers](docs/05-kubernetes-worker.md)
* [Configuring the Kubernetes Client - Remote Access](docs/06-kubectl.md)
* [Managing the Container Network Routes](docs/07-network.md)
* [Setting up cilium daemon-set](docs/08-cilium.md)
* [Deploying the Cluster DNS Add-on](docs/09-dns-addon.md)
* [Smoke Test](docs/10-smoke-test.md)
* [Cleaning Up](docs/11-cleanup.md)
