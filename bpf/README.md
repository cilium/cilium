# Run eBPF tests using Little VM Helper

## Prerequisites

* Install `qemu-utils`:

```sh
sudo apt-get install qemu-utils
```

## Build Little VM Helper CLI

* Checkout the LVH repo:

```sh
gh repo clone cilium/little-vm-helper
```

* Build CLI:

```sh
make little-vm-helper
```

## VM image selection and preparation

* You can find all avaliable image types here: https://quay.io/organization/lvh-images. In this tutorial we will continue with the `complexity-test` image.

* Pull the image:

```sh
./lvh images pull quay.io/lvh-images/complexity-test:bpf-net-main --dir /var/tmp/
```

* Resize image (optional):

```sh
qemu-img resize /var/tmp/images/complexity-test_bpf-net.qcow2 +16G
```

## VM preparation

* Run VM:

```sh
./lvh run --image /var/tmp/images/complexity-test_bpf-net.qcow2 \
          --host-mount <path-to-cilium-repo> \
          --cpu-kind=host \
          --cpu=2 \
          --mem=8G \
          -p 2222:22 \
          --console-log-file=/tmp/lvh-console.log
```

* SSH to VM:

```sh
ssh -p 2222 root@localhost

resize2fs /dev/vda
git config --global --add safe.directory /host
apt update && apt install -y -o Dpkg::Options::="--force-confold" xxd docker-buildx-plugin
```

## Run tests

* All tests

```sh
cd /host
make run_bpf_tests
```

* Specific test

```sh
cd /host
make run_bpf_tests BPF_TEST="xdp_nodeport_lb4_nat_lb"
```

* Verbose mode

```sh
cd /host
make run_bpf_tests BPF_TEST_VERBOSE=1
```

* Dump context

```sh
cd /host
make run_bpf_tests BPF_TEST_DUMP_CTX=1 BPF_TEST_VERBOSE=1
```
