# Run eBPF tests using Little VM Helper

## Build Little VM Helper CLI

* Checkout the LVH repo:

```sh
gh repo clone cilium/little-vm-helper
```

* Build CLI:

```sh
make little-vm-helper
```

## VM image preparation

* Pull `bpf-next` LVH image:

```sh
docker pull quay.io/lvh-images/kind:bpf-next-main
```

* Extract and resize image:

```sh
mkdir -p /tmp/lvh
docker run -v /tmp/lvh:/mnt/images quay.io/lvh-images/kind:bpf-next-main cp /data/images/kind_bpf-next.qcow2.zst /mnt/images/kind_bpf-next.qcow2.zst
zstd -d --rm -f /tmp/lvh/kind_bpf-next.qcow2.zst -o /var/tmp/kind_bpf-next.qcow2
qemu-img resize /var/tmp/kind_bpf-next.qcow2 +16G
```

## VM preparation

* Run VM:

```sh
./lvh run --image /var/tmp/kind_bpf-next.qcow2 --host-mount /path/to/cilium --cpu-kind=host --cpu=2 --mem=8G -p 2222:22 --console-log-file=/tmp/lvh-console.log
```

* SSH to VM:

```sh
ssh -p 2222 root@localhost

resize2fs /dev/vda
git config --global --add safe.directory /host
systemctl restart docker.service
/usr/local/go/bin/go install github.com/onsi/ginkgo/ginkgo@v1.16.5
/host/contrib/scripts/extract-llvm.sh /tmp/llvm
mv -vf /tmp/llvm/usr/local/bin/{clang,llc} /bin/
rm -rf /tmp/llvm/
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
