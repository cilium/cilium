#!/bin/bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
cd "${dir}"

function build_dockerfile_dev {
   cat <<EOF > ./Dockerfile
FROM cilium/dependencies:`cat ../../../VERSION`
LABEL maintainer="andre@cilium.io"
# New packages can be added by appending ../cp-dirs
ADD . /tmp/cilium-net-build/src/github.com/cilium/cilium
RUN 
EOF

  # Remove trailing newline.
  printf %s "$(< Dockerfile)" > Dockerfile

  add_build_cilium_cmd
  add_cilium_run_cmd
}

function add_build_cilium_cmd {
  cat <<EOF >> ./Dockerfile
cd /tmp/cilium-net-build/src/github.com/cilium/cilium && \\
export GOROOT=/usr/local/go && \\
export GOPATH=/tmp/cilium-net-build && \\
export PATH="\$GOROOT/bin:/usr/local/clang+llvm/bin:\$GOPATH/bin:\$PATH" && \\
make clean-container build && \\
make PKG_BUILD=1 install && \\

# bash-completion-begin
mkdir -p /root && \\
echo ". /etc/profile.d/bash_completion.sh" >> /root/.bashrc && \\
cilium completion bash >> /root/.bashrc && \\
# bash-completion-end

groupadd -f cilium

EOF
}

function add_golang_install_cmd {
  cat <<EOF >> ./Dockerfile
cd /tmp && \\
curl -Sslk -o go.linux-amd64.tar.gz \\
https://storage.googleapis.com/golang/go1.9.linux-amd64.tar.gz && \\
tar -C /usr/local -xzf go.linux-amd64.tar.gz && \\
cd /tmp/cilium-net-build/src/github.com/cilium/cilium && \\
export GOROOT=/usr/local/go && \\
export GOPATH=/tmp/cilium-net-build && \\
export PATH="\$GOROOT/bin:/usr/local/clang+llvm/bin:\$GOPATH/bin:\$PATH" && \\
go get -u github.com/jteeuwen/go-bindata/... && go get -u github.com/google/gops && \\
mv /tmp/cilium-net-build/bin/gops /usr/local/bin/
EOF

}

function add_gopath_cmd {
  cat <<EOF >> ./Dockerfile
ENV GOROOT /usr/local/go
ENV GOPATH /tmp/cilium-net-build
ENV PATH "\$GOROOT/bin:/usr/local/clang+llvm/bin:\$GOPATH/bin:\$PATH"
EOF
}

function build_dockerfile_dependencies {
 cat <<EOF > ./Dockerfile
FROM ubuntu:16.04
LABEL maintainer="andre@cilium.io"
RUN mkdir -p /tmp/cilium-net-build/src/github.com/cilium/cilium
ADD ./contrib/packaging/docker/clang-3.8.1.key /tmp/cilium-net-build/src/github.com/cilium/cilium/contrib/packaging/docker/clang-3.8.1.key
EOF
  append_docker_install_deps
  add_golang_install_cmd
  add_gopath_cmd

}

function build_dockerfile_prod {
  cat <<EOF > ./Dockerfile
FROM ubuntu:16.04
LABEL maintainer="andre@cilium.io"
ADD . /tmp/cilium-net-build/src/github.com/cilium/cilium
EOF

  append_docker_install_deps
  add_golang_install_cmd
  printf %s "$(< Dockerfile)" > Dockerfile
  echo "$(cat ./Dockerfile) && \\" > Dockerfile
  add_build_cilium_cmd

  printf %s "$(< Dockerfile)" > Dockerfile
  local OUTPUT=' && \\'
  echo "$(cat ./Dockerfile) && \\" > Dockerfile
  cat <<EOF >> ./Dockerfile

apt-get purge --auto-remove -y gcc make bison flex git curl xz-utils ca-certificates && \\
apt-get clean && \\
rm -fr /root /var/lib/apt/lists/* /tmp/* /var/tmp/* /usr/local/go
EOF
  add_cilium_run_cmd
}

function add_cilium_run_cmd {
 cat <<EOF >> ./Dockerfile
ADD plugins/cilium-cni/cni-install.sh /cni-install.sh
ADD plugins/cilium-cni/cni-uninstall.sh /cni-uninstall.sh

ENV PATH="/usr/local/clang+llvm/bin:\$PATH"
ENV INITSYSTEM="SYSTEMD"

CMD ["/usr/bin/cilium"]
EOF


}

function append_docker_install_deps {
  cat <<EOF >> ./Dockerfile
RUN apt-get update && \\

apt-get install -y --no-install-recommends gcc make libelf-dev bison flex git ca-certificates libc6-dev.i386 iptables libgcc-5-dev binutils bash-completion && \\

# clang-3.8.1-begin
apt-get install -y --no-install-recommends curl xz-utils && \\
cd /tmp && \\
gpg --import /tmp/cilium-net-build/src/github.com/cilium/cilium/contrib/packaging/docker/clang-3.8.1.key && \\
curl -Ssl -o clang+llvm.tar.xz \\
http://releases.llvm.org/3.8.1/clang+llvm-3.8.1-x86_64-linux-gnu-ubuntu-16.04.tar.xz && \\
curl -Ssl -o clang+llvm.tar.xz.sig \\
http://releases.llvm.org/3.8.1/clang+llvm-3.8.1-x86_64-linux-gnu-ubuntu-16.04.tar.xz.sig && \\
gpg --verify clang+llvm.tar.xz.sig && \\
mkdir -p /usr/local && \\
tar -C /usr/local -xJf ./clang+llvm.tar.xz && \\
mv /usr/local/clang+llvm-3.8.1-x86_64-linux-gnu-ubuntu-16.04 /usr/local/clang+llvm && \\
rm clang+llvm.tar.xz && \\
rm -fr /usr/local/clang+llvm/include/llvm-c && \\
rm -fr /usr/local/clang+llvm/include/clang-c && \\
rm -fr /usr/local/clang+llvm/include/c++ && \\
rm -fr /usr/local/clang+llvm/share && \\
ls -d /usr/local/clang+llvm/lib/* | grep -vE clang$ | xargs rm -r && \\
ls -d /usr/local/clang+llvm/bin/* | grep -vE "clang$|clang-3.8$|llc$" | xargs rm -r && \\
# clang-3.8.1-end

# iproute2-begin
cd /tmp && \\
git clone -b v4.10.0 git://git.kernel.org/pub/scm/linux/kernel/git/shemminger/iproute2.git && \\
cd /tmp/iproute2 && \\
./configure && \\
make -j \`getconf _NPROCESSORS_ONLN\` && \\
make install && \\
# iproute2-end

# bpf-map-begin
curl -SsL https://github.com/cilium/bpf-map/releases/download/v1.0/bpf-map -o bpf-map && \\
chmod +x bpf-map && \\
mv bpf-map /usr/bin && \\
# bpf-map-end

# cni-begin
#Include the loopback binary in the image
mkdir -p tmp && cd tmp && \\
curl -sS -L https://storage.googleapis.com/kubernetes-release/network-plugins/cni-0799f5732f2a11b329d9e3d51b9c8f2e3759f2ff.tar.gz -o cni.tar.gz && \\
tar -xvf cni.tar.gz && \\
mkdir /cni && \\
cp bin/loopback /cni && \\
cd .. && \\
rm -r tmp && \\
# cni-end

EOF
}

eval $@
