#!/bin/bash
set -e
export GOPATH="/home/vagrant/go"

cd $GOPATH/src/github.com/cilium/cilium

if echo $(hostname) | grep "k8s" -q;
then
    if [[ "$(hostname)" == "k8s1" ]]; then

      echo "build_docker_image: building docker image"
      certs_dir="/home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/cluster/certs"
      cd /home/vagrant/go/src/github.com/cilium/cilium/

      docker run -d -p 5000:5000 --name registry registry
      make docker-image-dev
      docker tag cilium k8s1:5000/cilium/cilium-dev
      docker push k8s1:5000/cilium/cilium-dev
    else
        echo "No on master K8S node; no need to compile Cilium container"
    fi
else
    make
    make install
    mkdir -p /etc/sysconfig/
    cp -f contrib/systemd/cilium /etc/sysconfig/cilium
    for svc in $(ls -1 ./contrib/systemd/*.*); do
        cp -f "${svc}"  /etc/systemd/system/
        service=$(echo "$svc" | sed -E -n 's/.*\/(.*?).(service|mount)/\1.\2/p')
        echo "service $service"
        systemctl enable $service || echo "service $service failed"
        systemctl restart $service || echo "service $service failed to restart"
    done
fi
sudo adduser vagrant cilium
