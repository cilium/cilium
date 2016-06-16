# -*- mode: ruby -*-
# vi: set ft=ruby :

$bootstrap = <<SCRIPT
chown -R vagrant:vagrant /home/vagrant/go
mount bpffs /sys/fs/bpf/ -t bpf
sudo apt-get -y install socat curl

echo "export GOROOT=/usr/local/go" >> /home/vagrant/.profile
echo "export GOPATH=/home/vagrant/go" >> /home/vagrant/.profile
echo 'export PATH=/usr/local/go/bin:/home/vagrant/go/bin:/usr/local/clang+llvm-3.7.1-x86_64-linux-gnu-ubuntu-14.04/bin:$PATH' >>  /home/vagrant/.profile
echo 'export PATH=/usr/local/go/bin:/home/vagrant/go/bin:/usr/local/clang+llvm-3.7.1-x86_64-linux-gnu-ubuntu-14.04/bin:$PATH' >>  /root/.profile
SCRIPT

$build = <<SCRIPT
~/go/src/github.com/noironetworks/cilium-net/common/build.sh
SCRIPT

$install = <<SCRIPT
sudo -E make -C /home/vagrant/go/src/github.com/noironetworks/cilium-net/ install

sudo cp /home/vagrant/go/src/github.com/noironetworks/cilium-net/contrib/upstart/cilium-docker.conf /etc/init/
sudo cp /home/vagrant/go/src/github.com/noironetworks/cilium-net/contrib/upstart/cilium-net-daemon.conf /etc/init/
sudo cp /home/vagrant/go/src/github.com/noironetworks/cilium-net/contrib/upstart/cilium-socket-proxy.conf /etc/init/
sudo cp /home/vagrant/go/src/github.com/noironetworks/cilium-net/contrib/upstart/cilium-consul.conf /etc/init/
sudo cp /home/vagrant/go/src/github.com/noironetworks/cilium-net/contrib/upstart/cilium-policy-watcher.conf /etc/init/
sudo rm -rf /var/log/upstart/cilium-*
sudo service cilium-net-daemon restart
sleep 3s

sudo usermod -a -G cilium vagrant
SCRIPT

$testsuite = <<SCRIPT
make -C ~/go/src/github.com/noironetworks/cilium-net/ tests
sudo -E make -C ~/go/src/github.com/noironetworks/cilium-net/ runtime-tests
SCRIPT

$docker_libnetwork = <<SCRIPT
apt-get -y install libseccomp2
mkdir -p install
cd install
wget --quiet -r -np -nd http://www.infradead.org/~tgr/cilium-docker-build/
dpkg -r docker-engine
for pkg in *.deb; do
	dpkg -i $pkg
done
usermod -aG docker vagrant
echo 'DOCKER_OPTS="--storage-driver=overlay --iptables=false"' >> /etc/default/docker
cd ..
rm -rf $HOME/install
sudo service docker restart
SCRIPT

$install_k8s = <<SCRIPT
sudo apt-get -y install curl
curl -L  https://github.com/coreos/etcd/releases/download/v2.2.4/etcd-v2.2.4-linux-amd64.tar.gz -o etcd-v2.2.4-linux-amd64.tar.gz
tar xzvf etcd-v2.2.4-linux-amd64.tar.gz

export PATH=$PATH:/home/vagrant/etcd-v2.2.4-linux-amd64
echo 'export PATH=$PATH:/home/vagrant/etcd-v2.2.4-linux-amd64' >> $HOME/.profile

sudo chmod -R 775  /usr/local/go/pkg/
sudo chgrp vagrant /usr/local/go/pkg/

git clone -b v1.3.0-alpha.5 https://github.com/kubernetes/kubernetes.git
sudo chown -R vagrant.vagrant kubernetes
cd kubernetes
patch -p1 < /home/vagrant/go/src/github.com/noironetworks/cilium-net/examples/kubernetes/kubernetes-v1.3.0-alpha.5.patch

sudo apt-get -y install libncurses5-dev libslang2-dev gettext zlib1g-dev libselinux1-dev debhelper lsb-release pkg-config po-debconf autoconf automake autopoint libtool

cd $HOME
wget https://www.kernel.org/pub/linux/utils/util-linux/v2.24/util-linux-2.24.1.tar.gz
tar -xvzf util-linux-2.24.1.tar.gz
cd util-linux-2.24.1
./autogen.sh
./configure --without-python --disable-all-programs --enable-nsenter
make nsenter
sudo cp nsenter /usr/bin
SCRIPT

$route_node1 = <<SCRIPT
ip -6 addr add beef::11:11:11:11/64 dev eth2
ip -6 route add beef::c0a8:e60c:0/112 via beef::12:12:12:12
sleep 2s
ip -6 route add default via beef::1 || true
SCRIPT

$route_node2 = <<SCRIPT
ip -6 addr add beef::12:12:12:12/64 dev eth2
ip -6 route add beef::c0a8:e60b:0/112 via beef::11:11:11:11
sleep 2s
ip -6 route add default via beef::1 || true
echo 'exec cilium -D daemon -d eth2 -c "192.168.230.11:8500"' > /etc/init/cilium-net-daemon.conf
service cilium-net-daemon restart
sleep 3s
SCRIPT

$load_default_policy = <<SCRIPT
sudo cilium policy import /home/vagrant/go/src/github.com/noironetworks/cilium-net/examples/policy/default/
SCRIPT

Vagrant.configure(2) do |config|
    config.vm.box = "noironetworks/net-next"

    config.vm.provision "bootstrap", type: "shell", inline: $bootstrap
    config.vm.provision "build", type: "shell", run: "always", privileged: false, inline: $build
    config.vm.provision "install", type: "shell", run: "always", privileged: false, inline: $install
    config.vm.provision "testsuite", type: "shell", privileged: false, inline: $testsuite

    config.vm.provider :libvirt do |libvirt|
        libvirt.memory = 4096
        libvirt.cpus = 8
        config.vm.synced_folder ".", "/home/vagrant/go/src/github.com/noironetworks/cilium-net", disabled: false
    end

    config.vm.provider "virtualbox" do |vb|
        vb.memory = "4096"
        vb.cpus = 8

        config.vm.synced_folder '.', '/home/vagrant/go/src/github.com/noironetworks/cilium-net', type: "rsync"
        #config.vm.synced_folder '.', '/home/vagrant/go/src/github.com/noironetworks/cilium-net', type: "nfs"
        # Don't forget to enable this ports on your host before starting the VM
        # in order to have nfs working
        # iptables -I INPUT -p udp -s 192.168.33.0/24 --dport 111 -j ACCEPT
        # iptables -I INPUT -p udp -s 192.168.33.0/24 --dport 2049 -j ACCEPT
        # iptables -I INPUT -p udp -s 192.168.33.0/24 --dport 20048 -j ACCEPT
    end

    config.vm.define "node1", primary: true do |node1|
        node1.vm.network "private_network", ip: "192.168.33.11"
        node1.vm.network "private_network",
	  ip: "192.168.230.11",
	  :libvirt__network_name => "cilium-test",
	  :libvirt__guest_ipv6 => true,
	  :libvirt__dhcp_enabled => false
        node1.vm.hostname = "node1"
        config.vm.provision "route-node1", type: "shell", privileged: true, run: "always", inline: $route_node1
        config.vm.provision "load-policy", type: "shell", privileged: false, run: "always", inline: $load_default_policy
    end

    config.vm.define "node2", autostart: false do |node2|
        node2.vm.network "private_network", ip: "192.168.33.12"
        node2.vm.network "private_network",
	  ip: "192.168.230.12",
	  :libvirt__network_name => "cilium-test",
	  :libvirt__guest_ipv6 => true,
	  :libvirt__dhcp_enabled => false
        node2.vm.hostname = "node2"
        config.vm.provision "route-node2", type: "shell", privileged: true, run: "always", inline: $route_node2
        config.vm.provision "load-policy", type: "shell", privileged: false, run: "always", inline: $load_default_policy
    end

    config.vm.define "k8s1", autostart: false do |k8s1|
        k8s1.vm.network "private_network", ip: "192.168.33.21"
        k8s1.vm.network "private_network",
	  ip: "192.168.230.21",
	  :libvirt__network_name => "cilium-test",
	  :libvirt__guest_ipv6 => true,
	  :libvirt__dhcp_enabled => false
        k8s1.vm.hostname = "k8s1"
        config.vm.provision "install-k8s", type: "shell", privileged: false, run: "no", inline: $install_k8s
    end

    config.vm.define "k8s2", autostart: false do |k8s2|
        k8s2.vm.network "private_network", ip: "192.168.33.22"
        k8s2.vm.network "private_network",
	  ip: "192.168.230.22",
	  :libvirt__network_name => "cilium-test",
	  :libvirt__guest_ipv6 => true,
	  :libvirt__dhcp_enabled => false
        k8s2.vm.hostname = "k8s2"
        config.vm.provision "install-k8s", type: "shell", privileged: false, run: "no", inline: $install_k8s
    end

end
