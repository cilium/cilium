# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.require_version ">= 1.7.4"

if ARGV.first == "up" && ENV['CILIUM_SCRIPT'] != 'true'
    raise Vagrant::Errors::VagrantError.new, <<END
Calling 'vagrant up' directly is not supported.  Instead, please run the following:
  export NUM_NODES=n
  ./contrib/vagrant/start.sh
END
end

$bootstrap = <<SCRIPT
chown -R vagrant:vagrant /home/vagrant/go
sudo apt-get -y install socat curl jq realpath pv tmux
echo 'cd ~/go/src/github.com/cilium/cilium' >> /home/vagrant/.bashrc
SCRIPT

$build = <<SCRIPT
~/go/src/github.com/cilium/cilium/common/build.sh
SCRIPT

$install = <<SCRIPT
sudo -E make -C /home/vagrant/go/src/github.com/cilium/cilium/ install

sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/upstart/cilium-docker.conf /etc/init/
sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/upstart/cilium-net-daemon.conf /etc/init/
sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/upstart/cilium-socket-proxy.conf /etc/init/
sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/upstart/cilium-consul.conf /etc/init/
sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/upstart/cilium-policy-watcher.conf /etc/init/
sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/upstart/cilium-etcd.conf /etc/init/
sudo rm -rf /var/log/upstart/cilium-*

sudo usermod -a -G cilium vagrant
SCRIPT

$testsuite = <<SCRIPT
make -C ~/go/src/github.com/cilium/cilium/ tests
sudo -E env PATH="${PATH}" make -C ~/go/src/github.com/cilium/cilium/ runtime-tests
SCRIPT

$install_k8s = <<SCRIPT
sudo apt-get -y install curl
curl -L  https://github.com/coreos/etcd/releases/download/v2.2.4/etcd-v2.2.4-linux-amd64.tar.gz -o etcd-v2.2.4-linux-amd64.tar.gz
tar xzvf etcd-v2.2.4-linux-amd64.tar.gz

export PATH=$PATH:/home/vagrant/etcd-v2.2.4-linux-amd64
echo 'export PATH=$PATH:/home/vagrant/etcd-v2.2.4-linux-amd64' >> $HOME/.profile

sudo chmod -R 775  /usr/local/go/pkg/
sudo chgrp vagrant /usr/local/go/pkg/

git clone -b v1.4.0 https://github.com/kubernetes/kubernetes.git
sudo chown -R vagrant.vagrant kubernetes
cd kubernetes
patch -p1 < /home/vagrant/go/src/github.com/cilium/cilium/examples/kubernetes/kubernetes-v1.4.0.patch

go get -u github.com/jteeuwen/go-bindata/go-bindata

# Install loopback cni plugin
sudo mkdir -p /opt/cni/bin
cd /opt/cni/bin
sudo wget https://github.com/containernetworking/cni/releases/download/v0.3.0/cni-v0.3.0.tgz
sudo tar zxvf cni-v0.3.0.tgz
find . ! -name 'loopback' -type f -exec sudo rm -f {} +
sudo tee /etc/cni/net.d/99-loopback.conf <<EOF
{
    "type": "loopback"
}
EOF

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

$load_default_policy = <<SCRIPT
sudo cilium policy import /home/vagrant/go/src/github.com/cilium/cilium/examples/policy/default/
SCRIPT

$node_ip_base = ENV['NODE_IP_BASE'] || ""
$master_ip = $node_ip_base + "#{ENV['FIRST_IP_SUFFIX']}"
$num_node = (ENV['NUM_NODES'] || 0).to_i
$node_ips = $num_node.times.collect { |n| $node_ip_base + "#{n+(ENV['FIRST_IP_SUFFIX']).to_i+1}" }
$node_nfs_base_ip = ENV['NODE_NFS_IP_BASE']

if ENV['K8S'] then
    $k8stag="-k8s"
end

Vagrant.configure(2) do |config|
    config.vm.provision "bootstrap", type: "shell", inline: $bootstrap
    config.vm.provision "build", type: "shell", run: "always", privileged: false, inline: $build
    config.vm.provision "install", type: "shell", run: "always", privileged: false, inline: $install

    if ENV['RUN_TEST_SUITE'] then
        config.vm.provision "testsuite", type: "shell", privileged: false, inline: $testsuite
    end

    if ENV['K8S'] then
        config.vm.provision "install-k8s", type: "shell", privileged: false, run: "no", inline: $install_k8s
    end

    config.vm.provider :libvirt do |libvirt|
        config.vm.box = "noironetworks/net-next"
        libvirt.memory = ENV['VM_MEMORY']
        libvirt.cpus = ENV['VM_CPUS']
        config.vm.synced_folder ".", "/home/vagrant/go/src/github.com/cilium/cilium", disabled: false
    end

    config.vm.provider "virtualbox" do |vb|
        config.vm.box = "noironetworks/net-next"
        vb.memory = ENV['VM_MEMORY']
        vb.cpus = ENV['VM_CPUS']

        if ENV["NFS"] then
            config.vm.synced_folder '.', '/home/vagrant/go/src/github.com/cilium/cilium', type: "nfs"
            # Don't forget to enable this ports on your host before starting the VM
            # in order to have nfs working
            # iptables -I INPUT -p udp -s 192.168.34.0/24 --dport 111 -j ACCEPT
            # iptables -I INPUT -p udp -s 192.168.34.0/24 --dport 2049 -j ACCEPT
            # iptables -I INPUT -p udp -s 192.168.34.0/24 --dport 20048 -j ACCEPT
        else
            config.vm.synced_folder '.', '/home/vagrant/go/src/github.com/cilium/cilium', type: "rsync"
        end
    end

    master_vm_name = "cilium#{$k8stag}-master"

    config.vm.define master_vm_name, primary: true do |cm|
        cm.vm.network "private_network", ip: "#{$master_ip}",
            virtualbox__intnet: "cilium-test",
            :libvirt__network_name => "cilium-test",
            :libvirt__guest_ipv6 => true,
            :libvirt__dhcp_enabled => false
        if ENV["NFS"] then
            if ENV['FIRST_IP_SUFFIX'] then
                $nfs_addr = $node_nfs_base_ip + "#{ENV['FIRST_IP_SUFFIX']}"
            end
            cm.vm.network "private_network", ip: "#{$nfs_addr}"
        end
        cm.vm.hostname = "cilium-master"
        if ENV['CILIUM_TEMP'] then
            script = "#{ENV['CILIUM_TEMP']}/cilium-master.sh"
            cm.vm.provision "shell", privileged: true, run: "always", path: script
        end
        cm.vm.provision "load-policy", type: "shell", privileged: false, run: "always", inline: $load_default_policy
    end

    $num_node.times do |n|
        # n starts with 0
        node_vm_name =  "cilium#{$k8stag}-node-#{n+2}"
        node_hostname =  "cilium#{$k8stag}-node-#{n+2}"
        config.vm.define node_vm_name do |node|
            node_ip = $node_ips[n]
            if ENV['CILIUM_TEMP'] then
                script = "#{ENV['CILIUM_TEMP']}/node-start-#{n+2}.sh"
                node.vm.provision "shell", privileged: true, run: "always", path: script
            end
            node.vm.network "private_network", ip: "#{node_ip}",
                virtualbox__intnet: "cilium-test",
                :libvirt__network_name => "cilium-test",
                :libvirt__guest_ipv6 => true,
                :libvirt__dhcp_enabled => false
            if ENV["NFS"] then
                if ENV['FIRST_IP_SUFFIX'] then
                    $nfs_addr = $node_nfs_base_ip + "#{n+1+(ENV['FIRST_IP_SUFFIX']).to_i+1}"
                end
                node.vm.network "private_network", ip: "#{$nfs_addr}"
            end
        end
    end
end
