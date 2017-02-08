# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.require_version ">= 1.7.4"

if ARGV.first == "up" && ENV['CILIUM_SCRIPT'] != 'true'
    raise Vagrant::Errors::VagrantError.new, <<END
Calling 'vagrant up' directly is not supported.  Instead, please run the following:
  export NWORKERS=n
  ./contrib/vagrant/start.sh
END
end

$bootstrap = <<SCRIPT
chown -R vagrant:vagrant /home/vagrant/go
sudo apt-get -y update || true
sudo apt-get -y install socat curl jq realpath pv tmux
echo 'cd ~/go/src/github.com/cilium/cilium' >> /home/vagrant/.bashrc
SCRIPT

$build = <<SCRIPT
~/go/src/github.com/cilium/cilium/common/build.sh
rm -fr ~/go/bin/cilium*
SCRIPT

$install = <<SCRIPT
sudo -E make -C /home/vagrant/go/src/github.com/cilium/cilium/ install

if [ -n "$(grep DISTRIB_RELEASE=14.04 /etc/lsb-release)" ]; then
    sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/upstart/cilium-docker.conf /etc/init/
    sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/upstart/cilium.conf /etc/init/
    sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/upstart/cilium-consul.conf /etc/init/
    sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/upstart/cilium-policy-watcher.conf /etc/init/
    sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/upstart/cilium-etcd.conf /etc/init/
    sudo rm -rf /var/log/upstart/cilium-*
else
    sudo mkdir -p /etc/sysconfig
    sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/systemd/cilium-consul.service /lib/systemd/system
    sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/systemd/cilium-docker.service /lib/systemd/system
    sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/systemd/cilium-etcd.service /lib/systemd/system
    sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/systemd/cilium.service /lib/systemd/system
    sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/systemd/cilium /etc/sysconfig
fi

sudo usermod -a -G cilium vagrant
SCRIPT

$testsuite = <<SCRIPT
make -C ~/go/src/github.com/cilium/cilium/ tests
sudo -E env PATH="${PATH}" make -C ~/go/src/github.com/cilium/cilium/ runtime-tests
SCRIPT

$install_k8s = <<SCRIPT
sudo apt-get -y install curl
cd $HOME
mkdir -p "$HOME/k8s"
cd "$HOME/k8s"

k8s_path="/home/vagrant/go/src/github.com/cilium/cilium/examples/kubernetes/scripts"

INSTALL=1 "${k8s_path}/02-certificate-authority.sh"
"${k8s_path}/03-2-run-inside-vms-etcd.sh"
"${k8s_path}/04-2-run-inside-vms-kubernetes-controller.sh"
"${k8s_path}/05-2-run-inside-vms-kubernetes-worker.sh"
INSTALL=1 "${k8s_path}/06-kubectl.sh"

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

$node_ip_base = ENV['IPV4_BASE_ADDR'] || ""
$node_nfs_base_ip = ENV['IPV4_BASE_ADDR_NFS'] || ""
$num_workers = (ENV['NWORKERS'] || 0).to_i
$workers_ipv4_addrs = $num_workers.times.collect { |n| $node_ip_base + "#{n+(ENV['FIRST_IP_SUFFIX']).to_i+1}" }
$workers_ipv4_addrs_nfs = $num_workers.times.collect { |n| $node_nfs_base_ip + "#{n+(ENV['FIRST_IP_SUFFIX_NFS']).to_i+1}" }
$master_ip = ENV['MASTER_IPV4']
$master_ipv6 = ENV['MASTER_IPV6_PUBLIC']
$workers_ipv6_addrs_str = ENV['IPV6_PUBLIC_WORKERS_ADDRS'] || ""
$workers_ipv6_addrs = $workers_ipv6_addrs_str.split(' ')

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
        libvirt.memory = ENV['VM_MEMORY'].to_i
        libvirt.cpus = ENV['VM_CPUS'].to_i
        config.vm.synced_folder ".", "/home/vagrant/go/src/github.com/cilium/cilium", disabled: false
    end

    config.vm.provider "virtualbox" do |vb|
        config.vm.box = "noironetworks/net-next"
        vb.memory = ENV['VM_MEMORY'].to_i
        vb.cpus = ENV['VM_CPUS'].to_i

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
            :libvirt__guest_ipv6 => "yes",
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
                :libvirt__guest_ipv6 => 'yes',
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
