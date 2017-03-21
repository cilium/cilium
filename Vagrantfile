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
    $k8stag = ENV['K8STAG'] || "-k8s"
end

Vagrant.configure(2) do |config|
    config.vm.provision "bootstrap", type: "shell", inline: $bootstrap
    config.vm.provision "build", type: "shell", run: "always", privileged: false, inline: $build
    config.vm.provision "install", type: "shell", run: "always", privileged: false, inline: $install

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
        if ENV["NFS"] || ENV["IPV6_EXT"] then
            if ENV['FIRST_IP_SUFFIX_NFS'] then
                $nfs_ipv4_master_addr = $node_nfs_base_ip + "#{ENV['FIRST_IP_SUFFIX_NFS']}"
            end
            cm.vm.network "private_network", ip: "#{$nfs_ipv4_master_addr}", bridge: "enp0s9"
            # Add IPv6 address this way or we get hit by a virtualbox bug
            cm.vm.provision "ipv6-config",
                type: "shell",
                run: "always",
                inline: "ip -6 a a #{$master_ipv6}/16 dev enp0s9"
        end
        cm.vm.hostname = "cilium#{$k8stag}-master"
        if ENV['CILIUM_TEMP'] then
           if ENV["K8S"] then
               k8sinstall = "#{ENV['CILIUM_TEMP']}/cilium-k8s-install-1st-part.sh"
               cm.vm.provision "shell", privileged: true, path: k8sinstall
           end
           script = "#{ENV['CILIUM_TEMP']}/cilium-master.sh"
           cm.vm.provision "config-install", type: "shell", privileged: true, run: "always", path: script
           # In k8s mode cilium needs etcd in order to run which was started in
           # the first part of the script. The 2nd part will install the
           # policies into kubernetes and cilium.
           if ENV["K8S"] then
               k8sinstall = "#{ENV['CILIUM_TEMP']}/cilium-k8s-install-2nd-part.sh"
               cm.vm.provision "shell", privileged: true, path: k8sinstall
           end
        end
        if ENV['RUN_TEST_SUITE'] then
           cm.vm.provision "testsuite", run: "always", type: "shell", privileged: false, inline: $testsuite
        end
    end

    $num_workers.times do |n|
        # n starts with 0
        node_vm_name = "cilium#{$k8stag}-node-#{n+2}"
        node_hostname = "cilium#{$k8stag}-node-#{n+2}"
        config.vm.define node_vm_name do |node|
            node_ip = $workers_ipv4_addrs[n]
            node.vm.network "private_network", ip: "#{node_ip}",
                virtualbox__intnet: "cilium-test",
                :libvirt__guest_ipv6 => 'yes',
                :libvirt__dhcp_enabled => false
            if ENV["NFS"] || ENV["IPV6_EXT"] then
                nfs_ipv4_addr = $workers_ipv4_addrs_nfs[n]
                ipv6_addr = $workers_ipv6_addrs[n]
                node.vm.network "private_network", ip: "#{nfs_ipv4_addr}", bridge: "enp0s9"
                # Add IPv6 address this way or we get hit by a virtualbox bug
                node.vm.provision "ipv6-config",
                    type: "shell",
                    run: "always",
                    inline: "ip -6 a a #{ipv6_addr}/16 dev enp0s9"
            end
            node.vm.hostname = "cilium#{$k8stag}-node-#{n+2}"
            if ENV['CILIUM_TEMP'] then
                if ENV["K8S"] then
                    k8sinstall = "#{ENV['CILIUM_TEMP']}/cilium-k8s-install-1st-part.sh"
                    node.vm.provision "shell", privileged: true, path: k8sinstall
                end
                script = "#{ENV['CILIUM_TEMP']}/node-start-#{n+2}.sh"
                node.vm.provision "config-install", type: "shell", privileged: true, run: "always", path: script
                if ENV["K8S"] then
                    k8sinstall = "#{ENV['CILIUM_TEMP']}/cilium-k8s-install-2nd-part.sh"
                    node.vm.provision "shell", privileged: true, path: k8sinstall
                end
            end
        end
    end
end
