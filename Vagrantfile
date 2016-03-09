# -*- mode: ruby -*-
# vi: set ft=ruby :

$bootstrap = <<SCRIPT
chown -R vagrant:vagrant /home/vagrant/go
mount bpffs /sys/fs/bpf/ -t bpf
sudo apt-get -y install socat curl
SCRIPT

$build = <<SCRIPT
~/go/src/github.com/noironetworks/cilium-net/common/build.sh
SCRIPT

$install = <<SCRIPT
sudo -E make -C /home/vagrant/go/src/github.com/noironetworks/cilium-net/ install

sudo cp /home/vagrant/go/src/github.com/noironetworks/cilium-net/contrib/cilium-docker.conf /etc/init/
sudo cp /home/vagrant/go/src/github.com/noironetworks/cilium-net/contrib/cilium-net-daemon.conf /etc/init/
sudo cp /home/vagrant/go/src/github.com/noironetworks/cilium-net/contrib/cilium-socket-proxy.conf /etc/init/
sudo cp /home/vagrant/go/src/github.com/noironetworks/cilium-net/contrib/cilium-consul.conf /etc/init/
sudo service cilium-docker restart
sudo service cilium-net-daemon restart
sudo service cilium-socket-proxy restart
sudo service cilium-consul restart
SCRIPT

$testsuite = <<SCRIPT
make -C ~/go/src/github.com/noironetworks/cilium-net/ tests
sudo -E make -C ~/go/src/github.com/noironetworks/cilium-net/ runtime-tests
SCRIPT

Vagrant.configure(2) do |config|
    config.vm.box = "noironetworks/net-next"

    config.vm.provision "bootstrap", type: "shell", inline: $bootstrap
    config.vm.provision "build", type: "shell", run: "always", privileged: false, inline: $build
    config.vm.provision "install", type: "shell", run: "always", privileged: false, inline: $install
    config.vm.provision "testsuite", type: "shell", privileged: false, inline: $testsuite

    config.vm.provider :libvirt do |libvirt|
        libvirt.memory = 4096
        config.vm.synced_folder ".", "/home/vagrant/go/src/github.com/noironetworks/cilium-net", disabled: false
    end

    config.vm.provider "virtualbox" do |vb|
        vb.memory = "4096"
        vb.cpus = 8

        config.vm.synced_folder ".", "/vagrant", disabled: true
        config.vm.synced_folder '.', '/home/vagrant/go/src/github.com/noironetworks/cilium-net', nfs: true
        # Don't forget to enable this ports on your host before starting the VM
        # in order to have nfs working
        # iptables -I INPUT -p udp -s 192.168.33.0/24 --dport 111 -j ACCEPT
        # iptables -I INPUT -p udp -s 192.168.33.0/24 --dport 2049 -j ACCEPT
        # iptables -I INPUT -p udp -s 192.168.33.0/24 --dport 20048 -j ACCEPT
    end

    config.vm.define "node1", primary: true do |node1|
        node1.vm.network "private_network", ip: "192.168.33.11"
        node1.vm.hostname = "node1"
    end

    config.vm.define "node2", autostart: false do |node2|
        node2.vm.network "private_network", ip: "192.168.33.12"
        node2.vm.hostname = "node2"
    end

end
