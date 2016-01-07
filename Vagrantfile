# -*- mode: ruby -*-
# vi: set ft=ruby :
Vagrant.configure(2) do |config|
  config.vm.box = "noironetworks/net-next"
  config.vm.synced_folder ".", "/home/vagrant/go/src/github.com/noironetworks/cilium-net", disabled: false

  config.vm.provision "shell", inline: <<-SHELL
    rm -rf /home/vagrant/go/src/github.com/docker/libnetwork
    mkdir -p /home/vagrant/go/src/github.com/docker
    cd /home/vagrant/go/src/github.com/docker
    git clone -b ipv6-citizen https://github.com/tgraf/libnetwork.git
    chown -R vagrant:vagrant /home/vagrant/go
  SHELL

  config.vm.provider :libvirt do |libvirt|
    libvirt.memory = 4096
  end

end
