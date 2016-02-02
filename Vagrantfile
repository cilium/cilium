# -*- mode: ruby -*-
# vi: set ft=ruby :
Vagrant.configure(2) do |config|
  config.vm.box = "noironetworks/net-next"
  config.vm.synced_folder ".", "/home/vagrant/go/src/github.com/noironetworks/cilium-net", disabled: false

  config.vm.provision "shell", inline: <<-SHELL
    chown -R vagrant:vagrant /home/vagrant/go
    mount bpffs /sys/fs/bpf/ -t bpf

    # Temporary workaround until new image is built
    echo 'export GOROOT=/usr/local/go' >> /home/vagrant/.profile
    echo 'export GOPATH=/home/vagrant/go' >> /home/vagrant/.profile
    echo 'export PATH=/usr/local/go/bin:/home/vagrant/go/bin:/usr/local/clang+llvm-3.7.1-x86_64-linux-gnu-ubuntu-14.04/bin:$PATH' >> /home/vagrant/.profile

    su - vagrant -c /home/vagrant/go/src/github.com/noironetworks/cilium-net/common/build.sh

    make -C /home/vagrant/go/src/github.com/noironetworks/cilium-net/ install

    cp /home/vagrant/go/src/github.com/noironetworks/cilium-net/contrib/cilium-docker.conf /etc/init/
    cp /home/vagrant/go/src/github.com/noironetworks/cilium-net/contrib/cilium-net-daemon.conf /etc/init/
    service cilium-docker start
    service cilium-net-daemon start
  SHELL

  config.vm.provider :libvirt do |libvirt|
    libvirt.memory = 4096
  end

  config.vm.define "node1", primary: true  do |node1|
  end

  config.vm.define "node2", autostart: false do |node2|
  end

end
