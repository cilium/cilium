# -*- mode: ruby -*-
# vi: set ft=ruby :
Vagrant.configure(2) do |config|
  config.vm.box = "noironetworks/net-next"
  config.vm.synced_folder ".", "/home/vagrant/go/src/github.com/noironetworks/cilium-net", disabled: false

  config.vm.provision "shell", inline: <<-SHELL
    apt-get -y install vim
    apt-get -y install git
    wget --quiet https://storage.googleapis.com/golang/go1.5.2.linux-amd64.tar.gz
    mkdir -p /usr/local
    sudo tar -C /usr/local -xzf go1.5.2.linux-amd64.tar.gz
    rm go1.5.2.linux-amd64.tar.gz
    export GOROOT=/usr/local/go
    echo 'export GOROOT=/usr/local/go' >> /home/vagrant/.bashrc
    export PATH=$GOROOT/bin:$PATH
    echo 'export PATH=$GOROOT/bin:$PATH' >> /home/vagrant/.bashrc

    rm -rf /home/vagrant/go
    mkdir -p /home/vagrant/go/src
    echo 'export GOPATH=$HOME/go' >> /home/vagrant/.bashrc
    echo 'export PATH=$PATH:$HOME/go/bin' >> /home/vagrant/.bashrc
    export GOPATH=/home/vagrant/go
    export PATH=$PATH:/home/vagrant/go/bin
    go get github.com/tools/godep
    chown -R vagrant:vagrant /home/vagrant/go
  SHELL

  config.vm.provider :libvirt do |libvirt|
    libvirt.memory = 4096
  end

end
