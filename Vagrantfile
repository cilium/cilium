# -*- mode: ruby -*-
# vi: set ft=ruby :
Vagrant.configure(2) do |config|
  config.vm.box = "fedora23"
  config.vm.provision "shell", inline: <<-SHELL
    sudo dnf -y update
    curl -sSL https://experimental.docker.com/ | sh
    sudo usermod -aG docker vagrant
    sleep 3s
    sudo service docker enable
    sudo service docker start
    sleep 3s
  SHELL
end
