# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.require_version ">= 1.8.3"

if ARGV.first == "up" && ENV['CILIUM_SCRIPT'] != 'true'
    raise Vagrant::Errors::VagrantError.new, <<END
Calling 'vagrant up' directly is not supported.  Instead, please run the following:
  export NWORKERS=n
  ./contrib/vagrant/start.sh
END
end

if ENV['IPV4'] == '0'
    raise Vagrant::Errors::VagrantError.new, <<END
Disabling IPv4 is currently not allowed until k8s 1.9 is released
END
end

$bootstrap = <<SCRIPT
echo "bootstrap: starting"
echo "bootstrap: restarting Docker"
sudo service docker restart
echo 'cd ~/go/src/github.com/cilium/cilium' >> /home/vagrant/.bashrc
echo "bootstrap: setting GOPATH"
export GOPATH=/home/vagrant/go
echo "bootstrap: installing go-bindata"
sudo -E /usr/local/go/bin/go get github.com/jteeuwen/go-bindata/...
echo "bootstrap: installing gops"
sudo -E /usr/local/go/bin/go get -u github.com/google/gops
echo "bootstrap: setting vagrant:vagrant as owner of $GOPATH"
chown -R vagrant:vagrant $GOPATH
echo "bootstrap: downloading bpf-map tool"
curl -SsL https://github.com/cilium/bpf-map/releases/download/v1.0/bpf-map -o bpf-map
chmod +x bpf-map
mv bpf-map /usr/bin
echo "bootstrap: complete"
#TODO is this necessary from Eloy's work? /tmp/provision/compile.sh
SCRIPT

$build = <<SCRIPT
echo "build: building Cilium"
~/go/src/github.com/cilium/cilium/common/build.sh
rm -fr ~/go/bin/cilium*
echo "build: done building Cilium"
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
make -C ~/go/src/github.com/cilium/cilium/ tests || exit 1
sudo -E env PATH="${PATH}" make -C ~/go/src/github.com/cilium/cilium/ runtime-tests
SCRIPT

$build_docker_image = <<SCRIPT
echo "build_docker_image: building docker image"
certs_dir="/home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/cluster/certs"
cd /home/vagrant/go/src/github.com/cilium/cilium/
docker run -d -p 5000:5000 --name registry -v ${certs_dir}:/certs \
        -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/kubernetes.pem \
        -e REGISTRY_HTTP_TLS_KEY=/certs/kubernetes-key.pem \
        registry:2
make docker-image-dev
docker tag cilium:${DOCKER_IMAGE_TAG} localhost:5000/cilium:${DOCKER_IMAGE_TAG}
docker push localhost:5000/cilium:${DOCKER_IMAGE_TAG}
SCRIPT

$load_docker_image = <<SCRIPT
certs_dir="/home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/cluster/certs"
sudo mkdir -p /etc/docker/certs.d/192.168.36.11:5000
sudo cp ${certs_dir}/ca.pem /etc/docker/certs.d/192.168.36.11:5000/ca.crt
docker pull 192.168.36.11:5000/cilium:${DOCKER_IMAGE_TAG}
docker tag 192.168.36.11:5000/cilium:${DOCKER_IMAGE_TAG} cilium:${DOCKER_IMAGE_TAG}
SCRIPT

$k8s_install = <<SCRIPT
/home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/cluster/cluster-manager.bash fresh_install
SCRIPT

$cilium_master = <<SCRIPT
ip -6 a a FD01::B/16 dev enp0s8
echo 'FD01::B k8s-1' >> /etc/hosts
echo "FD01::C k8s-2" >> /etc/hosts
SCRIPT

$cilium_slave = <<SCRIPT
ip -6 a a FD01::C/16 dev enp0s8
echo 'FD01::C k8s-1' >> /etc/hosts
echo "FD01::B k8s-2" >> /etc/hosts
SCRIPT

# allow setting up k8s_version remotely when executing the runtime tests via ssh
$install_sshd_env = <<SCRIPT
echo "AcceptEnv k8s_version" >> /etc/ssh/sshd_config
# Load options
sudo service sshd restart
SCRIPT

# We need this workaround since kube-proxy is not aware of multiple network
# interfaces. If we send a packet to a service IP that packet is sent
# to the default route, because the service IP is unknown by the linux routing
# table, with the source IP of the interface in the default routing table, even
# though the service IP should be routed to a different interface.
# This particular workaround is only needed for cilium, running on a pod on host
# network namespace, to reach out kube-api-server.
$kube_proxy_workaround = <<SCRIPT
sudo iptables -t nat -A POSTROUTING -o enp0s8 ! -s 192.168.36.12 -j MASQUERADE
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
$docker_image_tag=ENV['DOCKER_IMAGE_TAG'] || "local_build"


####################################################
# Use environment variables for VM / VBoxNet names #
####################################################

# Create unique ID for use in vboxnet name so Jenkins pipeline can have concurrent builds.
$job_name = ENV['JOB_BASE_NAME'] || "local"
$build_number = ENV['BUILD_NUMBER'] || "0"
$build_id = "#{$job_name}-#{$build_number}"
# Only create the build_id_name for Jenkins environment so that
# we can run VMs locally without having any the `build_id` in the name.
if ENV['BUILD_NUMBER'] then
    $build_id_name = "-build-#{$build_id}"
end

if ENV['K8S'] then
    $k8stag = ENV['K8STAG'] || "-k8s"
end

$K8S_VERSION = ENV['K8S_VERSION'] || "1.7"

#puts "cilium#{$k8stag}-master#{$build_id_name}"
#(1..2).each do |i|
    #puts "k8s#{i}#{$build_id_name}-#{$K8S_VERSION}"
#end

Vagrant.configure(2) do |config|
    config.vm.box = "combined/test2"
    ###############################
    # Dev / Runtime test VM Setup #
    ###############################
    master_vm_name = "cilium#{$k8stag}-master#{$build_id_name}"
    config.vm.define "runtime", primary: true do |cm|        


        ###################################
        #  libvirt specific configuration #
        ###################################
        cm.vm.provider :libvirt do |libvirt|
            libvirt.memory = ENV['VM_MEMORY'].to_i
            libvirt.cpus = ENV['VM_CPUS'].to_i
            config.vm.synced_folder ".", "/home/vagrant/go/src/github.com/cilium/cilium", disabled: false
        end

        #####################################
        # VirtualBox specific configuration #
        #####################################
        cm.vm.provider "virtualbox" do |vb|
            # Do not inherit DNS server from host, use proxy
            vb.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
            vb.customize ["modifyvm", :id, "--natdnsproxy1", "on"]

            vb.memory = ENV['VM_MEMORY'].to_i
            vb.cpus = ENV['VM_CPUS'].to_i

            if ENV["NFS"] then
                cm.vm.synced_folder '.', '/home/vagrant/go/src/github.com/cilium/cilium', type: "nfs"
                # To get NFS working, run the following commands on your host before starting the VM
                # iptables -I INPUT -p udp -s 192.168.34.0/24 --dport 111 -j ACCEPT
                # iptables -I INPUT -p udp -s 192.168.34.0/24 --dport 2049 -j ACCEPT
                # iptables -I INPUT -p udp -s 192.168.34.0/24 --dport 20048 -j ACCEPT
            else
                # Ignore contrib/packaging/docker/stage to prevent concurrent
                # problems when using rsync on multiple VMs. Also ignore src directory
                # when running Ginkgo tests.
                cm.vm.synced_folder '.', '/home/vagrant/go/src/github.com/cilium/cilium', type: "rsync",
                rsync__exclude: ["contrib/packaging/docker/stage", "src"]
            end
        end

        # Provisioning scripts for Cilium.
        cm.vm.provision "bootstrap", type: "shell", inline: $bootstrap
        cm.vm.provision "build", type: "shell", run: "always", privileged: false, inline: $build
        cm.vm.provision "install", type: "shell", run: "always", privileged: false, inline: $install

        # Networking configuration
        node_ip = "#{$master_ip}"
        cm.vm.network "private_network", ip: "#{$master_ip}",
            virtualbox__intnet: "cilium-test-#{$build_id}",
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
            node_ip = "#{$nfs_ipv4_master_addr}"
            if ENV["IPV6_EXT"] then
                node_ip = "#{$master_ipv6}"
            end
        end
        cm.vm.hostname = "cilium#{$k8stag}-master"
        if ENV['CILIUM_TEMP'] then
           if ENV["K8S"] then
               k8sinstall = "#{ENV['CILIUM_TEMP']}/cilium-k8s-install-1st-part.sh"
               cm.vm.provision "k8s-install-master-part-1",
                   type: "shell",
                   run: "always",
                   env: {"node_ip" => node_ip},
                   privileged: true,
                   path: k8sinstall
           end
           script = "#{ENV['CILIUM_TEMP']}/cilium-master.sh"
           cm.vm.provision "config-install", type: "shell", privileged: true, run: "always", path: script
           # In k8s mode cilium needs etcd in order to run which was started in
           # the first part of the script. The 2nd part will install the
           # policies into kubernetes and cilium.
           if ENV["K8S"] then
               k8sinstall = "#{ENV['CILIUM_TEMP']}/cilium-k8s-install-2nd-part.sh"
               cm.vm.provision "k8s-install-master-part-2",
                   type: "shell",
                   run: "always",
                   env: {"node_ip" => node_ip},
                   privileged: true,
                   path: k8sinstall
           end
        end
        #if ENV['RUN_TEST_SUITE'] then
        #   cm.vm.provision "testsuite", run: "always", type: "shell", privileged: false, inline: $testsuite
        #end
    end

    #####################################
    # Create worker nodes if specified  #
    #####################################
    $num_workers.times do |n|
        # n starts with 0
        node_vm_name = "cilium#{$k8stag}-node-#{n+2}"
        node_hostname = "cilium#{$k8stag}-node-#{n+2}"
        config.vm.define node_vm_name do |node|
            node_ip = $workers_ipv4_addrs[n]
            node.vm.network "private_network", ip: "#{node_ip}",
                virtualbox__intnet: "cilium-test-#{$build_id}",
                :libvirt__guest_ipv6 => 'yes',
                :libvirt__dhcp_enabled => false
            if ENV["NFS"] || ENV["IPV6_EXT"] then
                nfs_ipv4_addr = $workers_ipv4_addrs_nfs[n]
                node_ip = "#{nfs_ipv4_addr}"
                ipv6_addr = $workers_ipv6_addrs[n]
                node.vm.network "private_network", ip: "#{nfs_ipv4_addr}", bridge: "enp0s9"
                # Add IPv6 address this way or we get hit by a virtualbox bug
                node.vm.provision "ipv6-config",
                    type: "shell",
                    run: "always",
                    inline: "ip -6 a a #{ipv6_addr}/16 dev enp0s9"
                if ENV["IPV6_EXT"] then
                    node_ip = "#{ipv6_addr}"
                end
            end
            node.vm.hostname = "cilium#{$k8stag}-node-#{n+2}"
            if ENV['CILIUM_TEMP'] then
                if ENV["K8S"] then
                    k8sinstall = "#{ENV['CILIUM_TEMP']}/cilium-k8s-install-1st-part.sh"
                    node.vm.provision "k8s-install-node-part-1",
                        type: "shell",
                        run: "always",
                        env: {"node_ip" => node_ip},
                        privileged: true,
                        path: k8sinstall
                end
                script = "#{ENV['CILIUM_TEMP']}/node-start-#{n+2}.sh"
                node.vm.provision "config-install", type: "shell", privileged: true, run: "always", path: script
                if ENV["K8S"] then
                    k8sinstall = "#{ENV['CILIUM_TEMP']}/cilium-k8s-install-2nd-part.sh"
                    node.vm.provision "k8s-install-node-part-2",
                        type: "shell",
                        run: "always",
                        env: {"node_ip" => node_ip},
                        privileged: true,
                        path: k8sinstall
                end
            end
        end
    end

    #######################
    # Multinode K8s setup #
    ####################### 
    (1..2).each do |i|
    config.vm.define "k8s#{i}-#{$K8S_VERSION}" do |server|
        server.vm.provider "virtualbox" do |vb|
            # TODO - why do we need this? 
            vb.customize ["modifyvm", :id, "--hwvirtex", "on"]
            vb.memory = ENV['VM_MEMORY'].to_i
            vb.cpus = ENV['VM_CPUS'].to_i
            #TODO - is this necessary?
            #vb.linked_clone = true

            # Do not inherit DNS server from host, use proxy
            vb.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
            vb.customize ["modifyvm", :id, "--natdnsproxy1", "on"]

            if ENV["NFS"] then
                server.vm.synced_folder '.', '/home/vagrant/go/src/github.com/cilium/cilium', type: "nfs"
                # To get NFS working, run the following commands on your host before starting the VM
                # iptables -I INPUT -p udp -s 192.168.34.0/24 --dport 111 -j ACCEPT
                # iptables -I INPUT -p udp -s 192.168.34.0/24 --dport 2049 -j ACCEPT
                # iptables -I INPUT -p udp -s 192.168.34.0/24 --dport 20048 -j ACCEPT
            else
                # Ignore contrib/packaging/docker/stage to prevent concurrent
                # problems when using rsync on multiple VMs. Also ignore src directory
                # when running Ginkgo tests.
                server.vm.synced_folder '.', '/home/vagrant/go/src/github.com/cilium/cilium', type: "rsync",
                #server.vm.synced_folder '.', '/src', type: "rsync",
                rsync__exclude: ["contrib/packaging/docker/stage", "src"]
            end

        end

        ####################
        # Networking setup #
        ####################
        server.vm.hostname = "k8s#{i}"
        server.vm.network "private_network", ip: "192.168.36.1#{i}", virtualbox__intnet: "cilium-k8s-multi-test-#{$build_id}-#{$K8S_VERSION}"
        server.vm.network "private_network", ip: "192.168.37.1#{i}", bridge: "enp0s9"

        # Hack to ensure that Kubernetes picks up the node-ip of the private_network
        # instead of the NATed vagrant IP
        server.vm.provision :shell, inline: "sed 's/127\.0\.0\.1.*k8s.*/192\.168\.36\.1#{i} k8s#{i}/' -i /etc/hosts"

        # Mount BPF filesystem
        server.vm.provision :shell, inline: "mount bpffs /sys/fs/bpf -t bpf"

        ########################
        # Provisioning scripts #
        ########################
        # http://foo-o-rama.com/vagrant--stdin-is-not-a-tty--fix.html
        server.vm.provision :shell,
            :inline => "sed -i 's/^mesg n$/tty -s \\&\\& mesg n/g' /root/.profile"
            server.vm.provision "file", source: "test/provision", destination: "/tmp/provision"
            server.vm.provision "shell" do |sh|
            # TODO - remove this?
                sh.path = "./test/provision/k8s_install.sh"
                sh.args = ["k8s#{i}", "192.168.36.1#{i}", "#{$K8S_VERSION}"]
            end
        end
    end
end
