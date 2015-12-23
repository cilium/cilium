#!/bin/bash

# Set up dns
cat <<EOF > /etc/resolv.conf
nameserver 8.8.8.8
nameserver 8.8.4.4
options timeout:2 attempts:1 rotate
EOF

# Set up sudo
echo "%vagrant ALL=NOPASSWD:ALL" > /etc/sudoers.d/vagrant
chmod 0440 /etc/sudoers.d/vagrant

# Setup sudo to allow no-password sudo for "sudo"
usermod -a -G sudo vagrant

# Installing vagrant keys
mkdir /home/vagrant/.ssh
chmod 700 /home/vagrant/.ssh
cd /home/vagrant/.ssh
#cat <<EOF > authorized_keys
#ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDZTTnFNK09hRwUjTsT33KsZbCb0U8oUrj/VkP+uwfY1ygiNZki/nupU1YZhxWw4kADlU9xt1U1Iy0abfCqih9Scd5YyucA9iaFmO+PzSRlvtrn3B5T9Ss7pT6lNemL9yqpR7M6dvyDa+Hchrdfv/9M3DJRHKGj82lIJy8QfpWpnU9C7K8J8qiC2t63ugjQBK2VvrIpb66beaDFCUPU3Wst0OZuzWrjsRtc8MwhgnHD8zED9vim1Z6h/e2tW2wvAuJEWfUGB4EMIOigRJnaispPsHr8hXQCQy2LD9yo8g6os+xYVJ3OSsTNiCgaQ951i4lzaOL2YqQ4t2kC4D/d5PID root@noiro-ucs08
#EOF

wget --no-check-certificate 'https://raw.githubusercontent.com/mitchellh/vagrant/master/keys/vagrant.pub' -O authorized_keys
chmod 600 /home/vagrant/.ssh/authorized_keys
chown -R vagrant /home/vagrant/.ssh
