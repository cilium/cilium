#!/bin/bash

echo "optimizing libvirt vagrant box"
mkdir -p tmp
rm -Rf tmp/*
tar -xf ubuntu-1604-libvirt.box -C tmp
mv tmp/box.img tmp/box.img.big
qemu-img convert -O qcow2 tmp/box.img.big tmp/box.img
rm tmp/box.img.big
env GZIP=-9 tar -czf ubuntu-1604-libvirt.box -C tmp .
