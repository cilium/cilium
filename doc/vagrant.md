To bring up a [vagrant](https://www.vagrantup.com/) VM with Cilium
installed and running:

```
$ vagrant up
```

Alternatively you can use the vagrant box `noironetworks/net-next` directly and
manually install Cilium:

  ```
  $ vagrant init noironetworks/net-next
  $ vagrant up
  $ vagrant ssh [...]
  $ cd go/src/github.com/noironetworks/cilium-net/
  $ make
  $ sudo make install
  $ sudo service cilium-net-daemon restart
  ```
