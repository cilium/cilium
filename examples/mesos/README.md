# (Experimental) Simple Cilium demo for Apache Mesos

## Overview

It will create a vbox with installed Apache Mesos, marathon and Cilium.
You can play with a provided simple Cilium policy applied to a dummy
"web-server" and a client.

## Instructions

Build VBox (will take a while):
    
    vagrant up

Login into VBox:

    vagrant ssh

Inside of the Virtual Box start Marathon:

    [HOST_IP=192.168.44.11] ./start_marathon.sh

Run a dummy web-server:

    curl -i -H 'Content-Type: application/json' -d @web-server.json 127.0.0.1:8080/v2/apps

(optional) Make sure it works:
    
    cilium endpoint list # should return the endpoint with label mesos:id=web-server and assigned IP
    curl <IP>:8181/api # use <IP> from the previous command

Run a client:

    # Generate a json file for the client task:
    ./generate_client_file.sh # It should generate client.json for the client task
    # Submit the client task
    curl -i -H 'Content-Type: application/json' -d @client.json 127.0.0.1:8080/v2/apps
   
There is no easy way to retrieve the logs of the client, so use the following script:

    ./tail_client.sh

Make sure the previous command continuously prints the result of the client accessing */public* and */private* API of the web-server:

    ...
    --------------------------------
    GET /public
    OK

    GET /private
    OK
    --------------------------------
    GET /public
    OK

    GET /private
    OK
    --------------------------------
    ...

Now, in a different terminal apply a provided policy that allows accessing only */public* API:

    cilium policy import l7-policy.json

Check the client's log and you should see that */private* is no longer accessible.

(optional) Remove the policy and notice that the access to */private* is again unrestricted:

    cilium policy delete --all

To clean the node kill all mesos-master, mesos-agent, marathon related processes manually.

## Troubleshooting

### Mesos master and slave do not seem to be working

Inspect result of journalctl and *marathon.log* for any obvious errors.
Restart mesos/marathon processes if needed.

    sudo service mesos-master restart
    sudo service mesos-slave restart

### tail\_client.sh does not print anything

Make sure you regenerated the client.json if you restarted a web-server task. Inspect client.json
and see if it uses the IP of the web-server.

Run

    cilium endpoint list

to check that both endpoints are created and the correct IP is being used in the script.

### Other

Send a PR!
