# Smoke Test

This lab walks you through a quick smoke test to make sure things are working.

## Test

```
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/master/examples/gce/deployments/guestbook/1-redis-master-controller.json
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/master/examples/gce/deployments/guestbook/2-redis-master-service.json
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/master/examples/gce/deployments/guestbook/3-redis-slave-controller.json
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/master/examples/gce/deployments/guestbook/4-redis-slave-service.json
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/master/examples/gce/deployments/guestbook/5-guestbook-controller.json
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/master/examples/gce/deployments/guestbook/6-guestbook-service.json
```

```
replicationcontroller "redis-master" created
service "redis-master" created
replicationcontroller "redis-slave" created
service "redis-slave" created
replicationcontroller "guestbook" created
service "guestbook" created
```

```
kubectl get pods -o wide
```
```
NAME                          READY     STATUS    RESTARTS   AGE       IP               NODE
cilium-net-controller-85kpx   1/1       Running   0          1h        172.16.0.20      worker0
cilium-net-controller-gxz7d   1/1       Running   0          1h        172.16.0.21      worker1
cilium-net-controller-z8mh8   1/1       Running   0          1h        172.16.0.22      worker2
guestbook-53blr               1/1       Running   0          35s       10.202.118.183   worker2
redis-master-1hv5l            1/1       Running   0          35s       10.200.118.183   worker0
redis-slave-rs789             1/1       Running   0          35s       10.201.66.100    worker1
```

Connect to the machine where guestbook is running and run the following commands

```
sudo apt-get install socat -y
sudo socat TCP-LISTEN:3000,fork TCP:10.202.118.183:3000
```

### Create the Service Firewall Rule

#### GCP

```
gcloud compute firewall-rules create kubernetes-guestbook-service \
  --allow=tcp:3000 \
  --network kubernetes
```

Grab the `EXTERNAL_IP` for one of the worker node where guestbook is running:

```
NODE_PUBLIC_IP=$(gcloud compute instances describe worker2 \
  --format 'value(networkInterfaces[0].accessConfigs[0].natIP)')
```

Test the guestbook service using cURL:

```
curl http://${NODE_PUBLIC_IP}:3000
```

```
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta content="text/html; charset=utf-8" http-equiv="Content-Type">
    <meta charset="utf-8">
    <meta content="width=device-width" name="viewport">
    <link href="/style.css" rel="stylesheet">
    <title>Guestbook</title>
  </head>
  <body>
    <div id="header">
      <h1>Guestbook</h1>
    </div>

    <div id="guestbook-entries">
      <p>Waiting for database connection...</p>
    </div>

    <div>
      <form id="guestbook-form">
        <input autocomplete="off" id="guestbook-entry-content" type="text">
        <a href="#" id="guestbook-submit">Submit</a>
      </form>
    </div>

    <div>
      <p><h2 id="guestbook-host-address"></h2></p>
      <p><a href="/env">/env</a>
      <a href="/info">/info</a></p>
    </div>
    <script src="//ajax.googleapis.com/ajax/libs/jquery/2.1.1/jquery.min.js"></script>
    <script src="/script.js"></script>
  </body>
</html>
```

Or open your browser on address http://${NODE_PUBLIC_IP}:3000 to see a prettier output.
