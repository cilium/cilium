=======================   Test Setup ============================

# Note: cqlsh client does not properly detect disconnections, and it seems like each time we change policy, the
# the connection is broken.   Error from cqlsh is "NoHostAvailable:".   Just 'quit' cqlsh and re-connect.  


sudo /usr/bin/cilium-agent --debug --auto-ipv6-node-routes --ipv4-range 10.11.0.0/16 --kvstore-opt consul.address=192.168.33.11:8500 --kvstore consul --container-runtime=docker --container-runtime-endpoint=unix:///var/run/docker.sock -t vxlan --access-log=/var/log/cilium-access.log --fixed-identity-mapping=128=kv-store --fixed-identity-mapping=129=kube-dns --debug-verbose=flow

docker network create --ipv6 --subnet ::1/112 --driver cilium --ipam-driver cilium cilium-net

docker run -d --net cilium-net --name cass-server -l id=cass-server cassandra

cilium endpoint list  # record IP of cass-server

docker run -it  --net cilium-net --name cass-client -l id=cass-client --entrypoint=bash cassandra

[ inside container ] 

cqlsh <IP of cass-server> 

Connected to Test Cluster at 10.11.244.109:9042.
[cqlsh 5.0.1 | Cassandra 3.11.3 | CQL spec 3.4.4 | Native protocol v4]
Use HELP for help.
cqlsh> CREATE KEYSPACE posts_db WITH REPLICATION = { 'class' : 'NetworkTopologyStrategy', 'datacenter1' : 2 };
cqlsh> USE posts_db;
cqlsh:posts_db> CREATE TABLE posts (username varchar, creation timeuuid, content varchar, PRIMARY KEY ((username), creation));
cqlsh:posts_db> INSERT INTO posts (username, creation, content) values ('nicolas', now(), 'First Post');
cqlsh:posts_db> INSERT INTO posts (username, creation, content) values ('arnaud', now(), 'Salut');
cqlsh:posts_db> INSERT INTO posts (username, creation, content) values ('nicolas', now(), 'Second Post');
cqlsh:posts_db> SELECT * FROM posts;

 username | creation                             | content
----------+--------------------------------------+-------------
   arnaud | f537e0c0-b19a-11e8-9245-b1eb355ab4a6 |       Salut
  nicolas | f1cc5420-b19a-11e8-9245-b1eb355ab4a6 |  First Post
  nicolas | f93e26c0-b19a-11e8-9245-b1eb355ab4a6 | Second Post

(3 rows)

=============== Example Policies ===========

# This policy will allow all commands, but will result in access-log messages for each Cassandra request

$ cat cass-allow-all.json 
[ { 
    "endpointSelector": {"matchLabels":{"id":"cass-server"}}, 
    "ingress": [ {
	  "toPorts": [{
		  "ports": [{"port": "9042", "protocol": "TCP"}],
            		"rules": {
                		"l7proto": "cassandra",
                		"l7": [{}] 
            		}
		}]
	  } ] 
}]

# This policy will allow the cqlsh client to connect (it sends several queries automatically) 
# and then allow 'insert' into 'posts_db.posts' table, but will not allow 'select' from that table.
# 
# You will see an error like: 
# 
# cqlsh:posts_db> SELECT * FROM posts;
# Unauthorized: Error from server: code=2100 [Unauthorized] message="Request Unauthorized" 

$ cat cass-no-select-posts.json 
[ { 
    "endpointSelector": {"matchLabels":{"id":"cass-server"}}, 
    "ingress": [ {
	  "toPorts": [{
		  "ports": [{"port": "9042", "protocol": "TCP"}],
            		"rules": {
                		"l7proto": "cassandra",
                		"l7": [
				       { "opcode": "startup"},	
				       { "opcode": "register"},	
				       { "opcode": "options" }, 
				       { "opcode": "query", "query_action" : "use"},
				       { "opcode": "query", "query_action" : "select", "query_table": "^system.*"}, 
				       { "opcode": "query", "query_action" : "insert", "query_table" : "^posts_db.posts$"}

				]}
            		}]
	 }]
} ] 


