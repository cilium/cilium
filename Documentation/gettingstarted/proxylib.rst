.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

********************************************
Getting Started with Envoy Golang Extensions
********************************************

This is a guide for developers who are interested in writing a Golang extension to the 
Envoy proxy as part of Cilium.   These extensions greatly simplify the work required to
add awareness of a new protocol or API to Cilium, taking full advantage of Cilium features
including high-performance redirection to/from Envoy, rich L7-aware policy language
and access logging, and visibility into encrypted traffic traffic via kTLS (coming soon!).  

This guide uses simple examples based on a hypothetical "r2d2" protocol that might be used to 
talk to a simple protocol droid a long time ago in a galaxy far, far away.   But it also points
to other real protocols like memcache and cassandra that already exist in the cilium/proxylib 
directory.  

Step 1: Decide on a Basic Policy Model
======================================

To get started, take some time to think about what it means to provide protocol-aware security
 in the context of your chosen protocol.   Most protocols follow a common pattern of a client 
who performs an ''operation'' on a ''resource''.   For example: 

- A standard RESTful HTTP request has a GET/POST/PUT/DELETE methods (operation) and URLs (resources).
- A database protocol like MySQL has SELECT/INSERT/UPDATE/DELETE actions (operation) on a combined database + table name (resource).   
- A queueing protocol like Kafka has produce/consume (operation) on a particular queue (resources).    

A common policy model is to allow the user to whitelist certain operations on one or more resources.   
In some cases, the resources need to support regexes to avoid explicit matching on variable content 
like ids (e.g., /users/<uuid> would match /users/.*) 

In our examples, the ''r2d2'' example, we'll use a basic set of operations (READ/WRITE/HALT/RESET). 
The READ and WRITE commands also support a 'filename' resource, while HALT and RESET have no resource.  

Step 2: Understand Protocol, Encoding, Framing and Types
========================================================

Next, get your head wrapped around how a protocol looks terms of the raw data, as this is what you'll be parsing. 

Try looking for official definitions of the protocol or API.   Official docs will not only help you quickly 
learn how the protocol works, but will also help you by documenting tricky corner cases that wouldn't be 
obvious just from regular use of the protocol.   For example, here are example specs for 
`Redis <https://redis.io/topics/protocol>`_ , `Cassandra <https://github.com/apache/cassandra/blob/trunk/doc/native_protocol_v4.spec>`_,  
and `AWS SQS <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/Welcome.html>`_ .  

These specs help you understand protocol aspects like: 

- **encoding / framing** : how to recognize the beginning/end of individual requests/replies within a TCP stream. 
 This typically involves reading a header that encodes the overall request length, though some simple 
 protocols use a delimiter like ''\r\n\'' to separate messages.  

- **request/reply fields** : for most protocols, you will need to parse out fields at various offsets
 into the request data in order to extract security-relevant values for visibility + filtering.  In some cases, access
 control requires filtering requests from clients to servers, but in some cases, parsing replies will also be required
 if reply data is required to understand future requests (e.g., prepared-statements in database protocols).  

- **message flow** : specs often describe various dependencies between different requests.  Basic protocols tend to 
 follow a simple serial request/reply model, but more advanced protocols will support pipelining (i.e., sending 
 multiple requests before any replies have been received).  

- **protocol errors** : when a Cilium proxy denies a request based on policy, it should return a protocol-specific
 error to the client (e.g., in HTTP, a proxy should return a ''403 Access Denied'' error).  Looking at the protocol
 spec will typically indicate how you should return an equivalent ''Access Denied'' error.    
  
Sometimes, the protocol spec does not give you a full sense of the set of commands that can be sent over the protocol.  In that 
case, looking at higher-level user documentation can fill in some of these knowledge gaps.  Here are examples for 
`Redis <https://redis.io/commands>`_ and `Cassandra <https://docs.datastax.com/en/cql/3.1/cql/cql_reference/cqlCommandsTOC.html>`_ .  
 
Another great trick is to use `Wireshark <https://www.wireshark.org>`_  to capture raw packet data between
a client and server.   For many protocols, the `Wireshark Sample Captures <https://wiki.wireshark.org/SampleCaptures>`_ 
has already saved captures for us.  Otherwise, you can easily use tcpdump to capture a file.  For example, for 
Mysql traffic on port 3306, you could run the following in a container running the mysql client or server: 
“tcpdump -s 0 port 3306 -w mysql.pcap”.  `More Info <https://linuxexplore.com/2012/06/07/use-tcpdump-to-capture-in-a-pcap-file-wireshark-dump/>`_    

In our example r2d2 protocol, we'll keep the spec as simple as possible.  It is a text-only based protocol, 
with each request being a line terminated by ''\r\n''.  A request starts with a case-insensitive string 
command ("READ","WRITE","HALT","RESET").   If the command is "READ" or "WRITE", the command must be followed
by a space, and a non-empty filename that contains only non whitespace ASCII characters.  

Step 3: Search for Existing Parser Code / Libraries
===================================================

Look for open source golang library/code that can help.    
Is there existing open source golang code that parse your protocol that you can leverage, 
either directly as library or a motivating example?  For example, the `tidwall/recon library 
<https://github.com/tidwall/redcon>`_ parses Redis in golang, and `Vitess 
<https://github.com/vitessio/vitess>`_ parses MySQL in golang.   `Wireshark dissectors 
<https://github.com/boundary/wireshark/tree/master/epan/dissectors>`_ also has a wealth of 
protocol parsers written in C that can serve as useful guidance.    Note:  finding client-only 
protocol parsing code is typically less helpful than finding a proxy implementation, or a full 
parser library.   This is because the set of requests a client parsers is typically the inverse
set of the requests a Cilium proxy needs to parse, since the proxy mimics the server rather than 
the client.   Still, viewing a golang client can give you a general idea of how to parse the 
general serialization format of the protocol.  

Step 4: Follow the Cilium Developer Guide
=========================================

It is easiest to start Cilium development by following the :ref:`_dev_guide`

After cloning Cilium: 

::

    $ cd cilium 
    $ contrib/vagrant/start.sh 
    $ cd proxylib

While this dev VM is running, you can open additional terminals to the Cilium dev VM
by running ''vagrant ssh'' from within the cilium source directory.  


Step 5: Create New Proxy Skeleton 
=================================

From inside the proxylib directory, copy the rd2d directory and rename the files. 
Replace ''newproto'' with your protocol: 

:: 

    $ mkdir newproto
    $ cd newproto
    $ cp ../r2d2/r2d2parser.go newproto.go
    $ cp ../r2d2/r2d2parser_test.go newproto_test.go


Within both newproto.go and newproto_test.go update references to r2d2 with
your protocol name.   Search for both ''r2d2'' and ''R2D2''.  

Also, edit proxylib.go and add the following import line: 

:: 

       _ "github.com/cilium/cilium/proxylib/newproto"


Step 6: Update OnData Method 
============================

The beating heart of your parsing is implementing the onData function, which is called with an 
array of byte arrays each time envoy receives some more data on the proxy port (in either the 
request or reply direction).   The job of OnData is to tell the framework one of four things: 

- **PASS x** :  The first x bytes that were passed to OnData represent a request/reply that should be
 passed on to the server/client.   The common case here is that this is a request that should be 
 allowed by policy, or that no policy is applied.   
- **MORE x** :  The buffers passed to OnData to do not represent a full request/reply.  The parser 
 needs to see at least x new bytes beyond the current data to know if a full request has been 
 received.   When parsing data, be defensive, and recognize that it is technically possible that 
 data arrives one byte byte at a time.   Two common scenarios exist here:  
    - **Text-based Protocols** : For text-based protocols
      that use a delimiter like "\r\n", it is common to simply check if the delimiter exists, and return 
      MORE 1 if it does not, as technically one more character could result in the delimiter being present.
      See the sample r2d2 parser as a basic example of this.    
    - **Binary-based protocols** : Many binary protocols  
      have a fixed header length, which containers a field that then indicates the remaining length
      of the request.  In the binary case, first check to make sure a full header is received, returning
      MORE if it is not, then reach the full request length, and return MORE if the full request has not
      been passed (see the existing CassandraParser as an example).
- **DROP x** :  Remove the first x bytes from the data stream passed to OnData, as they represent a request/reply
  that should not be forwarded to the client or server based on policy.  Don't worry about making onData return 
  a drop right away, as we'll return to DROP in a later step below.  
- **ERROR y** : The connection contains data that does not match the protocol spec, and prevents you from further 
  parsing the data stream.   The framework will terminate the connection.   An example would be a request length
  that falls outside the min/max specified by the protocol spec, or values for a field that fall outside the values
  indicated by the spec (e.g., wrong versions, unknown commands).  If you are still able to properly frame the 
  requests, you can also choose to simply drop the request and return a protocol error (e.g., similar to an 
  ''HTTP 400 Bad Request'' error.   But in all cases, you should write your parser defensively, such that you 
  never forward a request that you do not understand, as such a request could become an avenue for subverting 
  the intended security visibility and filtering policies.  See proxylib/types.h for the set of valid error codes.   


Keep it simple, and work iteratively.  Start out just getting the framing right.  Can you write a parser that just 
prints out the length and contents of a request, and then PASS each request with no policy enforcement?   

One simple trick is to comment out the r2d2 parsing logic in OnData, but leave it in the file as a reference, as your protocol will likely
require similar code as we add more functionality below.  

Step 7: Use Unit Testing To Drive Development
=============================================

Use unit tests to drive your development.    Its tempting to want to first test your parser by firing up a
client and server and developing on the fly.   But in our experience you’ll iterate faster by using the 
great unit test framework created along with the golang proxy framework.   This framework lets you pass
in an example set of requests as byte arrays to a CheckOnDataOK method, which are passed to the parser's OnData method.
CheckOnDataOK takes a set of expected return values, and compares them to the actual return values from OnData 
processing the byte arrays.  

Take some time to look at the unit tests for the r2d2 parser, and then for more complex parsers like Cassandra
and Memcached.   For simple text-based protocols, you can simply write ASCII strings to represent protocol messages, 
and convert them to []byte arrays and pass them to CheckOnDataOK.   For binary protocols, one can either create 
byte arrays directly, or use a mechanism to convert a hex string to byte[] array using a helper function like 
hexData in cassandra/cassandraparser_test.go

A great way to get the exact data to pass in is to copy the data from the Wireshark captures mentioned
above in Step #2.   You can see the full application layer data streams in Wireshark by right-clicking
on a packet and selecting “Follow As… TCP Stream”.  If the protocol is text-based, you can copy the data 
as ASCII (see r2d2/r2d2parser_test.go as an example of this).   For binary data, it can be easier to instead 
select “raw” in the dropdown, and use a basic utility to convert from ascii strings to binary raw data (see 
cassandra/cassandraparser_test.go for an example of this). 

To run the unit tests, go to proxylib/newproto and run: 

:: 

  $ go test

This will build the latest version of your parser and unit test *.go files and run the unit tests.   

Step 8: Add More Advanced Parsing
=================================

Thinking back to step #1, what are the critical fields to parse out of the request in order to 
understand the “operation” and “resource” of each request.  Can you print those out for each request?

Use the unit test framework to pass in increasingly complex requests, and confirm that the parser prints out the right values, and that the 
unit tests are properly slicing the datastream into requests and parsing out the required fields. 

A couple scenarios to make sure your parser handles properly via unit tests: 

- data chunks that are less than a full request (return MORE) 
- requests that are spread across multiple data chunks. (return MORE ,then PASS) 
- multiple requests that are bundled into a single data chunk (return PASS, then another PASS)
- rejection of malformed requests (return ERROR). 

For certain advanced cases, it is required for a parser to store state across requests. 
In this case, data can be stored using data structures that
are included as part of the main parser struct.  See CassandraParser in cassandra/cassandaraparser.go as an example 
of how the parser uses a string to store the current 'keyspace' in use, and uses golang maps to keep 
state required for handling prepared queries.   

Step 9:  Add Policy Loading and Matching
========================================

Once you have the parsing of most protocol messages ironed out, its time to start enforcing policy. 

First, create a golang object that will represent a single rule in the policy language. For example,
this is the rule for the r2d2 protocol, which performs exact match on the command string, and a regex
on the filename:  

:: 

 type R2d2Rule struct {
    cmdExact   string
    fileRegexCompiled *regexp.Regexp
 }

There are two key methods to update: 

- Matches :   This function implements the basic logic of comparing data from a single request 
 against a single policy rule, and return true if that rule matches (i.e., allows) that request.  
- <NewProto>RuleParser : Reads key value pairs from policy, validates those entries, and stores
  them as a <NewProto>Rule object.   

See r2d2/r2d2parser.go for examples of both functions for the r2d2 protocol.  

You'll also need to update OnData to call Matches() on the connection, and return DROP for a request.
Calling Matches() on the connection removes the need for the parser to explicitly iterate through 
each rule and call Matches() on that rule.    

Once you add the logic to call Matches() and return DROP in OnData, you will need to update
unit tests to have policies that allow the traffic you expect to be passed.   The following 
is an example of how r2d2/r2d2parser_test.go adds an allow-all policy for a given test: 

:: 

    s.ins.CheckInsertPolicyText(c, "1", []string{`
        name: "cp1"
        policy: 2
        ingress_per_port_policies: <
          port: 80
          rules: <
            l7_proto: "r2d2"
            l7_rules: <
              l7_rules: <>
            >
          >
        >
        `})

The following is an example of a policy that would allow READ commands with a file 
regex of ".*": 

:: 

    s.ins.CheckInsertPolicyText(c, "1", []string{`
        name: "cp2"
        policy: 2
        ingress_per_port_policies: <
          port: 80
          rules: <
            l7_proto: "r2d2"
            l7_rules: <
            rule: <
              key: "cmd"
              value: "READ"
            >
            rule: <
              key: "file"
              value: ".*"
            >
              >
            >
          >
        >
        `})


Note:  Each policy added in your test file should have a unique name (e.g., "cp1", "cp2", etc.). 

Step 10: Add Access Logging
===========================

Cilium also has the notion of an ''Access Log'', which records each request handled by the proxy 
and indicates whether the request was allowed or denied.  

A call to ''p.connection.Log()'' implements access logging. See the OnData function in r2d2/r2d2parser.go 
as an example.   

Step 11: Manual Testing
=======================

Find the standard docker container for running the protocol server.  Often the same image also has a CLI client that you can use as a client. 

 Start both a server and client container running in the cilium dev VM, and attach them to the already created “cilium-net”.  

For example, with cassandra, we run:

:: 
    docker run --name cass-server -l id=cass-server -d --net cilium-net cassandra

    docker run --name cass-client -l id=cass-client -d --net cilium-net cassandra sh -c 'sleep 3000' 
 

Note that we run both containers with labels that will make it easy to refer to these containers in a cilium 
network policy.   Note that we have the client container run the sleep command, as we will use 'docker exec' to 
access the client CLI.  

Use ''cilium endpoint list to identify the IP address of the protocol server.  

:: 

$ cilium endpoint list
ENDPOINT   POLICY (ingress)   POLICY (egress)   IDENTITY   LABELS (source:key[=value])   IPv6                 IPv4            STATUS   
           ENFORCEMENT        ENFORCEMENT                                                                                     
2987       Disabled           Disabled          31423      container:id=cass-server      f00d::a0b:0:0:bab    10.11.51.247    ready   
27333      Disabled           Disabled          4          reserved:health               f00d::a0b:0:0:6ac5   10.11.92.46     ready   
50923      Disabled           Disabled          18253      container:id=cass-client      f00d::a0b:0:0:c6eb   10.11.175.191   ready 

One can then invoke the client CLI using that server IP address (10.11.51.247 in the above example):

:: 

 docker exec -it cass-client sh -c 'cqlsh 10.11.51.247 -e "select * from system.local"'

Note that in the above example, ingress policy is not enforced for the cassandra server endpoint, so no data will flow through the
cassandra parser.  A simple ''allow all'' L7 cassandra policy can be used to send all data to the cassandra server through the 
golang cassandra parser.  This policy has a single empty rule, which matches all requests.  An allow all policy looks like: 

:: 

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


A policy can be imported into cilium using ''cilium policy import'', after which another call to ''cilium endpoint list''
confirms that ingress policy is now in place on the server.  If the above policy was saved to a file cass-allow-all.json, 
one would run: 

:: 

    $ cilium policy import cass-allow-all.json
    Revision: 1
    $ cilium endpoint list
    ENDPOINT   POLICY (ingress)   POLICY (egress)   IDENTITY   LABELS (source:key[=value])   IPv6                 IPv4            STATUS   
               ENFORCEMENT        ENFORCEMENT                                                                                     
    2987       Enabled            Disabled          31423      container:id=cass-server      f00d::a0b:0:0:bab    10.11.51.247    ready   
    27333      Disabled           Disabled          4          reserved:health               f00d::a0b:0:0:6ac5   10.11.92.46     ready   
    50923      Disabled           Disabled          18253      container:id=cass-client      f00d::a0b:0:0:c6eb   10.11.175.191   ready 

Note that policy is now showing as ''Enabled'' for the cassandra server on ingress. 

To remove this or any other policy, run: 

:: 

    $ cilium policy delete --all 

To install a new policy, first delete, and then run ''cilium policy import'' again.  For example, the following policy would allow
select statements on a specific set of tables to this cassandra server, but deny all other queries. 

:: 

  [ {
    "endpointSelector": {"matchLabels":{"id":"cass-server"}},
    "ingress": [ {
          "toPorts": [{
                  "ports": [{"port": "9042", "protocol": "TCP"}],
                        "rules": {
                                "l7proto": "cassandra",
                                "l7": [
                                       { "query_action" : "select", "query_table": "^system.*"},
                                       { "query_action" : "select", "query_table" : "^posts_db.posts$"}

                                ]}
                        }]
         }]
  } ]

When performing manual testing, remember that each time you change your golang proxy code, you must
re-run ''make'' and ''sudo make install'' and then restart the cilium-agent process.  If the only changes
you have made since last compiling cilium are in your cilium/proxylib/newproto directory, you can safely 
just run ''make'' in that directory, which saves time.  You will still need to run ''sudo make install'' 
from the top level directory.   For example: 

:: 

  $ cd proxylib/newproto  // only safe is this is the only directory that has changed
  $ make  
    <snip> 
  $ cd ../..
  $ sudo make install 
    <snip> 
  $ sudo service cilium restart

Cilium service logs are accessible via journalctl: 

:: 

   journalctl -u cilium -f


The cilium access log is accessible from within the developer VM at ''/var/log/cilium-access.log''

One can also stop the cilium service and run the cilium-agent directly as a command in a terminal window, 
which can be helpful for tweaking debug levels on the fly.  The ''--debug-verbose=flow'' flag is particularly
helpful in many circumstances.   

:: 

  $ sudo service cilium stop 
  
  $ sudo /usr/bin/cilium-agent --debug --auto-ipv6-node-routes --ipv4-range 10.11.0.0/16 --kvstore-opt consul.address=192.168.33.11:8500 --kvstore consul --container-runtime=docker --container-runtime-endpoint=unix:///var/run/docker.sock -t vxlan --fixed-identity-mapping=128=kv-store --fixed-identity-mapping=129=kube-dns --debug-verbose=flow --access-log=/var/log/cilium-access.log 


Step 12: Add Runtime Tests
==========================

Before submitting this change to the Cilium community, it is recommended that you all runtime tests that will run as
part of Cilium's continuous integration testing.   Usually these runtime test can be based on the same container 
images and test commands you used for manual testing.   

The best approach for adding runtime tests is typically to start out by copying-and-pasting an existing L7 protocol runtime
test and then updating it to run the container images and CLI commands specific to the new protocol.   
See cilium/test/runtime/cassandra.go as an example that matches the use of cassandra described above in the manual testing
section.   Note that the json policy files used by the runtime tests are stored in cilium/test/runtime/manifests, and 
the cassandra example policies in those directories are easy to use as a based for similar policies you may create for your
new protocol.  

Step 13: Review Spec for Corner Cases
=====================================

Many protocols have advanced features or corner cases that will not manifest themselves as part of basic testing.   
Once you have written a first rev of the parser, it is a good idea to go back and review the protocol's spec or list of 
commands to see what if any aspects may fall outside the scope of your initial parser.    
For example, corner cases like the handling of empty or nil lists may not show up in your testing, but may cause your
parser to fail.   Add more unit tests to cover these corner cases.  
It is OK for the first rev of your parser not to handle all types of requests, or to have a simplified policy structure 
in terms of which fields can be matched.   However, it is 
important to know what aspects of the protocol you are not parsing, and ensure that it does not lead to any security concerns. 
For example, failing to parse prepared statements in a database protocol and instead just passing PREPARE and EXECUTE
commands through would lead to gaping security whole that would render your other filtering meaningless in the face of
a sophisticated attacker.   

Step 14: Write Docs or Getting Started Guide (optional) 
=======================================================

At a minimum, the policy examples included as part of the runtime tests serve
as basic documentation of the policy and its expected behavior.  But we also 
encourage adding more user friendly examples and documentation, for example, 
Getting Started Guides.  cilium/Documentation/gettingstarted/cassandra.rst is
a good example to follow.   Also be sure to update Documentation/gettingstarted/index.rst
with a link to this new getting started guide. 

With that, you are ready to post this change for feedback from the Cilium community.  Congrats! 
