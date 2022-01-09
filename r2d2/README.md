# r2d2

Run the following command to send request to r2d2 server

Start r2d2 server by `go run r2d2/server.go`

``` sh
echo -n "READ VERSION\r\n" | nc localhost 3333  # read VERSION file in current folder
echo -n "READ\r\n" | nc localhost 3333 # invalid read cmd
echo -n "WRITE VERSION\r\n" | nc localhost 3333 # write VERSION file
echo -n "HALT\r\n" | nc localhost 3333 # run halt cmd
echo -n "RESET\r\n" | nc localhost 3333 # run reset cmd
```
