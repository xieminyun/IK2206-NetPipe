# IK2206-NetPipe
This is the project from KTH IK2206. The goal is to add implement simple TLS.

To test the programme, run  NetPipeServer/NetPipeServer.jar and run the corresponding NetPipeClient.jar/NetPipeClient.

Use command line argument or IDEA edit configurations with the following arguments:

Server:

```
--port=2206 --usercert=src/server.pem --cacert=src/ca.pem --key=src/server-private.der
```

Client

```
--host=localhost  --port=2206  --usercert=src/client.pem --cacert=src/ca.pem --key=src/client-private.der
```

:)
