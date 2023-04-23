# Script Verifier Server


> The Script Verifier Server is a gRPC-based service that receives signed Bash scripts, verifies their signatures using locally stored x509 certificates, and then executes the scripts if the signatures are valid.

## Project Structure

```go
.
├── build.sh
├── cmd
│   └── server
│       └── main.go
├── go.mod
├── go.sum
├── internal
│   ├── proto
│   └── scriptverifier
│       └── verifier.go
├── proto
│   └── script_verifier.proto
├── tests
│   ├── certs
│   └── scriptverifier_test.go
└── README.md

```

## Prerequisites
* Go 1.20 or higher
* Protocol Buffers Compiler ([protoc](https://grpc.io/docs/protoc-installation/))
* Go protobuf plugins: `protoc-gen-go` and `protoc-gen-go-grpc`

Run the following command to install them:

```bash
go install -u google.golang.org/protobuf/cmd/protoc-gen-go@latest 
go install -u google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```


## Build
To build the project, run the following commands:

```bash
chmod+x build.sh && ./build.sh
```

This will create the server executable in the `bin` directory.

## Run

To run the server, execute the following command:

```bash
./bin/server --cert-dir=path/to/certificates
```

The default certs dir is `test/certs`. Replace `path/to/certificates` with the path to the directory containing the X.509 certificates.

Use `grpcurl` to interact with the server, install `grpcurl` and then execute the following command:

```bash
grpcurl -plaintext -d '{"script": "<base64-encoded signature + script>"}' localhost:13337 ScriptSigVerifier.proto.ScriptVerifier/ExecuteScript
```

To install `grpcurl`:

```bash
go install -u github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
```


## Communication Protocol

The project uses gRPC as the IPC mechanism for communication between the client and the server. The protocol is defined in the `script_verifier.proto` file.

The server accepts the following request message:

```proto
message ExecuteScriptRequest {
  string script = 1;
}
```

And returns the following response message:

```proto
message ExecuteScriptResponse {
  string status = 1;
  string output = 2;
}
```
## Status Code

Status Code
The status code indicates the execution result of the script:

* `OK`: This status code is returned when the script signature is successfully verified, and the script is executed successfully.

* `INVALID_SIGNATURE`: This status code is returned when the signature in the script file is not a valid base64-encoded string or the signature verification fails due to a wrong or invalid public key.

* `SCRIPT_EXECUTION_ERROR`: This status code is returned when the script signature is successfully verified, but the execution of the script fails due to some error, such as syntax error or permissions issue.

If the server works as expected, the client will display the script output upon successful execution. If there's a failure in script execution or signature verification, the client will display an error message.


## Testing

To run the test cases, start two terminals. In the first terminal, run the server with the test certificates:

```bash
./bin/server --cert-dir=test/certs

```

In the second terminal, run the tests:

```bash
go test -v test/
```

## TODO

- [x] Support certs memory pooling based on cert file name.
- [ ] Implement a RESTful API to interact with the server.



