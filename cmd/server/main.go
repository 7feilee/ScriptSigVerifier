package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"ScriptSigVerifier/internal/proto"
	"ScriptSigVerifier/internal/scriptverifier"

	"google.golang.org/grpc"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/reflection"
)

const (
	Address = "localhost:13337"
)

type server struct {
	proto.UnimplementedScriptVerifierServer
}

func main() {

	certDir := flag.String("cert-dir", "test/certs", "Path to the directory containing X.509 certificates")

	// Parse the flags
	flag.Parse()

	err := scriptverifier.InitPublicKeyPool(*certDir)
	if err != nil {
		log.Fatalf("Failed to initialize certificate pool: %v", err)
	}

	go scriptverifier.WatchCertDir(*certDir)

	listen, err := net.Listen("tcp", Address)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	// Set up the interceptor
	grpclog.SetLoggerV2(grpclog.NewLoggerV2(os.Stdout, os.Stdout, os.Stderr))
	srvOpts := []grpc.ServerOption{
		grpc.UnaryInterceptor(loggingInterceptor),
	}
	s := grpc.NewServer(srvOpts...)
	proto.RegisterScriptVerifierServer(s, &server{})
	reflection.Register(s)

	log.Println("Server listening at", listen.Addr())
	if err := s.Serve(listen); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

// ExecuteScript executes the provided signed script if the signature is valid
// Returns the output of the executed script or an error if the signature is invalid or script execution fails
func (s *server) ExecuteScript(ctx context.Context, req *proto.ExecuteScriptRequest) (*proto.ExecuteScriptResponse, error) {
	// Split the received script into the base64-encoded signature and the actual script
	signedScript := string(req.GetScript())
	signatureAndScript := strings.SplitN(signedScript, "\n", 2)
	base64Signature := signatureAndScript[0]
	script := signatureAndScript[1]

	// Decode the base64-encoded signature
	signature, err := base64.StdEncoding.DecodeString(base64Signature)
	if err != nil {
		return &proto.ExecuteScriptResponse{Status: "INVALID_SIGNATURE"}, nil
	}

	hashedScript := sha256.Sum256([]byte(script))

	err = scriptverifier.VerifySignature(signature, hashedScript[:])
	if err != nil {
		return &proto.ExecuteScriptResponse{Status: "INVALID_SIGNATURE"}, nil
	}

	// Execute the script and capture the output
	output, err := executeScriptWithTimeout(script, 5*time.Second)

	if err != nil {
		fmt.Println(err)
		return &proto.ExecuteScriptResponse{Status: "SCRIPT_EXECUTION_ERROR", Output: err.Error()}, nil
	}

	return &proto.ExecuteScriptResponse{Status: "OK", Output: string(output)}, nil
}

func executeScriptWithTimeout(script string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "-c", script)
	output, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		return "", errors.New("script execution timed out")
	}

	return string(output), err
}

func loggingInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	grpclog.Infof("gRPC request: %v", info.FullMethod)
	grpclog.Infof("request data: %v", req)

	resp, err := handler(ctx, req)
	if err != nil {
		grpclog.Errorf("gRPC error (%s): %v", info.FullMethod, err)
	} else {
		grpclog.Infof("response data: %v", resp)
	}
	return resp, err
}
