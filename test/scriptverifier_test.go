package scriptverifier_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"sync"
	"testing"
	"time"

	"ScriptSigVerifier/internal/proto"

	"google.golang.org/grpc"
)

const (
	Address = "localhost:13337"
	certDir = "./certs"
)

var (
	client proto.ScriptVerifierClient
)

func TestMain(m *testing.M) {
	client = connectClient()
	code := m.Run()
	os.Exit(code)
}

func connectClient() proto.ScriptVerifierClient {
	conn, err := grpc.Dial(Address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}

	return proto.NewScriptVerifierClient(conn)
}

func generateRSAKeyPair() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	return key
}

func createSelfSignedCertificate(key *rsa.PrivateKey, isCodeSigning bool) []byte {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	if !isCodeSigning {
		template.ExtKeyUsage = []x509.ExtKeyUsage{}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	certPem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}

	return pem.EncodeToMemory(certPem)
}

func signScript(key *rsa.PrivateKey, script string) (string, error) {
	hashed := sha256.Sum256([]byte(script))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

func saveCertificate(cert []byte) string {
	certPath := certDir + "/test_cert.pem"
	ioutil.WriteFile(certPath, cert, 0644)

	return certPath
}

func deleteCertificate(certPath string) {
	err := os.Remove(certPath)
	if err != nil {
		log.Fatalf("Failed to remove test certificate: %v", err)
	}
}

func TestSuccessfulVerification(t *testing.T) {
	key := generateRSAKeyPair()
	cert := createSelfSignedCertificate(key, true)
	certPath := saveCertificate(cert)
	time.Sleep(2 * time.Second)

	script := "echo 'Hello, World!'"
	signature, err := signScript(key, script)
	if err != nil {
		t.Fatalf("Failed to sign Script: %v", err)
	}

	req := &proto.ExecuteScriptRequest{
		Script: fmt.Sprintf("%s\n%s", signature, script),
	}

	resp, err := client.ExecuteScript(context.Background(), req)
	if err != nil {
		t.Fatalf("Failed to execute Script: %v", err)
	}

	if resp.Status != "OK" {
		t.Errorf("Expected status 'OK', got '%s'", resp.Status)
	}

	expectedOutput := "Hello, World!\n"
	if resp.Output != expectedOutput {
		t.Errorf("Expected output '%s', got '%s'", expectedOutput, resp.Output)
	}

	deleteCertificate(certPath)
}

func TestIncorrectScript(t *testing.T) {
	key := generateRSAKeyPair()

	cert := createSelfSignedCertificate(key, true)
	certPath := saveCertificate(cert)
	time.Sleep(2 * time.Second)

	script := "echo'Hello, World!'"
	signature, err := signScript(key, script)
	if err != nil {
		t.Fatalf("Failed to sign Script: %v", err)
	}

	req := &proto.ExecuteScriptRequest{
		Script: fmt.Sprintf("%s\n%s", signature, script),
	}

	resp, err := client.ExecuteScript(context.Background(), req)

	if resp.Status != "SCRIPT_EXECUTION_ERROR" {
		t.Errorf("Expected status 'SCRIPT_EXECUTION_ERROR', got '%s'", resp.Status)
	}

	deleteCertificate(certPath)
}

func TestIncorrectCertificate(t *testing.T) {
	key := generateRSAKeyPair()
	anotherKey := generateRSAKeyPair()

	cert := createSelfSignedCertificate(anotherKey, true)
	certPath := saveCertificate(cert)
	time.Sleep(2 * time.Second)

	script := "echo 'Hello, World!'"
	signature, err := signScript(key, script)
	if err != nil {
		t.Fatalf("Failed to sign Script: %v", err)
	}

	req := &proto.ExecuteScriptRequest{
		Script: fmt.Sprintf("%s\n%s", signature, script),
	}

	resp, err := client.ExecuteScript(context.Background(), req)

	if resp.Status != "INVALID_SIGNATURE" {
		t.Errorf("Expected status 'INVALID_SIGNATURE', got '%s'", resp.Status)
	}

	deleteCertificate(certPath)
}

func TestConcurrentRequests(t *testing.T) {
	key := generateRSAKeyPair()
	cert := createSelfSignedCertificate(key, true)
	certPath := saveCertificate(cert)
	time.Sleep(2 * time.Second)

	wg := sync.WaitGroup{}
	baseScript := "echo 'Hello, %d!'\n"
	signatures := make([]string, 10)
	for i := 0; i < 10; i++ {
		signature, err := signScript(key, fmt.Sprintf(baseScript, i))
		if err != nil {
			t.Fatalf("Failed to sign Script: %v", err)
		}
		signatures[i] = signature
	}

	worker := func(index int) {
		req := &proto.ExecuteScriptRequest{
			Script: fmt.Sprintf("%s\n%s", signatures[index], fmt.Sprintf(baseScript, index)),
		}

		resp, err := client.ExecuteScript(context.Background(), req)
		if err != nil {
			t.Errorf("Failed to execute Script: %v", err)
		}

		if resp.Status != "OK" {
			t.Errorf("Expected status 'OK', got '%s'", resp.Status)
		}

		expectedOutput := fmt.Sprintf("Hello, %d!\n", index)
		if resp.Output != expectedOutput {
			t.Errorf("Expected output '%s', got '%s'", expectedOutput, resp.Output)
		}

		wg.Done()
	}

	concurrentRequests := 10
	wg.Add(concurrentRequests)

	for i := 0; i < concurrentRequests; i++ {
		go worker(i)
	}

	wg.Wait()
	deleteCertificate(certPath)
}
