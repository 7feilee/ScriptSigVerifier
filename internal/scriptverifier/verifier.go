package scriptverifier

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
)

var publicKeyPool map[string]*rsa.PublicKey
var publicKeyPoolLock sync.RWMutex

func VerifySignature(signature, hashedScript []byte) error {

	verified := false
	var verificationErr error

	publicKeyPoolLock.RLock()
	defer publicKeyPoolLock.RUnlock()

	for _, publicKey := range publicKeyPool {
		err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashedScript[:], signature)
		if err == nil {
			verified = true
			break
		}
		verificationErr = err
	}

	if !verified {
		return verificationErr
	}

	return nil
}

func InitPublicKeyPool(certDir string) error {
	newPublicKeyPool, err := loadPublicKeys(certDir)
	if err != nil {
		return fmt.Errorf("failed to load public keys: %v", err)
	}

	publicKeyPoolLock.Lock()
	defer publicKeyPoolLock.Unlock()
	publicKeyPool = newPublicKeyPool

	return nil
}

func loadPublicKeys(certDir string) (map[string]*rsa.PublicKey, error) {
	newPublicKeyPool := make(map[string]*rsa.PublicKey)

	files, err := ioutil.ReadDir(certDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate directory: %v", err)
	}

	for _, file := range files {
		certData, err := ioutil.ReadFile(filepath.Join(certDir, file.Name()))
		if err != nil {
			return nil, fmt.Errorf("failed to read certificate file %s: %v", file.Name(), err)
		}

		block, _ := pem.Decode(certData)
		if block == nil {
			log.Printf("Failed to parse the certificate in file %s", file.Name())
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Printf("Failed to parse certificate in file %s: %v", file.Name(), err)
			continue
		}

		if !IsCodeSigningCertificate(cert) {
			log.Printf("Certificate in file %s is not a code signing certificate", file.Name())
			continue
		}

		publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			log.Printf("Unexpected public key type in file %s", file.Name())
			continue
		}

		newPublicKeyPool[file.Name()] = publicKey
	}

	return newPublicKeyPool, nil
}

func IsCodeSigningCertificate(cert *x509.Certificate) bool {
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageCodeSigning {
			return true
		}
	}
	return false
}

func WatchCertDir(certDir string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("Failed to create watcher: %v", err)
	}
	defer watcher.Close()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Remove == fsnotify.Remove {
					log.Printf("Certificate directory modified, reloading certificates...\n")
					err := InitPublicKeyPool(certDir)
					if err != nil {
						log.Printf("Failed to update certificate pool: %v", err)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("Watcher error: %v", err)
			}
		}
	}()

	err = watcher.Add(certDir)
	if err != nil {
		log.Fatalf("Failed to watch certificate directory: %v", err)
	}
	<-done
}
