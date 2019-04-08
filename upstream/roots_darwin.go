package upstream

import (
	"crypto/x509"
	"os/exec"
	"path"
	"sync"

	homedir "github.com/mitchellh/go-homedir"
)

var rootCAsOnce sync.Once  // nolint
var rootCAs *x509.CertPool // nolint
var rootCAsErr error       // nolint

// loadRootCAs initializes cert pool for the specified certs chain
// for some reason this implementation is much more memory-efficient than the native SystemCertPool() call
func loadRootCAs() (*x509.CertPool, error) {
	rootCAsOnce.Do(initRootCAs)
	return rootCAs, rootCAsErr
}

func initRootCAs() {
	rootCAs = x509.NewCertPool()

	for _, keychain := range certKeychains() {
		err := addCertsFromKeychain(rootCAs, keychain)
		if err != nil {
			rootCAs = nil
			rootCAsErr = err
			return
		}
	}
}

func addCertsFromKeychain(pool *x509.CertPool, keychain string) error {
	cmd := exec.Command("/usr/bin/security", "find-certificate", "-a", "-p", keychain)
	data, err := cmd.Output()
	if err != nil {
		return err
	}

	pool.AppendCertsFromPEM(data)

	return nil
}

func certKeychains() []string {
	keychains := []string{
		"/System/Library/Keychains/SystemRootCertificates.keychain",
		"/Library/Keychains/System.keychain",
	}
	home, err := homedir.Dir()
	if err == nil {
		loginKeychain := path.Join(home, "Library", "Keychains", "login.keychain")
		keychains = append(keychains, loginKeychain)
	}
	return keychains
}
