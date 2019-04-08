// +build !darwin

package upstream

import "crypto/x509"

// loadRootCAs initializes cert pool for the specified certs chain
func loadRootCAs() *x509.CertPool {
	return nil
}
