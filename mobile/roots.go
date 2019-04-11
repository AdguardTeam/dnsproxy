package mobile

import "crypto/x509"

func loadSystemRootCAs() *x509.CertPool {
	// Use default implementation
	p := x509.NewCertPool()
	p.AppendCertsFromPEM([]byte(systemRootsPEM))
	return p
}
