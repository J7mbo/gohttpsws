package gohttpsws

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

// Config contains the configuration required to start a webserver with TLS.
// If any of these string path values are omitted, an error will be returned at runtime.
type Config struct {
	port     string
	certPath string
	keyPath  string
	caPath   string
}

// NewConfig is used to create a Config. See Config documentation for behaviour when ommitting values.
func NewConfig(port, certPath, keyPath, caPath string) *Config {
	return &Config{port: port, certPath: certPath, keyPath: keyPath, caPath: caPath}
}

// Server takes a Config and can be used via Server.ServeDev and Server.ServeProd.
// Any pointers do not signify an optional parameter.
type Server struct {
	c *Config
}

// NewServer is used to initialise a new Server. Config is mandatory.
func NewServer(c *Config) (*Server, error) {
	if c == nil {
		return nil, errors.New("error: no configuration (port, tls settings) provided to NewServer")
	}

	return &Server{c: c}, nil
}

// TLSFileNotFound is returned when one of the certificates is not found on at the path provided by the user.
type TLSFileNotFound struct {
	Path string
}

// Error is the standard error function returning the error string from TLSFileNotFound.
func (e TLSFileNotFound) Error() string {
	return fmt.Sprintf("error loading tls file at path: %s, does it exist and is it readable?", e.Path)
}

// TLSSetup is returned when an error reading certificates as PEM etc fails.
// It's just a wrapper around the errors returned from tls.LoadX509KeyPair or CertPool.AppendCertsFromPEM.
type TLSSetup struct {
	Err error
}

// Error is the standard error function returning the error string from TLSSetup.
func (e *TLSSetup) Error() string {
	return fmt.Errorf("error setting up tls: %w", e.Err).Error()
}

// ServeDev is used for local development with custom certs.
// By appending the certificate authority provided by the user to the cert pool,
// it will be considered a trustworthy certificate when used to serve the application.
func (s *Server) ServeDev(h http.Handler) error {
	if err := ensureCertsExist(s.c.certPath, s.c.keyPath, s.c.caPath); err != nil {
		return err
	}

	cert, err := tls.LoadX509KeyPair(s.c.certPath, s.c.keyPath)
	if err != nil {
		return &TLSSetup{fmt.Errorf("failed loading X509 key pair: %w", err)}
	}

	caCert, err := ioutil.ReadFile(s.c.caPath)
	if err != nil {
		return &TLSSetup{fmt.Errorf("failed reading ca file: %w", err)}
	}

	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caCert) {
		return &TLSSetup{fmt.Errorf("failed appending ca to cert pool: %w", err)}
	}

	server := http.Server{
		Addr:    ":" + s.c.port,
		Handler: h,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      rootCAs,
		},
	}

	err = server.ListenAndServeTLS("", "")
	if err != nil {
		return err
	}

	return nil
}

// ServeProd only requires a cert and key paths, as the ca for prod is legitimate and doesn't need to be included here.
func (s *Server) ServeProd(h http.Handler) error {
	if err := ensureCertsExist(s.c.certPath, s.c.keyPath); err != nil {
		return err
	}

	if err := (&http.Server{
		Addr:    ":" + s.c.port,
		Handler: h,
	}).ListenAndServeTLS(s.c.certPath, s.c.keyPath); err != nil {
		return err
	}

	return nil
}

// ensureCertsExist returns a TLSFileNotFound given one of the cert files can't be found.
func ensureCertsExist(certPaths ...string) error {
	for _, certPath := range certPaths {
		if certPath == "" || !fileExists(certPath) {
			return &TLSFileNotFound{certPath}
		}
	}

	return nil
}

// fileExists returns whether or not the path provided exists via os.Stat.
func fileExists(path string) bool {
	_, err := os.Stat(path)

	return err == nil
}
