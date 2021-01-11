package gohttpsws_test

import (
	"fmt"
	"github.com/j7mbo/gohttpsws"
	"github.com/stretchr/testify/suite"
	"os"
	"path/filepath"
	"testing"
)

// testCertsDir is the relative path containing certs.
const testCertsDir = "test"

type ServerTestSuite struct {
	suite.Suite
}

func TestSuite(t *testing.T) {
	suite.Run(t, new(ServerTestSuite))
}

func (s *ServerTestSuite) TestServeDev_Fails_WithInvalidCertPath() {
	// Given
	srv, _ := gohttpsws.NewServer(gohttpsws.NewConfig("80", "", "/a", "/a"))

	// When
	err := srv.ServeDev(nil)

	// Then
	s.IsType(&gohttpsws.TLSFileNotFound{}, err)
}

func (s *ServerTestSuite) TestServeDev_Fails_WithInvalidKeyPath() {
	// Given
	srv, _ := gohttpsws.NewServer(gohttpsws.NewConfig("80", "/a", "", "/a"))

	// When
	err := srv.ServeDev(nil)

	// Then
	s.IsType(&gohttpsws.TLSFileNotFound{}, err)
}

func (s *ServerTestSuite) TestServeDev_Fails_WithInvalidCaPath() {
	// Given
	srv, _ := gohttpsws.NewServer(gohttpsws.NewConfig("80", "/a", "/a", ""))

	// When
	err := srv.ServeDev(nil)

	// Then
	s.IsType(&gohttpsws.TLSFileNotFound{}, err)
}

func (s *ServerTestSuite) TestServeDev_Fails_WithInvalidCertFile() {
	certsDir, _ := os.Getwd()
	certsDir = filepath.ToSlash(fmt.Sprintf("%s/%s/", certsDir, testCertsDir))

	// Given
	srv, _ := gohttpsws.NewServer(
		gohttpsws.NewConfig("80", certsDir+"stubcert.pem", certsDir+"stubkey.pem", certsDir+"stubca.pem"),
	)

	// When
	err := srv.ServeDev(nil)

	// Then
	s.IsType(&gohttpsws.TLSSetup{}, err)
}
