package ca

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/kairoaraujo/goca"
)

type CA struct {
	rootCa *goca.CA
	mutex  sync.Mutex
}

// Define the GOCAPTH (Default is current dir)
func NewCA() *CA {
	os.Setenv("CAPATH", "/tmp/ca")

	// RootCAIdentity for creation
	rootCAIdentity := goca.Identity{
		Organization:       "InvisiRisk, Inc.",
		OrganizationalUnit: "PSE-Proxy Certificates",
		Country:            "US",
		Locality:           "Houston",
		Province:           "Texas",
		Intermediate:       false,
	}

	// (1) Create the New Root CA or loads existent from disk ($CAPATH)
	rootCA, err := goca.New("invisirisk.com", rootCAIdentity)
	if err != nil {
		// Loads in case it exists
		fmt.Println("Loading CA")
		rootCA, err = goca.Load("invisirisk.com")
		if err != nil {
			log.Fatal(err)
		}
	}
	return &CA{
		rootCa: &rootCA,
	}
}
func (ca *CA) RootCert() *x509.Certificate {
	return ca.rootCa.GoCertificate()
}
func (ca *CA) IssueCertificate(name string) (*tls.Certificate, error) {
	ca.mutex.Lock()
	defer func() {
		ca.mutex.Unlock()
	}()
	intranetIdentity := goca.Identity{

		Intermediate: false,
		DNSNames:     []string{name},
	}
	cert, err := ca.rootCa.LoadCertificate(name)
	if err != nil {
		cert, err = ca.rootCa.IssueCertificate(name, intranetIdentity)
	}
	if err != nil {
		return nil, err

	}
	gocert, err := tls.X509KeyPair([]byte(cert.Certificate), []byte(cert.PrivateKey))
	return &gocert, err

}
