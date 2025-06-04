package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/joho/godotenv"
	"github.com/stretchr/testify/require"
	"inivisirisk.com/pse/server"
)

var (
	policyFile = "../production/policy.json"
)

func TestStart(t *testing.T) {
	godotenv.Load("../.env")
	s := server.StartServer(8081, "../policy/policies")
	defer s.Close()
	p := NewProxy(policyFile)
	go func() {
		p.Start()
	}()
	time.Sleep(time.Second)
	certPool := x509.NewCertPool()
	certPool.AddCert(p.rootCa.RootCert())
	tr := http.Transport{
		Proxy: func(r *http.Request) (*url.URL, error) {
			return r.URL.Parse("http://localhost:3128/")
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
			RootCAs:            certPool,
		},
	}
	req, _ := http.NewRequest("GET", "https://www.google.com/", nil)
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	log.Printf("response %v", resp.StatusCode)

	req, _ = http.NewRequest("GET", "https://"+self+"/start", nil)
	resp, err = tr.RoundTrip(req)
	require.NoError(t, err)
	log.Printf("response %v", resp.StatusCode)
}
