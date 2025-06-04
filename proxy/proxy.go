package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/invisirisk/clog"
	"inivisirisk.com/pse/ca"
	"inivisirisk.com/pse/policy"
	"inivisirisk.com/pse/utils"
)

// bottom proxy
type Proxy struct {
	rootCa   *ca.CA
	appProxy *http.Server
	l        *AppListner
}

var (
	cl = clog.NewCLog("proxy")
)

type proxyConn struct {
	*net.TCPConn

	remoteAddr net.Addr
}

func (c *proxyConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (p *Proxy) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	var rip string
	if r.Method == "CONNECT" {

		cl.Infof("CONNECT request for " + r.URL.String() + " from " + r.RemoteAddr)
		hj, ok := rw.(http.Hijacker)
		if !ok {
			cl.Infof("webserver doesn't support hijacking")
			http.Error(rw, "webserver doesn't support hijacking", http.StatusInternalServerError)
			return
		}
		fwd := r.Header.Get("Forwarded")
		if fwd != "" {
			cl.Infof("fowarded for %v", fwd)
			parts := strings.Split(fwd, "=")
			if len(parts) >= 2 {
				if parts[0] == "for" {
					rip = parts[1]
					cl.Infof("setting rip to %v", rip)
				}
			}
		}

		conn, bufrw, err := hj.Hijack()
		if err != nil {
			http.Error(rw, "webserver hijack returned error", http.StatusInternalServerError)
		}
		bufrw.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		bufrw.Flush()
		if rip != "" {
			addr := conn.RemoteAddr().(*net.TCPAddr)
			addr.IP = net.ParseIP(rip)
			pc := &proxyConn{
				TCPConn:    conn.(*net.TCPConn),
				remoteAddr: addr,
			}
			conn = pc
		}

		p.l.c <- conn
	}
	// handle direct requests

}

func NewProxy(policyFile string) *Proxy {
	// initialize policy
	rootCa := ca.NewCA()

	p, err := policy.NewPolicy(policyFile)
	if err != nil {
		log.Panic(err)
	}

	appList := &AppListner{
		c: make(chan net.Conn, 100),
	}

	rp := &httputil.ReverseProxy{
		Transport: &http.Transport{
			TLSClientConfig: createDynamicTLSConfig(rootCa),
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		Director: func(r *http.Request) {
			r.URL.Scheme = "https"
			r.URL.Host = r.Host
		},
		ModifyResponse: func(rsp *http.Response) error {
			// This function processes an HTTP response by setting up a context with logging,and then handling the response body through a series of utility chains for MIME type, checksum, and file size. It modifies the response based on a policy.

			// Parameters:
			//   rsp - The HTTP response to be processed.
			//
			// Returns:
			//   An error if any issues occur during processing, otherwise nil.

			ctx, cl := clog.WithCtx(rsp.Request.Context(), "response")
			cl.Infof("handling response for %v", rsp.Request.URL)

			mime_chain := &utils.MimeChain{Direction: "Download"}
			check_sum := &utils.Checksum{Direction: "Download"}
			file_size := &utils.FileSize{Direction: "Download"}
			secret,_ := utils.NewSecrets(policy.GetSecretsFilePath(),"response")
			if rsp.Body != nil {
				top := utils.ReaderChain(ctx, rsp.Body, mime_chain, check_sum, file_size, &utils.PHPCheck{Response: rsp},secret)
				rsp.Body = top
			}
			rsp_data := utils.ResponseData{Response: rsp, Mime: mime_chain.Mime, Checksum: check_sum.Checksum, FileSizeByte: file_size.ByteSize}
			ModifyResponseBasedOnPolicy(p, ctx, &rsp_data)
			return nil
		},
	}

	appProxy := &http.Server{
		Handler: &PolicyHandler{
			next: rp,
			p:    p,
		},
		TLSConfig: &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return rootCa.IssueCertificate(hello.ServerName)
			},
			NextProtos: []string{
				"h2",
				"http/1.1",
			},
		},
	}

	return &Proxy{
		rootCa:   rootCa,
		l:        appList,
		appProxy: appProxy,
	}

}

func createDynamicTLSConfig(rootCa *ca.CA) *tls.Config {
	// Create a mutex to protect concurrent access to the certificate pool
	certPoolMutex := &sync.Mutex{}

	// Create initial certificate pool
	certPool := loadCertificates(rootCa)

	// Create the TLS config with a GetConfigForClient callback
	// This callback is called for each new connection, allowing us to provide the latest certificates
	config := &tls.Config{
		MinVersion: tls.VersionTLS12, // Enforce minimum TLS version
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			// Lock to prevent concurrent modification of the cert pool
			certPoolMutex.Lock()
			defer certPoolMutex.Unlock()

			// Reload certificates for each new connection
			freshCertPool := loadCertificates(rootCa)

			// Return a new config with the fresh cert pool
			return &tls.Config{
				RootCAs:    freshCertPool,
				MinVersion: tls.VersionTLS12,
			}, nil
		},
	}

	// Set initial RootCAs
	config.RootCAs = certPool

	return config
}

func loadCertificates(rootCa *ca.CA) *x509.CertPool {
	rootCAs, err := x509.SystemCertPool()
	if err != nil || rootCAs == nil {
		// System cert pool not available, create a new one
		rootCAs = x509.NewCertPool()
		cl.Infof("System cert pool not available, created new pool: %v", err)

		// Try to load from common locations
		certFiles := []string{
			"/etc/ssl/certs/ca-certificates.crt",             // Debian/Ubuntu
			"/etc/pki/tls/certs/ca-bundle.crt",               // Fedora/RHEL
			"/etc/ssl/cert.pem",                              // Alpine/macOS
			"/etc/certs/ca-certificates.crt",                 // Docker containers
			"/usr/local/share/ca-certificates/extra/pse.crt", // Where your script puts the cert
		}

		for _, caFile := range certFiles {
			certs, err := ioutil.ReadFile(caFile)
			if err == nil {
				rootCAs.AppendCertsFromPEM(certs)
				cl.Infof("Loaded certificates from %s", caFile)
			}
		}
	}

	// Add our own root CA certificate
	if rootCa != nil && rootCa.RootCert() != nil {
		rootCAs.AddCert(rootCa.RootCert())
		cl.Infof("Added root CA certificate to pool")
	}

	return rootCAs
}

func (p *Proxy) Start() {

	// Listen on both IPv4 and IPv6 for TLS
	tlist := tls.NewListener(p.l, p.appProxy.TLSConfig)
	go func() {
		if err := p.appProxy.Serve(tlist); err != nil {
			log.Panic(err)
		}
	}()

	tlist2, err := tls.Listen("tcp4", "[::]:12345", p.appProxy.TLSConfig)
	if err != nil {
		log.Panic("TLS Listen: ", err)
	}
	go func() {
		if err := p.appProxy.Serve(tlist2); err != nil {
			log.Panic(err)
		}
	}()

	// Listen on both IPv4 and IPv6 for HTTP
	listener, err := net.Listen("tcp4", "[::]:3128")
	if err != nil {
		log.Panic("Listen: ", err)
	}
	if err := http.Serve(listener, p); err != nil {
		log.Panic("ListenAndServe: ", err)
	}
}
