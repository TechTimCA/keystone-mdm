// Command keystone runs the Keystone MDM server.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TechTimCA/keystone-mdm/internal/pki"
	"github.com/TechTimCA/keystone-mdm/internal/store"
	"github.com/TechTimCA/keystone-mdm/internal/web"
	"github.com/TechTimCA/keystone-mdm/internal/wmdm"
)

var version = "dev"

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func must(key string) string {
	v := env(key, "")
	if v == "" {
		log.Fatalf("keystone: %s is required (see README)", key)
	}
	return v
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("keystone ")

	publicURL := strings.TrimRight(must("KEYSTONE_PUBLIC_URL"), "/")
	dataDir := env("KEYSTONE_DATA_DIR", "./data")
	org := env("KEYSTONE_ORG_NAME", "My Office")
	addr := env("KEYSTONE_LISTEN", ":8080")
	certFile, keyFile := env("KEYSTONE_TLS_CERT", ""), env("KEYSTONE_TLS_KEY", "")

	ca, err := pki.LoadOrCreate(filepath.Join(dataDir, "pki"), org)
	if err != nil {
		log.Fatalf("pki: %v", err)
	}
	st, err := store.Open(filepath.Join(dataDir, "keystone.json"))
	if err != nil {
		log.Fatalf("store: %v", err)
	}

	mux := http.NewServeMux()
	mdm := &wmdm.Server{
		PublicURL:     publicURL,
		EnrollSecret:  must("KEYSTONE_ENROLL_SECRET"),
		OrgName:       org,
		CA:            ca,
		Store:         st,
		TrustProxyTLS: certFile == "",
	}
	mdm.Register(mux)
	(&web.UI{
		Store:     st,
		PublicURL: publicURL,
		OrgName:   org,
		AdminUser: env("KEYSTONE_ADMIN_USER", "admin"),
		AdminPass: must("KEYSTONE_ADMIN_PASSWORD"),
	}).Register(mux)

	srv := &http.Server{
		Addr:              addr,
		Handler:           logRequests(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("Keystone MDM %s for %q listening on %s (public URL %s)", version, org, addr, publicURL)

	if certFile != "" {
		// Direct TLS: ask PCs for their Keystone client certificate on the
		// management endpoint (verified per request against our CA).
		pool := x509.NewCertPool()
		pool.AddCert(ca.Cert)
		srv.TLSConfig = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool, MinVersion: tls.VersionTLS12}
		log.Fatal(srv.ListenAndServeTLS(certFile, keyFile))
	}
	log.Printf("TLS is handled by your reverse proxy; device client certificates are not checked (see README security notes)")
	log.Fatal(srv.ListenAndServe())
}

func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h.ServeHTTP(w, r)
		if !strings.HasPrefix(r.URL.Path, "/healthz") {
			log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
		}
	})
}
