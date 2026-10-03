// Command firewall is the egress control point. The agent container has no
// route to the internet; this process is the only way out.
//
// Three enforcement levels can be switched at runtime through the admin API,
// which is what lets one running stack produce a three-column comparison:
//
//	off        no enforcement (control group)
//	allowlist  destination allowlist, TLS tunnelled blind
//	full       allowlist + TLS interception + DLP
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"aegis/lab/internal/audit"
	"aegis/lab/internal/certs"
	"aegis/lab/internal/dlp"
	"aegis/lab/internal/policy"
	"aegis/lab/internal/webui"
)

type firewall struct {
	pol       *policy.Policy
	log       *audit.Log
	dlp       *dlp.Engine
	ca        *certs.CA
	upstream  *x509.CertPool
	startedAt time.Time
}

func main() {
	var (
		proxyAddr  = flag.String("proxy", envOr("PROXY_ADDR", ":8080"), "proxy listen address")
		adminAddr  = flag.String("admin", envOr("ADMIN_ADDR", ":9090"), "admin listen address")
		policyPath = flag.String("policy", envOr("POLICY_PATH", "/config/policy.json"), "policy file")
		pkiDir     = flag.String("pki", envOr("PKI_DIR", "/pki"), "pki directory")
		auditPath  = flag.String("audit", envOr("AUDIT_LOG", "/out/firewall.jsonl"), "audit jsonl path")
	)
	flag.Parse()
	log.SetFlags(log.Ltime)

	pol, err := policy.Load(*policyPath)
	if err != nil {
		log.Fatalf("policy: %v", err)
	}
	if m := os.Getenv("FIREWALL_MODE"); m != "" {
		pol.SetMode(m)
	}
	snap := pol.Snapshot()

	ca, err := certs.LoadOrCreateCA(
		*pkiDir+"/mitm-ca.pem", *pkiDir+"/mitm-ca.key",
		"Aegis Egress Firewall Interception CA")
	if err != nil {
		log.Fatalf("interception CA: %v", err)
	}

	secrets := splitList(os.Getenv("PROTECTED_SECRETS"))
	if s := os.Getenv("AGENT_SECRET"); s != "" {
		secrets = append(secrets, s)
	}

	fw := &firewall{
		pol: pol,
		log: audit.New("firewall", *auditPath, 50000, true),
		ca:  ca,
		dlp: dlp.New(dlp.Options{
			Secrets:           secrets,
			Patterns:          snap.DLP.Patterns,
			MinFragment:       snap.DLP.MinFragment,
			CoverageThreshold: snap.DLP.CoverageThreshold,
			WindowSeconds:     snap.DLP.WindowSeconds,
			WindowBytes:       snap.DLP.WindowBytes,
			MaxDecodeDepth:    snap.DLP.MaxDecodeDepth,
		}),
		upstream:  certs.PoolFrom(*pkiDir+"/lab-ca.pem", *pkiDir+"/mitm-ca.pem"),
		startedAt: time.Now(),
	}

	log.Printf("egress firewall: mode=%s allowlist=%d canaries=%d",
		pol.Mode(), len(snap.Allowlist), fw.dlp.Secrets())
	log.Printf("proxy on %s, admin console on %s", *proxyAddr, *adminAddr)

	go func() {
		srv := &http.Server{
			Addr:              *adminAddr,
			Handler:           fw.adminMux(),
			ReadHeaderTimeout: 10 * time.Second,
		}
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("admin: %v", err)
		}
	}()

	srv := &http.Server{
		Addr:              *proxyAddr,
		Handler:           http.HandlerFunc(fw.handle),
		ReadHeaderTimeout: 30 * time.Second,
		// The proxy must not force HTTP/2 on the client side.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("proxy: %v", err)
	}
}

// ------------------------------------------------------------- admin API ---

func (f *firewall) adminMux() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(webui.Dashboard))
	})

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		snap := f.pol.Snapshot()
		writeJSON(w, map[string]any{
			"component":     "firewall",
			"mode":          f.pol.Mode(),
			"scenario":      f.log.Scenario(),
			"tls_intercept": f.pol.TLSIntercept(),
			"dlp":           f.pol.DLPEnabled(),
			"allowlist":     snap.Allowlist,
			"secrets":       f.dlp.Secrets(),
			"counts":        f.log.Counts(),
			"uptime_s":      int(time.Since(f.startedAt).Seconds()),
		})
	})

	mux.HandleFunc("/mode", func(w http.ResponseWriter, r *http.Request) {
		m := r.URL.Query().Get("m")
		if m == "" {
			m = r.FormValue("mode")
		}
		if !f.pol.SetMode(m) {
			http.Error(w, "bad mode: use off|allowlist|full", http.StatusBadRequest)
			return
		}
		log.Printf("mode -> %s", m)
		writeJSON(w, map[string]any{"mode": f.pol.Mode()})
	})

	mux.HandleFunc("/scenario", func(w http.ResponseWriter, r *http.Request) {
		s := r.URL.Query().Get("s")
		f.log.SetScenario(s)
		// Each scenario is an independent trial. Clearing the correlation
		// window stops fragments from an earlier experiment making a later one
		// look detectable when it was not.
		f.dlp.Reset()
		writeJSON(w, map[string]any{"scenario": s})
	})

	mux.HandleFunc("/reset", func(w http.ResponseWriter, r *http.Request) {
		f.log.Reset()
		f.dlp.Reset()
		writeJSON(w, map[string]any{"reset": true})
	})

	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		ev := f.log.Events()
		writeJSON(w, map[string]any{"events": ev, "count": len(ev)})
	})

	mux.HandleFunc("/ca", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(f.ca.PEM)
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func clientIP(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}
