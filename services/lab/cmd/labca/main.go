// Command labca bootstraps the fake internet's certificate authority.
//
// The lab needs real TLS, not plaintext stand-ins, because the whole question
// is what an egress proxy can and cannot see inside an encrypted session. This
// runs once before the other services and writes a CA plus server certificates
// into the shared pki volume.
package main

import (
	"flag"
	"log"
	"os"

	"aegis/lab/internal/certs"
)

func main() {
	dir := flag.String("pki", envOr("PKI_DIR", "/pki"), "pki output directory")
	flag.Parse()
	log.SetFlags(0)

	if err := os.MkdirAll(*dir, 0o755); err != nil {
		log.Fatalf("labca: %v", err)
	}

	ca, err := certs.LoadOrCreateCA(*dir+"/lab-ca.pem", *dir+"/lab-ca.key", "Aegis Lab Root CA")
	if err != nil {
		log.Fatalf("labca: %v", err)
	}

	attackerIP := envOr("ATTACKER_IP", "172.28.0.10")
	cdnIP := envOr("CDN_IP", "172.28.0.11")

	if err := ca.WriteLeafFiles(*dir+"/attacker.pem", *dir+"/attacker.key",
		"attacker.lab",
		"*.attacker.lab",
		"evil.user.cdn.trusted.lab",
		"*.user.cdn.trusted.lab",
		attackerIP,
	); err != nil {
		log.Fatalf("labca attacker cert: %v", err)
	}

	if err := ca.WriteLeafFiles(*dir+"/site.pem", *dir+"/site.key",
		"cdn.trusted.lab",
		"*.cdn.trusted.lab",
		"docs.internal.lab",
		"*.internal.lab",
		cdnIP,
	); err != nil {
		log.Fatalf("labca site cert: %v", err)
	}

	log.Printf("lab CA ready in %s (lab-ca.pem, attacker.pem, site.pem)", *dir)
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
