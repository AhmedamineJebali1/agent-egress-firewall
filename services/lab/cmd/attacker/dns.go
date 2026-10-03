package main

import (
	"log"
	"net"
	"os"
	"strings"

	"aegis/lab/internal/dnsmsg"
)

// zone is a tiny authoritative server for the lab's fake internet. Every query
// under a sink suffix is also recorded as exfiltrated data, because the query
// name is the payload.
type zone struct {
	exact    map[string]net.IP
	wildcard []wildcardRec // longest suffix wins
	sinks    []string
}

type wildcardRec struct {
	suffix string
	ip     net.IP
}

func newZone() *zone {
	attackerIP := net.ParseIP(envOr("ATTACKER_IP", "172.28.0.10"))
	cdnIP := net.ParseIP(envOr("CDN_IP", "172.28.0.11"))
	firewallIP := net.ParseIP(envOr("FIREWALL_IP", "172.28.0.20"))

	z := &zone{
		exact: map[string]net.IP{
			"attacker.lab":             attackerIP,
			"exfil.attacker.lab":       attackerIP,
			"cdn.trusted.lab":          cdnIP,
			"docs.internal.lab":        cdnIP,
			"firewall.lab":             firewallIP,
			"evil.user.cdn.trusted.lab": attackerIP,
		},
		// Ordered specific-to-general.
		wildcard: []wildcardRec{
			{"user.cdn.trusted.lab", attackerIP}, // attacker-controlled subdomain
			{"attacker.lab", attackerIP},
			{"cdn.trusted.lab", cdnIP},
			{"internal.lab", cdnIP},
			{"trusted.lab", cdnIP},
		},
		// Queries under these suffixes carry data in the labels.
		sinks: []string{"attacker.lab", "user.cdn.trusted.lab"},
	}
	for _, extra := range strings.Split(os.Getenv("EXTRA_SINKS"), ",") {
		if e := strings.TrimSpace(extra); e != "" {
			z.sinks = append(z.sinks, e)
		}
	}
	return z
}

// lookup resolves a name, preferring exact records then the longest wildcard.
func (z *zone) lookup(name string) (net.IP, bool) {
	if ip, ok := z.exact[name]; ok {
		return ip, true
	}
	best := -1
	var bestIP net.IP
	for _, w := range z.wildcard {
		if name == w.suffix || strings.HasSuffix(name, "."+w.suffix) {
			if len(w.suffix) > best {
				best, bestIP = len(w.suffix), w.ip
			}
		}
	}
	if best >= 0 {
		return bestIP, true
	}
	return nil, false
}

// sinkPrefix returns the attacker-controlled labels of a query, or "" when the
// name is not under a collection suffix.
func (z *zone) sinkPrefix(name string) (string, bool) {
	for _, s := range z.sinks {
		if strings.HasSuffix(name, "."+s) {
			return strings.TrimSuffix(name, "."+s), true
		}
	}
	return "", false
}

func (a *attacker) serveDNS(addr string) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Printf("attacker dns: %v", err)
		return
	}
	log.Printf("attacker authoritative dns on %s/udp", addr)

	buf := make([]byte, 4096)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}
		q, err := dnsmsg.ParseQuestion(buf[:n])
		if err != nil {
			continue
		}

		// Record the lookup when it lands on a collection suffix.
		if prefix, ok := a.zone.sinkPrefix(q.Name); ok && prefix != "" {
			a.record(Hit{
				Channel:  "dns",
				Scenario: scenarioFromLabels(prefix),
				Via:      "dns-query",
				QName:    stripScenarioLabels(prefix),
				Remote:   src.String(),
			})
		}

		var resp []byte
		switch {
		case q.Type == dnsmsg.TypeA:
			if ip, ok := a.zone.lookup(q.Name); ok {
				resp = dnsmsg.AnswerA(q, []net.IP{ip}, 30, true)
			} else {
				resp = dnsmsg.Respond(q, dnsmsg.RcodeNXDomain, true)
			}
		case q.Type == dnsmsg.TypeTXT:
			resp = dnsmsg.AnswerTXT(q, "ok", 30, true)
		default:
			// Known name, unsupported type: NOERROR with no answers, which is
			// what stops a resolver from retrying forever.
			if _, ok := a.zone.lookup(q.Name); ok {
				resp = dnsmsg.Respond(q, dnsmsg.RcodeNoError, true)
			} else {
				resp = dnsmsg.Respond(q, dnsmsg.RcodeNXDomain, true)
			}
		}
		_, _ = pc.WriteTo(resp, src)
	}
}

// scenarioFromLabels pulls the "s-<id>" marker the harness plants so DNS hits
// can be attributed to an experiment.
func scenarioFromLabels(prefix string) string {
	for _, l := range strings.Split(prefix, ".") {
		if strings.HasPrefix(l, "s-") && len(l) > 2 {
			return strings.ReplaceAll(l[2:], "-", "_")
		}
	}
	return ""
}

// stripScenarioLabels removes the marker so it cannot pollute reconstruction.
func stripScenarioLabels(prefix string) string {
	var keep []string
	for _, l := range strings.Split(prefix, ".") {
		if strings.HasPrefix(l, "s-") {
			continue
		}
		keep = append(keep, l)
	}
	return strings.Join(keep, ".")
}
