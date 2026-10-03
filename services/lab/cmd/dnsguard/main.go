// Command dnsguard is the agent container's only resolver.
//
// An HTTP allowlist is not an egress policy on its own: a resolver that answers
// anything is a covert channel, because the query name itself carries data.
// This service applies the same three enforcement levels as the HTTP proxy and
// adds hostname-specific heuristics in full mode.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"aegis/lab/internal/audit"
	"aegis/lab/internal/dlp"
	"aegis/lab/internal/dnsmsg"
	"aegis/lab/internal/policy"
)

type guard struct {
	pol      *policy.Policy
	log      *audit.Log
	dlp      *dlp.Engine
	labZone  string
	labDNS   string
	upstream []string
}

func main() {
	var (
		addr       = flag.String("addr", envOr("DNS_ADDR", ":53"), "dns listen address")
		adminAddr  = flag.String("admin", envOr("ADMIN_ADDR", ":9092"), "admin listen address")
		policyPath = flag.String("policy", envOr("POLICY_PATH", "/config/policy.json"), "policy file")
		auditPath  = flag.String("audit", envOr("AUDIT_LOG", "/out/dnsguard.jsonl"), "audit jsonl path")
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

	secrets := splitList(os.Getenv("PROTECTED_SECRETS"))
	if s := os.Getenv("AGENT_SECRET"); s != "" {
		secrets = append(secrets, s)
	}

	g := &guard{
		pol:     pol,
		log:     audit.New("dnsguard", *auditPath, 50000, true),
		labZone: strings.ToLower(snap.LabZoneSuffix),
		labDNS:  envOr("LAB_ZONE_DNS", snap.LabZoneDNS),
		dlp: dlp.New(dlp.Options{
			Secrets:           secrets,
			MinFragment:       snap.DLP.MinFragment,
			CoverageThreshold: snap.DLP.CoverageThreshold,
			WindowSeconds:     snap.DLP.WindowSeconds,
			WindowBytes:       snap.DLP.WindowBytes,
			MaxDecodeDepth:    snap.DLP.MaxDecodeDepth,
		}),
	}
	g.upstream = snap.UpstreamDNS
	if v := os.Getenv("UPSTREAM_DNS"); v != "" {
		g.upstream = splitList(v)
	}
	if len(g.upstream) == 0 {
		g.upstream = []string{"127.0.0.11:53"}
	}
	if g.labDNS == "" {
		g.labDNS = g.upstream[0]
	}

	log.Printf("dns guard: mode=%s zone=.%s zone-ns=%s upstream=%v",
		pol.Mode(), g.labZone, g.labDNS, g.upstream)

	go g.serveAdmin(*adminAddr)
	go g.serveTCP(*addr)
	g.serveUDP(*addr)
}

func (g *guard) serveUDP(addr string) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Fatalf("dns udp: %v", err)
	}
	log.Printf("dns listening on %s/udp", addr)
	buf := make([]byte, 4096)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}
		q := make([]byte, n)
		copy(q, buf[:n])
		go func() {
			if resp := g.handle(q, hostOf(src.String())); resp != nil {
				_, _ = pc.WriteTo(resp, src)
			}
		}()
	}
}

func (g *guard) serveTCP(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("dns tcp: %v", err)
		return
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			var lb [2]byte
			if _, err := readFull(c, lb[:]); err != nil {
				return
			}
			n := int(lb[0])<<8 | int(lb[1])
			if n <= 0 || n > 8192 {
				return
			}
			q := make([]byte, n)
			if _, err := readFull(c, q); err != nil {
				return
			}
			resp := g.handle(q, hostOf(c.RemoteAddr().String()))
			if resp == nil {
				return
			}
			out := append([]byte{byte(len(resp) >> 8), byte(len(resp))}, resp...)
			_, _ = c.Write(out)
		}(c)
	}
}

func readFull(c net.Conn, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := c.Read(b[got:])
		if err != nil {
			return got, err
		}
		got += n
	}
	return got, nil
}

// handle applies policy to one query and either forwards it or refuses it.
func (g *guard) handle(query []byte, client string) []byte {
	q, err := dnsmsg.ParseQuestion(query)
	if err != nil {
		return nil
	}

	ev := audit.Event{
		Client: client, Proto: "dns", Host: q.Name,
		QType: dnsmsg.TypeName(q.Type), Mode: g.pol.Mode(),
	}

	if block, reason, detail, v := g.evaluate(client, q); block {
		ev.Action, ev.Reason, ev.Detail = "block", reason, detail
		ev.Technique, ev.Coverage = v.Technique, v.Coverage
		g.log.Add(ev)
		return dnsmsg.Respond(q, dnsmsg.RcodeNXDomain, false)
	}

	resp, err := g.forward(query, q.Name)
	if err != nil {
		ev.Action, ev.Reason = "allow", "forward-failed: "+err.Error()
		g.log.Add(ev)
		return dnsmsg.Respond(q, dnsmsg.RcodeServFail, false)
	}

	ev.Action, ev.Reason = "allow", g.allowReason(q.Name)
	g.log.Add(ev)
	return resp
}

// evaluate returns true when the query must be refused.
func (g *guard) evaluate(client string, q *dnsmsg.Question) (bool, string, string, dlp.Verdict) {
	var none dlp.Verdict

	if !g.pol.AllowlistEnforced() {
		return false, "", "", none
	}

	allowed, allowReason := g.pol.HostAllowed(q.Name)

	// The allowlisted suffix is legitimate; the labels in front of it are the
	// attacker-controlled part, so that is what gets scored.
	prefix := q.Name
	if allowed {
		prefix = attackerControlled(q.Name, g.pol.MatchedPattern(q.Name))
	}

	// Observe before deciding. A query refused for its label length still
	// carries data, and feeding it to the correlation engine is what lets the
	// next query in the same tunnel be recognised as a continuation rather than
	// judged on its own, which is how a short second label used to slip past.
	var verdict dlp.Verdict
	if g.pol.StrictDNS() && prefix != "" {
		verdict = g.dlp.InspectName(client, prefix)
	}

	if !allowed {
		return true, "dns-" + allowReason, "name is not on the resolver allowlist", none
	}

	if !g.pol.StrictDNS() {
		// Allowlist-only mode stops here. A suffix match is enough, which is
		// exactly the gap an attacker-controlled subdomain walks through.
		return false, "", "", none
	}

	cfg := g.pol.Snapshot().DNS

	if len(q.Name) > cfg.MaxNameLen {
		return true, "dns:name-too-long",
			"query name is longer than the policy allows, typical of tunnelled data", none
	}
	if len(dnsmsg.Labels(q.Name)) > cfg.MaxLabels {
		return true, "dns:too-many-labels",
			"query has more labels than the policy allows", none
	}

	for _, l := range dnsmsg.Labels(prefix) {
		if len(l) > cfg.MaxLabelLen {
			return true, "dns:label-too-long",
				"label of " + itoa(len(l)) + " characters below an allowed suffix", none
		}
		if len(l) >= 12 {
			if h := dlp.Entropy(l); h > cfg.EntropyThreshold {
				return true, "dns:high-entropy-label",
					"label entropy " + ftoa(h) + " bits/char looks like encoded data", none
			}
		}
	}

	if verdict.Leak {
		return true, "dns:dlp:" + verdict.Technique, verdict.Detail, verdict
	}
	return false, "", "", none
}

// attackerControlled strips the matched allowlist suffix from a name.
func attackerControlled(name, pattern string) string {
	base := strings.TrimPrefix(pattern, "*.")
	if base == "" {
		return name
	}
	if name == base {
		return ""
	}
	return strings.TrimSuffix(name, "."+base)
}

func (g *guard) allowReason(name string) string {
	if !g.pol.AllowlistEnforced() {
		return "enforcement-off"
	}
	_, reason := g.pol.HostAllowed(name)
	return reason
}

// forward relays the raw query to the right upstream resolver.
func (g *guard) forward(query []byte, name string) ([]byte, error) {
	targets := g.upstream
	if g.labZone != "" && (name == g.labZone || strings.HasSuffix(name, "."+g.labZone)) {
		targets = append([]string{g.labDNS}, g.upstream...)
	}

	var lastErr error
	for _, t := range targets {
		c, err := net.DialTimeout("udp", t, 2*time.Second)
		if err != nil {
			lastErr = err
			continue
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write(query); err != nil {
			c.Close()
			lastErr = err
			continue
		}
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		c.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if dnsmsg.Rcode(buf[:n]) == dnsmsg.RcodeNXDomain && len(targets) > 1 && t == targets[0] {
			// Fall through to the next resolver rather than cache a miss.
			lastErr = nil
			continue
		}
		return buf[:n], nil
	}
	if lastErr == nil {
		lastErr = errNoAnswer
	}
	return nil, lastErr
}

type constErr string

func (e constErr) Error() string { return string(e) }

const errNoAnswer = constErr("no upstream answered")

// --------------------------------------------------------------- admin -----

func (g *guard) serveAdmin(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"component":  "dnsguard",
			"mode":       g.pol.Mode(),
			"scenario":   g.log.Scenario(),
			"strict_dns": g.pol.StrictDNS(),
			"zone":       g.labZone,
			"upstream":   g.upstream,
			"counts":     g.log.Counts(),
		})
	})
	mux.HandleFunc("/mode", func(w http.ResponseWriter, r *http.Request) {
		m := r.URL.Query().Get("m")
		if !g.pol.SetMode(m) {
			http.Error(w, "bad mode", http.StatusBadRequest)
			return
		}
		log.Printf("mode -> %s", m)
		writeJSON(w, map[string]any{"mode": g.pol.Mode()})
	})
	mux.HandleFunc("/scenario", func(w http.ResponseWriter, r *http.Request) {
		s := r.URL.Query().Get("s")
		g.log.SetScenario(s)
		g.dlp.Reset() // keep each scenario an independent trial
		writeJSON(w, map[string]any{"scenario": s})
	})
	mux.HandleFunc("/reset", func(w http.ResponseWriter, r *http.Request) {
		g.log.Reset()
		g.dlp.Reset()
		writeJSON(w, map[string]any{"reset": true})
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		ev := g.log.Events()
		writeJSON(w, map[string]any{"events": ev, "count": len(ev)})
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	log.Printf("dns admin on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Printf("dns admin: %v", err)
	}
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

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func itoa(n int) string { return strconv.Itoa(n) }

func ftoa(f float64) string { return strconv.FormatFloat(f, 'f', 2, 64) }
