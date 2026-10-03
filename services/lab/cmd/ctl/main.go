// Command ctl drives the experiment and writes the report.
//
// It lives inside the lab network so the whole run needs nothing on the host
// beyond Docker itself: no curl, no jq, no Python, no make.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"aegis/lab/internal/audit"
)

var (
	firewallAdmin = envOr("FIREWALL_ADMIN", "http://firewall:9090")
	dnsAdmin      = envOr("DNSGUARD_ADMIN", "http://dnsguard:9092")
	attackerAdmin = envOr("ATTACKER_ADMIN", "http://attacker:9091")
	siteAdmin     = envOr("SITE_ADMIN", "http://cdn:9093")
	outDir        = envOr("OUT_DIR", "/out")
)

var client = &http.Client{Timeout: 20 * time.Second}

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "wait":
		mustWait()
	case "mode":
		need(3)
		setMode(os.Args[2])
	case "scenario":
		need(3)
		setScenario(os.Args[2])
	case "reset":
		resetAll()
	case "snapshot":
		need(3)
		snapshot(os.Args[2])
	case "report":
		report()
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println(`ctl <command>

  wait                 block until every lab service answers
  mode <off|allowlist|full>
                       switch the firewall and the DNS guard together
  scenario <id>        tag subsequent audit events
  reset                clear audit logs, DLP state and collected hits
  snapshot <config>    save raw evidence for one configuration
  report               join the evidence and write report.md / report.json`)
}

func need(n int) {
	if len(os.Args) < n {
		usage()
		os.Exit(2)
	}
}

// ---------------------------------------------------------------- actions --

func mustWait() {
	targets := map[string]string{
		"firewall": firewallAdmin + "/healthz",
		"dnsguard": dnsAdmin + "/healthz",
		"attacker": attackerAdmin + "/healthz",
		"cdn":      siteAdmin + "/healthz",
	}
	deadline := time.Now().Add(90 * time.Second)
	pending := map[string]bool{}
	for k := range targets {
		pending[k] = true
	}
	for time.Now().Before(deadline) {
		for name := range pending {
			if _, err := get(targets[name]); err == nil {
				log.Printf("  ready: %s", name)
				delete(pending, name)
			}
		}
		if len(pending) == 0 {
			log.Println("all lab services ready")
			return
		}
		time.Sleep(time.Second)
	}
	names := []string{}
	for k := range pending {
		names = append(names, k)
	}
	sort.Strings(names)
	log.Fatalf("timed out waiting for: %s", strings.Join(names, ", "))
}

func setMode(m string) {
	for _, base := range []string{firewallAdmin, dnsAdmin} {
		if _, err := post(base + "/mode?m=" + m); err != nil {
			log.Fatalf("set mode on %s: %v", base, err)
		}
	}
	log.Printf("enforcement mode -> %s", m)
}

func setScenario(s string) {
	for _, base := range []string{firewallAdmin, dnsAdmin} {
		_, _ = post(base + "/scenario?s=" + s)
	}
}

func resetAll() {
	for _, base := range []string{firewallAdmin, dnsAdmin, attackerAdmin, siteAdmin} {
		if _, err := post(base + "/reset"); err != nil {
			log.Printf("reset %s: %v", base, err)
		}
	}
	log.Println("lab state cleared")
}

// Raw is the evidence captured for one configuration.
type Raw struct {
	Config    string         `json:"config"`
	Mode      string         `json:"mode"`
	Captured  time.Time      `json:"captured"`
	Firewall  []audit.Event  `json:"firewall_events"`
	DNS       []audit.Event  `json:"dns_events"`
	Hits      []any          `json:"attacker_hits"`
	Recovered []RecoveryJSON `json:"recoveries"`
}

// RecoveryJSON mirrors the attacker's verdict structure.
type RecoveryJSON struct {
	Scenario  string `json:"scenario"`
	Hits      int    `json:"hits"`
	Recovered bool   `json:"recovered"`
	Technique string `json:"technique"`
	Detail    string `json:"detail"`
	Channel   string `json:"channel"`
}

func snapshot(config string) {
	raw := Raw{Config: config, Captured: time.Now().UTC()}

	var fwStatus struct {
		Mode string `json:"mode"`
	}
	_ = getJSON(firewallAdmin+"/status", &fwStatus)
	raw.Mode = fwStatus.Mode

	var fwEvents struct {
		Events []audit.Event `json:"events"`
	}
	if err := getJSON(firewallAdmin+"/events", &fwEvents); err != nil {
		log.Printf("firewall events: %v", err)
	}
	raw.Firewall = fwEvents.Events

	var dnsEvents struct {
		Events []audit.Event `json:"events"`
	}
	if err := getJSON(dnsAdmin+"/events", &dnsEvents); err != nil {
		log.Printf("dns events: %v", err)
	}
	raw.DNS = dnsEvents.Events

	var hits struct {
		Hits []any `json:"hits"`
	}
	_ = getJSON(attackerAdmin+"/hits", &hits)
	raw.Hits = hits.Hits

	var rec struct {
		Recoveries []RecoveryJSON `json:"recoveries"`
	}
	if err := getJSON(attackerAdmin+"/recoveries", &rec); err != nil {
		log.Printf("recoveries: %v", err)
	}
	raw.Recovered = rec.Recoveries

	path := fmt.Sprintf("%s/raw-%s.json", outDir, config)
	writeJSONFile(path, raw)
	log.Printf("snapshot %s: %d firewall events, %d dns events, %d collected hits",
		config, len(raw.Firewall), len(raw.DNS), len(raw.Hits))
}

func writeJSONFile(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Fatalf("encode %s: %v", path, err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		log.Fatalf("write %s: %v", path, err)
	}
}

// ----------------------------------------------------------- http helpers --

func get(url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return b, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return b, nil
}

func post(url string) ([]byte, error) {
	resp, err := client.Post(url, "application/json", strings.NewReader("{}"))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return b, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return b, nil
}

func getJSON(url string, v any) error {
	b, err := get(url)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
