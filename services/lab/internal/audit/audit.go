// Package audit is the shared structured event log. Every allow and every
// block is recorded here, which is what turns the demo into measurable data.
package audit

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"
)

// Event is one egress decision.
type Event struct {
	Seq       int       `json:"seq"`
	TS        time.Time `json:"ts"`
	Component string    `json:"component"`
	Mode      string    `json:"mode"`
	Scenario  string    `json:"scenario"`
	Client    string    `json:"client"`
	Proto     string    `json:"proto"`
	Host      string    `json:"host"`
	Port      string    `json:"port,omitempty"`
	Method    string    `json:"method,omitempty"`
	Path      string    `json:"path,omitempty"`
	QType     string    `json:"qtype,omitempty"`
	Action    string    `json:"action"`
	Reason    string    `json:"reason"`
	Technique string    `json:"technique,omitempty"`
	Coverage  float64   `json:"coverage,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	Bytes     int       `json:"bytes,omitempty"`
	Inspected bool      `json:"inspected"`
}

// Log keeps a bounded in-memory ring plus an optional JSONL file.
type Log struct {
	mu        sync.RWMutex
	events    []Event
	max       int
	seq       int
	file      *os.File
	enc       *json.Encoder
	component string
	scenario  string
	echo      bool
}

// New creates a log. path may be empty to skip file output.
func New(component, path string, max int, echo bool) *Log {
	l := &Log{max: max, component: component, echo: echo}
	if l.max <= 0 {
		l.max = 20000
	}
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err == nil {
			l.file = f
			l.enc = json.NewEncoder(f)
		} else {
			log.Printf("audit: cannot open %s: %v", path, err)
		}
	}
	return l
}

// SetScenario tags subsequent events with an experiment label.
func (l *Log) SetScenario(s string) {
	l.mu.Lock()
	l.scenario = s
	l.mu.Unlock()
}

// Scenario returns the current experiment label.
func (l *Log) Scenario() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.scenario
}

// Add records an event, filling in component, scenario and sequence.
func (l *Log) Add(e Event) Event {
	l.mu.Lock()
	l.seq++
	e.Seq = l.seq
	e.TS = time.Now().UTC()
	e.Component = l.component
	if e.Scenario == "" {
		e.Scenario = l.scenario
	}
	l.events = append(l.events, e)
	if len(l.events) > l.max {
		l.events = l.events[len(l.events)-l.max:]
	}
	enc, f, echo := l.enc, l.file, l.echo
	l.mu.Unlock()

	if enc != nil {
		_ = enc.Encode(e)
		_ = f.Sync()
	}
	if echo {
		icon := "ALLOW"
		if e.Action == "block" {
			icon = "BLOCK"
		}
		log.Printf("%s %-5s %-6s %s%s %s", icon, e.Proto, e.Method, e.Host, e.Path, e.Reason)
	}
	return e
}

// Events returns a copy of the ring.
func (l *Log) Events() []Event {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]Event, len(l.events))
	copy(out, l.events)
	return out
}

// Reset clears the ring. The JSONL file is left intact as a run archive.
func (l *Log) Reset() {
	l.mu.Lock()
	l.events = nil
	l.seq = 0
	l.mu.Unlock()
}

// Counts summarises allow/block totals for the status endpoint.
func (l *Log) Counts() map[string]int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	c := map[string]int{"total": len(l.events), "allow": 0, "block": 0}
	for _, e := range l.events {
		c[e.Action]++
	}
	return c
}
