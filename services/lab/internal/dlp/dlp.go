// Package dlp implements the data-loss-prevention engine the egress firewall
// uses once TLS is intercepted and request bodies become visible.
//
// The design assumption is that an attacker who controls the agent's input also
// controls the *encoding* of the exfiltrated secret, so matching the literal
// string is close to useless. The engine therefore works in three layers:
//
//  1. Views. Every payload is expanded into decoded "views": percent, JSON,
//     HTML entity, zero-width, char-code, rot13, reverse, and a recursive
//     base64/base32/hex/gzip/zlib blob decoder.
//  2. Normalised matching. Each view is stripped to [a-z0-9] before comparison,
//     which defeats spacing, punctuation and separator tricks.
//  3. Correlation. Views are retained in a per-client sliding window and
//     concatenated view-by-view, so a secret split across many small requests
//     reassembles. Partial reassembly is scored by character coverage.
package dlp

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Verdict is the result of inspecting one payload.
type Verdict struct {
	Leak      bool    `json:"leak"`
	Technique string  `json:"technique"`
	View      string  `json:"view"`
	Detail    string  `json:"detail"`
	Coverage  float64 `json:"coverage"`
	Matched   string  `json:"matched"`
}

type entry struct {
	at    time.Time
	views map[string]string
}

// Engine is safe for concurrent use.
type Engine struct {
	mu sync.Mutex

	secrets     []string
	secretsNorm []string
	patterns    []*regexp.Regexp
	patternSrc  []string

	minFragment  int
	coverageMin  float64
	windowDur    time.Duration
	windowBytes  int
	decodeDepth  int
	maxViewBytes int

	windows map[string][]entry
}

// Options configures a new Engine.
type Options struct {
	Secrets           []string
	Patterns          []string
	MinFragment       int
	CoverageThreshold float64
	WindowSeconds     int
	WindowBytes       int
	MaxDecodeDepth    int
}

// New builds an engine. Invalid regexes are skipped rather than fatal so a
// typo in the policy file cannot take the firewall down.
func New(o Options) *Engine {
	e := &Engine{
		minFragment:  o.MinFragment,
		coverageMin:  o.CoverageThreshold,
		windowDur:    time.Duration(o.WindowSeconds) * time.Second,
		windowBytes:  o.WindowBytes,
		decodeDepth:  o.MaxDecodeDepth,
		maxViewBytes: 32 * 1024,
		windows:      map[string][]entry{},
	}
	if e.minFragment < 2 {
		e.minFragment = 3
	}
	if e.coverageMin <= 0 {
		e.coverageMin = 0.5
	}
	if e.windowDur <= 0 {
		e.windowDur = 15 * time.Minute
	}
	if e.windowBytes <= 0 {
		e.windowBytes = 256 * 1024
	}
	if e.decodeDepth <= 0 {
		e.decodeDepth = 2
	}
	for _, s := range o.Secrets {
		s = strings.TrimSpace(s)
		if len(s) < 6 {
			continue
		}
		e.secrets = append(e.secrets, s)
		e.secretsNorm = append(e.secretsNorm, normalize(s))
	}
	for _, p := range o.Patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			continue
		}
		e.patterns = append(e.patterns, re)
		e.patternSrc = append(e.patternSrc, p)
	}
	return e
}

// Secrets reports how many canaries are loaded (used by the status endpoint).
func (e *Engine) Secrets() int { return len(e.secrets) }

// Reset clears correlation state between experiment runs.
func (e *Engine) Reset() {
	e.mu.Lock()
	e.windows = map[string][]entry{}
	e.mu.Unlock()
}

// Inspect records a payload against the client's window and reports whether a
// secret is leaving, directly or by reassembly.
func (e *Engine) Inspect(client, payload string) Verdict {
	views := e.buildViews(payload)

	// Layers 1 and 2: single-payload detection.
	if v, ok := e.matchViews(views, ""); ok {
		e.remember(client, views)
		return v
	}

	// Generic secret-shaped material, independent of the planted canary.
	for i, re := range e.patterns {
		for _, name := range sortedKeys(views) {
			if m := re.FindString(views[name]); m != "" {
				e.remember(client, views)
				return Verdict{
					Leak:      true,
					Technique: "pattern",
					View:      name,
					Detail:    "matched secret-shaped pattern " + e.patternSrc[i],
					Coverage:  1,
					Matched:   Redact(m),
				}
			}
		}
	}

	// Layer 3: correlation across the sliding window.
	e.remember(client, views)
	return e.correlate(client)
}

// InspectName is the DNS-side entry point. Labels are joined before matching
// because the dots are an attacker-chosen separator, not data.
func (e *Engine) InspectName(client, name string) Verdict {
	return e.Inspect(client, name+"\n"+strings.ReplaceAll(name, ".", ""))
}

func (e *Engine) remember(client string, views map[string]string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.windows[client] = e.trim(append(e.windows[client], entry{at: time.Now(), views: views}))
}

func (e *Engine) trim(w []entry) []entry {
	cutoff := time.Now().Add(-e.windowDur)
	i := 0
	for i < len(w) && w[i].at.Before(cutoff) {
		i++
	}
	w = w[i:]
	total := 0
	for j := len(w) - 1; j >= 0; j-- {
		for _, v := range w[j].views {
			total += len(v)
		}
		if total > e.windowBytes {
			return w[j+1:]
		}
	}
	return w
}

// correlate concatenates each view across the window and looks for a secret
// that no single request contained on its own.
func (e *Engine) correlate(client string) Verdict {
	e.mu.Lock()
	w := append([]entry(nil), e.windows[client]...)
	e.mu.Unlock()

	if len(w) < 2 {
		return Verdict{}
	}

	names := map[string]bool{}
	for _, en := range w {
		for n := range en.views {
			names[n] = true
		}
	}

	joined := make(map[string]string, len(names))
	for n := range names {
		var sb strings.Builder
		for _, en := range w {
			if v, ok := en.views[n]; ok {
				sb.WriteString(v)
			}
		}
		joined[n] = sb.String()
	}

	if v, ok := e.matchViews(joined, "chunked:"); ok {
		v.Detail = "secret reassembled from " + strconv.Itoa(len(w)) + " separate requests"
		return v
	}

	// No full reassembly: score partial coverage so slow drips still alert.
	best := Verdict{}
	for _, name := range sortedKeys(joined) {
		norm := normalize(joined[name])
		for si, sec := range e.secretsNorm {
			cov, frags := e.coverage(sec, norm)
			if cov > best.Coverage {
				best = Verdict{
					Leak:      cov >= e.coverageMin,
					Technique: "chunked-partial",
					View:      name,
					Coverage:  cov,
					Detail:    "fragments of the secret seen across requests (" + strconv.Itoa(frags) + " fragments)",
					Matched:   Redact(e.secrets[si]),
				}
			}
		}
	}
	if best.Leak {
		return best
	}
	return Verdict{}
}

// coverage reports the fraction of the secret's characters that appear in text
// as runs of at least minFragment characters.
func (e *Engine) coverage(secret, text string) (float64, int) {
	if secret == "" || text == "" {
		return 0, 0
	}
	covered := make([]bool, len(secret))
	frags := 0
	for i := 0; i < len(secret); i++ {
		best := 0
		for l := len(secret) - i; l >= e.minFragment; l-- {
			if strings.Contains(text, secret[i:i+l]) {
				best = l
				break
			}
		}
		if best >= e.minFragment {
			frags++
			for k := i; k < i+best; k++ {
				covered[k] = true
			}
			i += best - 1
		}
	}
	n := 0
	for _, c := range covered {
		if c {
			n++
		}
	}
	return float64(n) / float64(len(secret)), frags
}

func (e *Engine) matchViews(views map[string]string, prefix string) (Verdict, bool) {
	for _, name := range sortedKeys(views) {
		text := views[name]
		if text == "" {
			continue
		}
		norm := normalize(text)
		for i, sec := range e.secrets {
			hit := strings.Contains(text, sec)
			if !hit && e.secretsNorm[i] != "" {
				hit = strings.Contains(norm, e.secretsNorm[i])
			}
			if hit {
				return Verdict{
					Leak:      true,
					Technique: prefix + techniqueFor(name),
					View:      name,
					Coverage:  1,
					Detail:    "secret recovered from view " + name,
					Matched:   Redact(sec),
				}, true
			}
		}
	}
	return Verdict{}, false
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func techniqueFor(view string) string {
	switch {
	case view == "raw":
		return "plaintext"
	case strings.HasPrefix(view, "dec:"):
		return strings.TrimPrefix(view, "dec:")
	default:
		return view
	}
}

// ---------------------------------------------------------------- views ----

// budget caps total decode attempts per payload so a hostile body cannot turn
// the firewall into a CPU sink.
type budget struct{ n int }

func (b *budget) take() bool {
	if b.n <= 0 {
		return false
	}
	b.n--
	return true
}

// buildViews expands one payload into every readable form of itself.
//
// Order matters here. A character-level transform such as zero-width decoding
// has to run on top of transport decoding, not only on the raw bytes: a Python
// client serialising JSON with ensure_ascii turns invisible characters into
// literal ​ sequences, so the zero-width payload only becomes visible
// after the JSON escapes are resolved.
func (e *Engine) buildViews(payload string) map[string]string {
	if len(payload) > e.maxViewBytes {
		payload = payload[:e.maxViewBytes]
	}
	views := map[string]string{}

	add := func(name, text string) {
		if text == "" || len(text) > e.maxViewBytes {
			return
		}
		if old, exists := views[name]; exists {
			if !strings.Contains(old, text) {
				views[name] = old + "\n" + text
			}
			return
		}
		views[name] = text
	}

	// Transport-level decodings of the whole payload. Each becomes a base that
	// the character-level transforms then run against.
	bases := map[string]string{"raw": payload}
	// Both percent depths matter: decoding twice resolves %2543, but it also
	// destroys a single-encoded view, so keep each one.
	if once := percentDecode(payload); once != "" {
		bases["percent"] = once
		if twice := percentDecode(once); twice != "" {
			bases["percent2"] = twice
		}
	}
	if v := jsonUnescape(payload); v != "" {
		bases["jsonesc"] = v
	}
	if v := htmlEntityDecode(payload); v != "" {
		bases["htmlent"] = v
	}

	name := func(base, transform string) string {
		if base == "raw" {
			return transform
		}
		return base + "+" + transform
	}

	var seeds []string
	for bn, base := range bases {
		add(bn, base)
		seeds = append(seeds, bn)

		if v := stripZeroWidth(base); v != "" {
			add(name(bn, "zwstrip"), v)
			seeds = append(seeds, name(bn, "zwstrip"))
		}
		if v := zeroWidthBits(base); v != "" {
			add(name(bn, "zwbits"), v)
		}
		if v := charCodeDecode(base); v != "" {
			add(name(bn, "charcode"), v)
		}
		add(name(bn, "rot13"), rot13(base))
		add(name(bn, "reverse"), reverse(base))
		seeds = append(seeds, name(bn, "reverse"))
	}

	// Recursive blob decoding over the useful seeds.
	bg := &budget{n: 4000}
	sort.Strings(seeds)
	for _, seed := range seeds {
		text, ok := views[seed]
		if !ok || text == "" {
			continue
		}
		for dn, dv := range e.decodeBlobs(text, e.decodeDepth, bg) {
			if seed == "raw" {
				add("dec:"+dn, dv)
			} else {
				add("dec:"+seed+"+"+dn, dv)
			}
		}
	}
	return views
}

var blobRe = regexp.MustCompile(`[A-Za-z0-9+/_=-]{8,}`)

// decodeBlobs finds encoded-looking runs and decodes them, following chains
// such as base64(gzip(secret)) up to the configured depth.
func (e *Engine) decodeBlobs(text string, depth int, bg *budget) map[string]string {
	out := map[string]string{}
	if depth <= 0 || text == "" || bg.n <= 0 {
		return out
	}

	// Take distinct candidates, longest first. Request headers contribute many
	// short tokens, and an encoded secret is long, so length is a better
	// priority than position when the budget runs out.
	seen := map[string]bool{}
	var blobs []string
	for _, b := range blobRe.FindAllString(text, 512) {
		if seen[b] {
			continue
		}
		seen[b] = true
		blobs = append(blobs, b)
	}
	sort.SliceStable(blobs, func(i, j int) bool { return len(blobs[i]) > len(blobs[j]) })
	if len(blobs) > 40 {
		blobs = blobs[:40]
	}
	// Also try the payload as one token: some bodies are a single long blob
	// broken up by characters the regex excludes.
	if compact := stripSpace(text); len(compact) >= 8 && len(compact) <= 8192 {
		blobs = append(blobs, compact)
	}

	appendOut := func(name, val string) {
		if val == "" || len(out[name]) > e.maxViewBytes {
			return
		}
		out[name] += val + "\n"
	}

	for _, b := range blobs {
		if len(b) > 8192 {
			b = b[:8192]
		}
		for dn, dec := range tryDecoders(b, bg) {
			if !looksUseful(dec) {
				continue
			}
			appendOut(dn, dec)
			for sn, sv := range e.decodeBlobs(dec, depth-1, bg) {
				appendOut(dn+"+"+sn, sv)
			}
		}
	}
	return out
}

// tryDecoders runs every transport codec we know against one token.
func tryDecoders(b string, bg *budget) map[string]string {
	out := map[string]string{}
	keep := func(name string, raw []byte, err error) {
		if err != nil || len(raw) == 0 {
			return
		}
		if _, seen := out[name]; !seen {
			out[name] = string(raw)
		}
	}
	if !bg.take() {
		return out
	}

	trimmed := strings.TrimRight(b, "=")
	upper := strings.ToUpper(trimmed)

	raw, err := decodeB64(base64.StdEncoding, b)
	keep("b64", raw, err)
	raw, err = decodeB64(base64.RawStdEncoding, trimmed)
	keep("b64", raw, err)
	raw, err = decodeB64(base64.URLEncoding, b)
	keep("b64url", raw, err)
	raw, err = decodeB64(base64.RawURLEncoding, trimmed)
	keep("b64url", raw, err)
	raw, err = decodeB32(base32.StdEncoding.WithPadding(base32.NoPadding), upper)
	keep("b32", raw, err)
	raw, err = decodeB32(base32.HexEncoding.WithPadding(base32.NoPadding), upper)
	keep("b32hex", raw, err)
	if len(b)%2 == 0 {
		raw, err = decodeHex(b)
		keep("hex", raw, err)
	}

	// Container formats, applied to whatever the codecs produced.
	for n, v := range cloneMap(out) {
		if g, gerr := gunzip([]byte(v)); gerr == nil {
			keep(n+"+gzip", g, nil)
		}
		if z, zerr := unzlib([]byte(v)); zerr == nil {
			keep(n+"+zlib", z, nil)
		}
	}
	return out
}

func cloneMap(m map[string]string) map[string]string {
	c := make(map[string]string, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

func decodeB64(enc *base64.Encoding, s string) ([]byte, error) {
	if len(s) < 8 {
		return nil, io.EOF
	}
	return enc.DecodeString(s)
}

func decodeB32(enc *base32.Encoding, s string) ([]byte, error) {
	if len(s) < 8 {
		return nil, io.EOF
	}
	return enc.DecodeString(s)
}

func decodeHex(s string) ([]byte, error) {
	if len(s) < 8 {
		return nil, io.EOF
	}
	return hex.DecodeString(s)
}

func gunzip(b []byte) ([]byte, error) {
	if len(b) < 2 || b[0] != 0x1f || b[1] != 0x8b {
		return nil, io.EOF
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(io.LimitReader(zr, 1<<20))
}

func unzlib(b []byte) ([]byte, error) {
	if len(b) < 2 || b[0] != 0x78 {
		return nil, io.EOF
	}
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(io.LimitReader(zr, 1<<20))
}

// looksUseful filters out the noise that speculative decoding produces.
func looksUseful(s string) bool {
	if len(s) < 3 || len(s) > 1<<20 {
		return false
	}
	if s[0] == 0x1f && len(s) > 1 && s[1] == 0x8b {
		return true // gzip container
	}
	if s[0] == 0x78 {
		return true // zlib container
	}
	printable, total := 0, 0
	for _, r := range s {
		total++
		if r == '\n' || r == '\t' || r == '\r' || (r >= 0x20 && r < 0x7f) {
			printable++
		}
	}
	return total > 0 && float64(printable)/float64(total) > 0.7
}

// --------------------------------------------------------- transformers ----

func normalize(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// Normalize is exported for tests and for the attacker-side reconstruction.
func Normalize(s string) string { return normalize(s) }

func stripSpace(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if !unicode.IsSpace(r) {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func percentDecode(s string) string {
	if !strings.Contains(s, "%") && !strings.Contains(s, "+") {
		return ""
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				sb.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		if s[i] == '+' {
			sb.WriteByte(' ')
			continue
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

var jsonEscRe = regexp.MustCompile(`\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})`)

func jsonUnescape(s string) string {
	if !strings.Contains(s, `\u`) && !strings.Contains(s, `\x`) {
		return ""
	}
	return jsonEscRe.ReplaceAllStringFunc(s, func(m string) string {
		h := strings.TrimPrefix(strings.TrimPrefix(m, `\u`), `\x`)
		v, err := strconv.ParseInt(h, 16, 32)
		if err != nil {
			return m
		}
		return string(rune(v))
	})
}

var htmlEntRe = regexp.MustCompile(`&#(x?)([0-9a-fA-F]{1,6});`)

func htmlEntityDecode(s string) string {
	if !strings.Contains(s, "&#") {
		return ""
	}
	return htmlEntRe.ReplaceAllStringFunc(s, func(m string) string {
		p := htmlEntRe.FindStringSubmatch(m)
		base := 10
		if p[1] == "x" {
			base = 16
		}
		v, err := strconv.ParseInt(p[2], base, 32)
		if err != nil {
			return m
		}
		return string(rune(v))
	})
}

const (
	zwSpace rune = 0x200B // zero-width space, used as bit 0
	zwNJ    rune = 0x200C // zero-width non-joiner, used as bit 1
	zwJ     rune = 0x200D // zero-width joiner
	zwBOM   rune = 0xFEFF // byte-order mark
	zwWJ    rune = 0x2060 // word joiner
)

func isZeroWidth(r rune) bool {
	return r == zwSpace || r == zwNJ || r == zwJ || r == zwBOM || r == zwWJ
}

func stripZeroWidth(s string) string {
	found := false
	var sb strings.Builder
	for _, r := range s {
		if isZeroWidth(r) {
			found = true
			continue
		}
		sb.WriteRune(r)
	}
	if !found {
		return ""
	}
	return sb.String()
}

// zeroWidthBits decodes the "invisible text" smuggling scheme where each bit of
// the payload is a zero-width space or zero-width non-joiner.
func zeroWidthBits(s string) string {
	var bits strings.Builder
	for _, r := range s {
		switch r {
		case zwSpace:
			bits.WriteByte('0')
		case zwNJ:
			bits.WriteByte('1')
		}
	}
	b := bits.String()
	if len(b) < 16 {
		return ""
	}
	var sb strings.Builder
	for i := 0; i+8 <= len(b); i += 8 {
		v, err := strconv.ParseUint(b[i:i+8], 2, 8)
		if err != nil {
			return ""
		}
		sb.WriteByte(byte(v))
	}
	return sb.String()
}

var (
	charCodeRe = regexp.MustCompile(`\d{1,3}(?:[,;:|\s-]+\d{1,3}){5,}`)
	nonDigitRe = regexp.MustCompile(`[^\d]+`)
)

// charCodeDecode handles "67,65,78,65..." style numeric encodings.
func charCodeDecode(s string) string {
	var sb strings.Builder
	for _, run := range charCodeRe.FindAllString(s, 16) {
		for _, p := range nonDigitRe.Split(run, -1) {
			if p == "" {
				continue
			}
			v, err := strconv.Atoi(p)
			if err != nil || v < 9 || v > 126 {
				continue
			}
			sb.WriteByte(byte(v))
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

func rot13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		}
		return r
	}, s)
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// Redact keeps logs useful without reprinting the secret in full.
func Redact(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}

// Entropy returns the Shannon entropy of a string in bits per character. The
// DNS guard uses it to spot encoded payloads hidden in hostname labels.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}
