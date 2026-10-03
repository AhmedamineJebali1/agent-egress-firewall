package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"aegis/lab/internal/audit"
)

const maxInspectBody = 1 << 20 // 1 MiB of each request body is inspected

// hopByHop headers must not be forwarded.
var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func (f *firewall) transport() *http.Transport {
	return &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       &tls.Config{RootCAs: f.upstream, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          32,
		IdleConnTimeout:       30 * time.Second,
	}
}

func (f *firewall) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		f.handleConnect(w, r)
		return
	}
	f.handlePlain(w, r)
}

// ------------------------------------------------------- plain HTTP proxy --

func (f *firewall) handlePlain(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() {
		// Not a proxy request. Give a useful hint instead of a blank error.
		http.Error(w, "this is an egress proxy; send absolute-URI or CONNECT requests",
			http.StatusBadRequest)
		return
	}
	host, port := splitHostPort(r.URL.Host, "80")
	client := clientIP(r.RemoteAddr)
	scenario := r.Header.Get("X-Lab-Scenario")

	ev := audit.Event{
		Client: client, Proto: "http", Host: host, Port: port,
		Method: r.Method, Path: r.URL.RequestURI(), Mode: f.pol.Mode(),
		Scenario: scenario, Inspected: f.pol.DLPEnabled(),
	}

	if allowed, reason := f.checkHost(host); !allowed {
		ev.Action, ev.Reason = "block", reason
		f.log.Add(ev)
		f.deny(w, "destination not on the egress allowlist", host, reason)
		return
	}

	body, err := readBody(r.Body)
	if err != nil {
		ev.Action, ev.Reason = "block", "body-read-error"
		f.log.Add(ev)
		http.Error(w, "bad request body", http.StatusBadRequest)
		return
	}
	ev.Bytes = len(body)

	if f.pol.DLPEnabled() {
		if v := f.dlp.Inspect(client, requestText(r, host, body)); v.Leak {
			ev.Action = "block"
			ev.Reason = "dlp:" + v.Technique
			ev.Technique = v.Technique
			ev.Coverage = v.Coverage
			ev.Detail = v.Detail
			f.log.Add(ev)
			f.deny(w, "data-loss prevention blocked this request", host, v.Detail)
			return
		}
	}

	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.Body = io.NopCloser(bytes.NewReader(body))
	out.ContentLength = int64(len(body))
	stripHopByHop(out.Header)

	resp, err := f.transport().RoundTrip(out)
	if err != nil {
		ev.Action, ev.Reason = "block", "upstream-error: "+err.Error()
		f.log.Add(ev)
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	ev.Action, ev.Reason = "allow", f.allowReason(host)
	f.log.Add(ev)

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// ------------------------------------------------------------- CONNECT -----

func (f *firewall) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port := splitHostPort(r.Host, "443")
	client := clientIP(r.RemoteAddr)

	ev := audit.Event{
		Client: client, Proto: "https", Host: host, Port: port,
		Method: "CONNECT", Mode: f.pol.Mode(),
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "proxy cannot hijack", http.StatusInternalServerError)
		return
	}

	if allowed, reason := f.checkHost(host); !allowed {
		ev.Action, ev.Reason = "block", reason
		f.log.Add(ev)
		// Refuse the tunnel outright: the client never speaks to the peer.
		w.Header().Set("X-Egress-Block", reason)
		http.Error(w, "egress denied: "+host+" ("+reason+")", http.StatusForbidden)
		return
	}

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	if _, err := bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := bufrw.Flush(); err != nil {
		return
	}

	if f.pol.TLSIntercept() {
		ev.Inspected = true
		ev.Action, ev.Reason = "allow", f.allowReason(host)+" (intercepting)"
		f.log.Add(ev)
		f.interceptTLS(conn, bufrw, client, host, port)
		return
	}

	ev.Action = "allow"
	ev.Reason = f.allowReason(host) + " (blind tunnel, payload not inspected)"
	f.log.Add(ev)
	f.blindTunnel(conn, bufrw, net.JoinHostPort(host, port))
}

// blindTunnel is what an allowlist-only proxy does: it moves bytes it cannot
// read. Anything the agent sends to an allowed host leaves unexamined.
func (f *firewall) blindTunnel(client net.Conn, bufrw *bufio.ReadWriter, target string) {
	upstream, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, bufrw); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}

// interceptTLS terminates the agent's TLS session with a certificate minted by
// the interception CA, inspects each request, then re-originates the connection
// to the real destination.
func (f *firewall) interceptTLS(raw net.Conn, bufrw *bufio.ReadWriter, client, host, port string) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hi.ServerName
			if name == "" {
				name = host
			}
			return f.ca.Leaf(name)
		},
	}

	// Anything already buffered by the HTTP server must be replayed into TLS.
	var pre []byte
	if n := bufrw.Reader.Buffered(); n > 0 {
		pre = make([]byte, n)
		_, _ = io.ReadFull(bufrw.Reader, pre)
	}
	srvConn := tls.Server(&prefixConn{Conn: raw, pre: pre}, tlsCfg)
	if err := srvConn.Handshake(); err != nil {
		f.log.Add(audit.Event{
			Client: client, Proto: "https", Host: host, Port: port, Mode: f.pol.Mode(),
			Action: "block", Reason: "tls-intercept-handshake-failed: " + err.Error(),
			Detail: "the agent did not trust the interception CA",
		})
		return
	}
	defer srvConn.Close()

	tr := f.transport()
	defer tr.CloseIdleConnections()
	reader := bufio.NewReader(srvConn)

	for {
		_ = srvConn.SetReadDeadline(time.Now().Add(60 * time.Second))
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		_ = srvConn.SetReadDeadline(time.Time{})

		body, rerr := readBody(req.Body)
		req.Body.Close()
		if rerr != nil {
			return
		}

		ev := audit.Event{
			Client: client, Proto: "https", Host: host, Port: port,
			Method: req.Method, Path: req.URL.RequestURI(), Mode: f.pol.Mode(),
			Scenario: req.Header.Get("X-Lab-Scenario"), Inspected: true, Bytes: len(body),
		}

		if v := f.dlp.Inspect(client, requestText(req, host, body)); v.Leak {
			ev.Action = "block"
			ev.Reason = "dlp:" + v.Technique
			ev.Technique = v.Technique
			ev.Coverage = v.Coverage
			ev.Detail = v.Detail
			f.log.Add(ev)
			writeDenial(srvConn, host, "data-loss prevention blocked this request", v.Detail)
			return
		}

		req.URL.Scheme = "https"
		req.URL.Host = net.JoinHostPort(host, port)
		if port == "443" {
			req.URL.Host = host
		}
		req.RequestURI = ""
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		stripHopByHop(req.Header)

		resp, err := tr.RoundTrip(req)
		if err != nil {
			ev.Action, ev.Reason = "block", "upstream-error: "+err.Error()
			f.log.Add(ev)
			writeDenial(srvConn, host, "upstream error", err.Error())
			return
		}

		ev.Action, ev.Reason = "allow", f.allowReason(host)+" (inspected, clean)"
		f.log.Add(ev)

		resp.Header.Del("Transfer-Encoding")
		resp.TransferEncoding = nil
		// Without a declared length the client can only find the end of the
		// body at EOF, so close after writing.
		if resp.ContentLength < 0 {
			resp.Close = true
		}
		err = resp.Write(srvConn)
		resp.Body.Close()
		if err != nil || req.Close || resp.Close {
			return
		}
	}
}

// prefixConn replays bytes that were read ahead of the TLS handshake.
type prefixConn struct {
	net.Conn
	pre []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.pre) > 0 {
		n := copy(b, p.pre)
		p.pre = p.pre[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// ------------------------------------------------------------- helpers -----

func (f *firewall) checkHost(host string) (bool, string) {
	if !f.pol.AllowlistEnforced() {
		return true, "enforcement-off"
	}
	return f.pol.HostAllowed(host)
}

func (f *firewall) allowReason(host string) string {
	if !f.pol.AllowlistEnforced() {
		return "enforcement-off"
	}
	_, reason := f.pol.HostAllowed(host)
	return reason
}

func (f *firewall) deny(w http.ResponseWriter, msg, host, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Egress-Block", reason)
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `{"error":%q,"host":%q,"reason":%q,"blocked_by":"aegis-egress-firewall"}`+"\n",
		msg, host, reason)
}

func writeDenial(w io.Writer, host, msg, detail string) {
	body := fmt.Sprintf(`{"error":%q,"host":%q,"detail":%q,"blocked_by":"aegis-egress-firewall"}`+"\n",
		msg, host, detail)
	fmt.Fprintf(w, "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n"+
		"X-Egress-Block: dlp\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}

// requestText flattens everything an inspector can see into one string: the
// body, the full URL, the decoded query and every header. Secrets hide in all
// of them, and an inspector that reads only bodies misses two thirds of the
// available channels.
//
// The body comes first and headers are sorted, so inspection is deterministic:
// the same request must always produce the same verdict.
func requestText(r *http.Request, host string, body []byte) string {
	var sb strings.Builder
	sb.Write(body)
	sb.WriteByte('\n')

	sb.WriteString(r.Method)
	sb.WriteByte(' ')
	u := *r.URL
	if u.Host == "" {
		u.Host = host
	}
	sb.WriteString(u.String())
	sb.WriteByte('\n')

	if q, err := url.ParseQuery(r.URL.RawQuery); err == nil {
		for _, k := range sortedHeaderKeys(q) {
			for _, v := range q[k] {
				sb.WriteString(k)
				sb.WriteByte('=')
				sb.WriteString(v)
				sb.WriteByte('\n')
			}
		}
	}

	for _, k := range sortedHeaderKeys(r.Header) {
		for _, v := range r.Header[k] {
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

func sortedHeaderKeys[T any](m map[string][]T) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func readBody(b io.ReadCloser) ([]byte, error) {
	if b == nil {
		return nil, nil
	}
	return io.ReadAll(io.LimitReader(b, maxInspectBody))
}

func stripHopByHop(h http.Header) {
	for _, k := range hopByHop {
		h.Del(k)
	}
}

func copyHeader(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func splitHostPort(hostport, defPort string) (string, string) {
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		return strings.ToLower(h), p
	}
	return strings.ToLower(hostport), defPort
}
