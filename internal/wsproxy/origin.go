// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package wsproxy

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// ParseOrigins reads a comma-separated list of browser origins
// (scheme://host[:port], http or https, nothing after the host) and returns
// them normalized for comparison.
func ParseOrigins(list string) ([]string, error) {
	var out []string
	for _, raw := range strings.Split(list, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		o, err := normalizeOrigin(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, nil
}

func normalizeOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("origin %q: %w", raw, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("origin %q: scheme must be http or https", raw)
	}
	if u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("origin %q: want scheme://host[:port] only", raw)
	}
	return scheme + "://" + strings.ToLower(u.Host), nil
}

// OriginFromWSURL returns the browser origin that serves a WebSocket URL on
// the same host: wss://h/p gives https://h, ws://h/p gives http://h.
func OriginFromWSURL(wsURL string) (string, error) {
	u, err := url.Parse(wsURL)
	if err != nil {
		return "", fmt.Errorf("websocket url %q: %w", wsURL, err)
	}
	var scheme string
	switch strings.ToLower(u.Scheme) {
	case "wss":
		scheme = "https"
	case "ws":
		scheme = "http"
	default:
		return "", fmt.Errorf("websocket url %q: scheme must be ws or wss", wsURL)
	}
	if u.Host == "" {
		return "", fmt.Errorf("websocket url %q: no host", wsURL)
	}
	return scheme + "://" + strings.ToLower(u.Host), nil
}

// originChecker allows a request with no Origin header (not a browser, so not
// a cross-site WebSocket hijack; the ticket still has to be valid), and a
// browser request from a listed origin or from the page's own origin: an
// Origin whose host and port are the ones the request was sent to (its Host
// header). The box is served on its name and on its addresses, so a page
// opened by any of them opens its terminal on the same origin.
type originChecker map[string]struct{}

func newOriginChecker(origins []string) originChecker {
	c := make(originChecker, len(origins))
	for _, o := range origins {
		c[o] = struct{}{}
	}
	return c
}

func (c originChecker) allowed(r *http.Request) bool {
	raw := r.Header.Get("Origin")
	if raw == "" {
		return true
	}
	o, err := normalizeOrigin(raw)
	if err != nil {
		return false
	}
	if _, ok := c[o]; ok {
		return true
	}
	return sameOrigin(o, r.Host)
}

// sameOrigin reports whether a normalized origin names the authority in
// host (a Host header): the same name or address and the same port, a
// missing port being the origin scheme's default. IPv6 addresses compare by
// value, so two spellings of one address match. An address with a zone id is
// never the same origin: browsers don't put zone ids in an Origin, and a
// link-local address isn't one the box is served on.
func sameOrigin(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	want, ok := authority(u.Host, u.Scheme)
	if !ok {
		return false
	}
	got, ok := authority(host, u.Scheme)
	return ok && got == want
}

// authority returns hostport in one comparable form, host lower-cased (an IP
// address in its canonical form) and the port filled in from scheme when
// it's left out. ok is false for an empty host, an IPv6 address without
// brackets, a zone id or a port that isn't a number.
func authority(hostport, scheme string) (string, bool) {
	host, port := hostport, ""
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		host, port = h, p
	} else if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		host = hostport[1 : len(hostport)-1]
	} else if strings.Contains(hostport, ":") {
		return "", false
	}
	if host == "" || strings.Contains(host, "%") {
		return "", false
	}
	if port == "" {
		port = defaultPort(scheme)
	}
	if strings.Trim(port, "0123456789") != "" {
		return "", false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.String()
	} else {
		host = strings.ToLower(host)
	}
	return net.JoinHostPort(host, port), true
}

func defaultPort(scheme string) string {
	if scheme == "http" {
		return "80"
	}
	return "443"
}
