// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package wsproxy

import (
	"fmt"
	"net/http"
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
// a cross-site WebSocket hijack; the ticket still has to be valid) and a
// browser request only from a listed origin.
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
	_, ok := c[o]
	return ok
}
