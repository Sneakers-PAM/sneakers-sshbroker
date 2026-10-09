// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"time"

	log "github.com/Bugs5382/go-log"
	workloadauth "github.com/Bugs5382/go-workload-identity"
)

// KeyRefresher is the part of go-workload-identity's Verifier that
// RunWorkloadKeys drives.
type KeyRefresher interface {
	Refresh(ctx context.Context) error
	Ready() error
}

// KeyRefresh sets how RunWorkloadKeys fetches the issuer's key set: retries
// start at Initial and double up to Max while no set has loaded, then the set
// is refetched every Interval.
type KeyRefresh struct {
	Initial  time.Duration
	Max      time.Duration
	Interval time.Duration
}

// DefaultKeyRefresh retries from 1 second up to 30 seconds, then refreshes at
// go-workload-identity's own interval.
var DefaultKeyRefresh = KeyRefresh{
	Initial:  time.Second,
	Max:      30 * time.Second,
	Interval: workloadauth.DefaultRefreshInterval,
}

// RunWorkloadKeys loads the issuer's key set and keeps it fresh until ctx
// ends, in place of Verifier.Run. Run fetches once and then only every
// refresh interval, so a first fetch that fails while the pod network comes
// up leaves readiness down for that whole interval: no caller reaches a pod
// that isn't ready, so nothing else triggers a fetch. While no set has
// loaded, this retries with capped backoff instead.
func RunWorkloadKeys(ctx context.Context, v KeyRefresher, p KeyRefresh, target string, lg log.Logger) {
	delay := p.Initial
	for attempt := 1; ; attempt++ {
		start := time.Now()
		err := v.Refresh(ctx)
		if err == nil {
			err = v.Ready()
		}
		if err == nil {
			if attempt > 1 {
				lg.Info("workload key set loaded; workload identity ready",
					log.F("target", target), log.F("attempts", attempt))
			}
			break
		}
		lg.Debug("workload key set fetch failed; retrying",
			log.F("target", target), log.F("attempt", attempt), log.F("outcome", err.Error()),
			log.F("duration_ms", time.Since(start).Milliseconds()), log.F("retry_in_ms", delay.Milliseconds()))
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, p.Max)
	}
	t := time.NewTicker(p.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = v.Refresh(ctx)
		}
	}
}
