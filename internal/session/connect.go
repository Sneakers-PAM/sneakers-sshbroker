// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"time"

	log "github.com/Bugs5382/go-log"
)

var connectLogger = log.New("sshbroker-session")

// Backoff is the wait between attempts to reach the shared store: Min after
// the first failure, doubling up to Max.
type Backoff struct {
	Min time.Duration
	Max time.Duration
}

// DefaultBackoff is the retry schedule the broker uses for Redis at start.
var DefaultBackoff = Backoff{Min: time.Second, Max: 30 * time.Second}

func (b Backoff) wait(attempt int) time.Duration {
	d := b.Min
	for i := 0; i < attempt && d < b.Max; i++ {
		d *= 2
	}
	return min(d, b.Max)
}

// ConnectShared calls connect until it returns a store, then attaches it. It
// keeps trying for as long as ctx lives, so a broker that started before Redis
// picks Redis up once it answers. It returns nil once attached, or ctx's error.
func (c *Composite) ConnectShared(ctx context.Context, connect func(context.Context) (TicketStore, error), b Backoff) error {
	connectLogger.Info().Msg("connecting to the shared ticket store; not ready until it answers")
	for attempt := 0; ; attempt++ {
		start := time.Now()
		shared, err := connect(ctx)
		if err == nil {
			c.Attach(shared)
			connectLogger.Info().Int("attempt", attempt+1).Dur("took", time.Since(start)).
				Msg("shared redis ticket store attached; ready (HA)")
			return nil
		}
		wait := b.wait(attempt)
		connectLogger.Warn().Err(err).Int("attempt", attempt+1).Dur("took", time.Since(start)).
			Dur("retry_in", wait).Msg("redis unreachable; not ready, retrying")
		select {
		case <-ctx.Done():
			connectLogger.Info().Err(ctx.Err()).Msg("stopped connecting to the shared ticket store")
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}
