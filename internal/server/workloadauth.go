// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"strings"

	workloadauth "github.com/Bugs5382/go-workload-identity"
)

// The token audience and the service-account prefix every Sneakers service
// uses. go-workload-identity has no defaults for either, so they are set here.
const (
	// WorkloadAudience is the audience required when WORKLOAD_AUDIENCE is unset.
	WorkloadAudience = "sneakers"
	// WorkloadServiceAccountPrefix is stripped from a service account to give
	// the caller name: "sneakers-gateway" is the caller "gateway".
	WorkloadServiceAccountPrefix = "sneakers-"
)

// WorkloadConfigFromEnv reads the WORKLOAD_* variables for a callee, failing
// closed like workloadauth.ServerConfigFromEnv. WORKLOAD_AUDIENCE defaults to
// WorkloadAudience and the caller name always drops
// WorkloadServiceAccountPrefix; WORKLOAD_SERVICEACCOUNT_PREFIX is not read.
func WorkloadConfigFromEnv(getenv func(string) string) (workloadauth.Config, bool, error) {
	cfg, enabled, err := workloadauth.ServerConfigFromEnv(withWorkloadAudience(getenv))
	if err != nil || !enabled {
		return cfg, enabled, err
	}
	cfg.ServiceAccountPrefix = WorkloadServiceAccountPrefix
	return cfg, true, nil
}

func withWorkloadAudience(getenv func(string) string) func(string) string {
	return func(k string) string {
		switch k {
		case workloadauth.EnvAudience:
			if v := getenv(k); strings.TrimSpace(v) != "" {
				return v
			}
			return WorkloadAudience
		case workloadauth.EnvServiceAccountPrefix:
			return ""
		}
		return getenv(k)
	}
}
