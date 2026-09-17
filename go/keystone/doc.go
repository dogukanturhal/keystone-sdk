// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

// Package keystone is the public, Apache-2.0-licensed SDK surface for
// Keystone's schema-management primitives. The operator itself
// (internal/, cmd/manager/, CRDs) is AGPL-3.0-or-later; this package
// is the legitimate integration boundary for third-party Go code that
// wants to reuse Keystone's analyzer pack, runner, differ, and
// inspector outside a Kubernetes cluster — typically in CI test
// suites, dev seeders, and schema-validation pipelines.
//
// Why a separate package:
//
//   - License: AGPL's network-copyleft clause makes it unsuitable for
//     embedding in proprietary applications. The Apache-2.0 split
//     (documented in ADR 0001) unblocks those use cases without
//     reopening the license debate.
//
//   - Surface: the operator carries controller-runtime, k8s clients,
//     webhook TLS, audit chains, and a dozen CRDs. A test harness
//     doesn't want any of that. This package re-exports only the
//     pieces that make sense outside a cluster.
//
//   - Stability: the operator's internal types evolve freely; the SDK
//     surface is held to a stricter v1 contract (see README).
//
// Typical usage in a Go test:
//
//	import ks "github.com/dogukanturhal/keystone-sdk/go/keystone"
//
//	func TestMySchema(t *testing.T) {
//	    pool := testPool(t) // spin up Postgres via testcontainers
//
//	    files := []ks.SQLFile{
//	        {Name: "001_init.up.sql", Body: `CREATE TABLE users (id uuid PRIMARY KEY)`},
//	    }
//	    findings, _ := ks.Lint(ctx, "my-bundle", "v1", files)
//	    for _, f := range findings {
//	        t.Logf("lint: %s %s:%d %s", f.Severity, f.File, f.Line, f.Message)
//	    }
//
//	    result, err := ks.Apply(ctx, pool, ks.ApplyOptions{
//	        Schema:       "app",
//	        Version:      "v1",
//	        Files:        files,
//	    })
//	    if err != nil { t.Fatalf("apply: %v", err) }
//
//	    snap, _ := ks.Inspect(ctx, pool, "app")
//	    if len(snap.Tables) != 1 {
//	        t.Errorf("expected 1 table; got %d", len(snap.Tables))
//	    }
//	}
//
// What this SDK is NOT:
//
//   - It is not a connection pool manager for the Postgres-side
//     helpers (Apply, Lint, Inspect, Diff). Callers pass in their own
//     *pgxpool.Pool.
//   - It is not a test harness. Callers bring their own Postgres
//     (testcontainers, local docker, dev instance).
//
// # Two surfaces
//
// The SDK has two parallel surfaces serving different concerns:
//
//  1. Postgres-side (Apply, Lint, Inspect, Diff) — direct database
//     operations. The caller already holds a *pgxpool.Pool to the
//     target database. No Kubernetes involvement.
//
//  2. Kubernetes-side (EnrollSchema, WaitSchemaReady,
//     WaitSchemaUpToDate, WaitSchemaFingerprint, DeenrollSchema) —
//     runtime tenant / product-instance enrollment. The caller holds
//     a controller-runtime client.Client and asks Keystone to create
//     the LogicalDatabase + DatabaseSchema CRs that drive async
//     reconciliation. No direct database access from the caller.
//
//     The three wait helpers serve different needs:
//     - WaitSchemaReady waits for the DatabaseSchema CR to be
//     Ready (schema present + ownership reconciled). Cheap; use
//     when a downstream caller only needs the bare schema.
//     - WaitSchemaUpToDate additionally waits for the SchemaDefinition
//     to have applied its current bundle to the matched schemas
//     (tables actually exist). Count-based — uses prevMatched+1.
//     Suits new enrollments where matchedSchemas count grows.
//     - WaitSchemaFingerprint (v0.1.49+) is identity-based — polls
//     per-schema LastAppliedFingerprint vs SD.Status.Fingerprint.
//     Race-free; correct for both new enrollments AND for updates
//     to existing enrollments (e.g. realm-DB migrator re-pointing
//     an existing schema's LogicalDatabase at a new cluster, where
//     matchedSchemas count doesn't change).
//
// Use surface (1) for one-shot SQL applications inside a service's
// own startup or test code. Use surface (2) for runtime enrollment
// of new tenants where Keystone owns DB lifecycle (creation, migration
// fan-out, drift detection, eventual deenrollment).
//
// See sdk/README.md for the stability contract and full examples.
package keystone
